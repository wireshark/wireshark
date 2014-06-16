/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-mms.c                                                               */
/* ../../tools/asn2wrs.py -b -p mms -c ./mms.cnf -s ./packet-mms-template -D . -O ../../epan/dissectors mms.asn */

/* Input file: packet-mms-template.c */

#line 1 "../../asn1/mms/packet-mms-template.c"
/* packet-mms_asn1.c
 *
 * Ronnie Sahlberg 2005
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
 */

#include "config.h"

#include <glib.h>
#include <epan/prefs.h>
#include <epan/packet.h>
#include <epan/asn1.h>
#include <epan/expert.h>

#include "packet-ber.h"
#include "packet-acse.h"
#include "packet-mms.h"

#define PNAME  "MMS"
#define PSNAME "MMS"
#define PFNAME "mms"

void proto_register_mms(void);
void proto_reg_handoff_mms(void);

/* Initialize the protocol and registered fields */
static int proto_mms = -1;


/*--- Included file: packet-mms-hf.c ---*/
#line 1 "../../asn1/mms/packet-mms-hf.c"
static int hf_mms_confirmed_RequestPDU = -1;      /* Confirmed_RequestPDU */
static int hf_mms_confirmed_ResponsePDU = -1;     /* Confirmed_ResponsePDU */
static int hf_mms_confirmed_ErrorPDU = -1;        /* Confirmed_ErrorPDU */
static int hf_mms_unconfirmed_PDU = -1;           /* Unconfirmed_PDU */
static int hf_mms_rejectPDU = -1;                 /* RejectPDU */
static int hf_mms_cancel_RequestPDU = -1;         /* Cancel_RequestPDU */
static int hf_mms_cancel_ResponsePDU = -1;        /* Cancel_ResponsePDU */
static int hf_mms_cancel_ErrorPDU = -1;           /* Cancel_ErrorPDU */
static int hf_mms_initiate_RequestPDU = -1;       /* Initiate_RequestPDU */
static int hf_mms_initiate_ResponsePDU = -1;      /* Initiate_ResponsePDU */
static int hf_mms_initiate_ErrorPDU = -1;         /* Initiate_ErrorPDU */
static int hf_mms_conclude_RequestPDU = -1;       /* Conclude_RequestPDU */
static int hf_mms_conclude_ResponsePDU = -1;      /* Conclude_ResponsePDU */
static int hf_mms_conclude_ErrorPDU = -1;         /* Conclude_ErrorPDU */
static int hf_mms_invokeID = -1;                  /* Unsigned32 */
static int hf_mms_listOfModifier = -1;            /* SEQUENCE_OF_Modifier */
static int hf_mms_listOfModifier_item = -1;       /* Modifier */
static int hf_mms_confirmedServiceRequest = -1;   /* ConfirmedServiceRequest */
static int hf_mms_cs_request_detail = -1;         /* CS_Request_Detail */
static int hf_mms_unconfirmedService = -1;        /* UnconfirmedService */
static int hf_mms_confirmedServiceResponse = -1;  /* ConfirmedServiceResponse */
static int hf_mms_modifierPosition = -1;          /* Unsigned32 */
static int hf_mms_serviceError = -1;              /* ServiceError */
static int hf_mms_informationReport = -1;         /* InformationReport */
static int hf_mms_unsolicitedStatus = -1;         /* UnsolicitedStatus */
static int hf_mms_eventNotification = -1;         /* EventNotification */
static int hf_mms_attach_To_Event_Condition = -1;  /* AttachToEventCondition */
static int hf_mms_attach_To_Semaphore = -1;       /* AttachToSemaphore */
static int hf_mms_status = -1;                    /* Status_Request */
static int hf_mms_getNameList = -1;               /* GetNameList_Request */
static int hf_mms_identify = -1;                  /* Identify_Request */
static int hf_mms_rename = -1;                    /* Rename_Request */
static int hf_mms_read = -1;                      /* Read_Request */
static int hf_mms_write = -1;                     /* Write_Request */
static int hf_mms_getVariableAccessAttributes = -1;  /* GetVariableAccessAttributes_Request */
static int hf_mms_defineNamedVariable = -1;       /* DefineNamedVariable_Request */
static int hf_mms_defineScatteredAccess = -1;     /* DefineScatteredAccess_Request */
static int hf_mms_getScatteredAccessAttributes = -1;  /* GetScatteredAccessAttributes_Request */
static int hf_mms_deleteVariableAccess = -1;      /* DeleteVariableAccess_Request */
static int hf_mms_defineNamedVariableList = -1;   /* DefineNamedVariableList_Request */
static int hf_mms_getNamedVariableListAttributes = -1;  /* GetNamedVariableListAttributes_Request */
static int hf_mms_deleteNamedVariableList = -1;   /* DeleteNamedVariableList_Request */
static int hf_mms_defineNamedType = -1;           /* DefineNamedType_Request */
static int hf_mms_getNamedTypeAttributes = -1;    /* GetNamedTypeAttributes_Request */
static int hf_mms_deleteNamedType = -1;           /* DeleteNamedType_Request */
static int hf_mms_input = -1;                     /* Input_Request */
static int hf_mms_output = -1;                    /* Output_Request */
static int hf_mms_takeControl = -1;               /* TakeControl_Request */
static int hf_mms_relinquishControl = -1;         /* RelinquishControl_Request */
static int hf_mms_defineSemaphore = -1;           /* DefineSemaphore_Request */
static int hf_mms_deleteSemaphore = -1;           /* DeleteSemaphore_Request */
static int hf_mms_reportSemaphoreStatus = -1;     /* ReportSemaphoreStatus_Request */
static int hf_mms_reportPoolSemaphoreStatus = -1;  /* ReportPoolSemaphoreStatus_Request */
static int hf_mms_reportSemaphoreEntryStatus = -1;  /* ReportSemaphoreEntryStatus_Request */
static int hf_mms_initiateDownloadSequence = -1;  /* InitiateDownloadSequence_Request */
static int hf_mms_downloadSegment = -1;           /* DownloadSegment_Request */
static int hf_mms_terminateDownloadSequence = -1;  /* TerminateDownloadSequence_Request */
static int hf_mms_initiateUploadSequence = -1;    /* InitiateUploadSequence_Request */
static int hf_mms_uploadSegment = -1;             /* UploadSegment_Request */
static int hf_mms_terminateUploadSequence = -1;   /* TerminateUploadSequence_Request */
static int hf_mms_requestDomainDownload = -1;     /* RequestDomainDownload_Request */
static int hf_mms_requestDomainUpload = -1;       /* RequestDomainUpload_Request */
static int hf_mms_loadDomainContent = -1;         /* LoadDomainContent_Request */
static int hf_mms_storeDomainContent = -1;        /* StoreDomainContent_Request */
static int hf_mms_deleteDomain = -1;              /* DeleteDomain_Request */
static int hf_mms_getDomainAttributes = -1;       /* GetDomainAttributes_Request */
static int hf_mms_createProgramInvocation = -1;   /* CreateProgramInvocation_Request */
static int hf_mms_deleteProgramInvocation = -1;   /* DeleteProgramInvocation_Request */
static int hf_mms_start = -1;                     /* Start_Request */
static int hf_mms_stop = -1;                      /* Stop_Request */
static int hf_mms_resume = -1;                    /* Resume_Request */
static int hf_mms_reset = -1;                     /* Reset_Request */
static int hf_mms_kill = -1;                      /* Kill_Request */
static int hf_mms_getProgramInvocationAttributes = -1;  /* GetProgramInvocationAttributes_Request */
static int hf_mms_obtainFile = -1;                /* ObtainFile_Request */
static int hf_mms_defineEventCondition = -1;      /* DefineEventCondition_Request */
static int hf_mms_deleteEventCondition = -1;      /* DeleteEventCondition_Request */
static int hf_mms_getEventConditionAttributes = -1;  /* GetEventConditionAttributes_Request */
static int hf_mms_reportEventConditionStatus = -1;  /* ReportEventConditionStatus_Request */
static int hf_mms_alterEventConditionMonitoring = -1;  /* AlterEventConditionMonitoring_Request */
static int hf_mms_triggerEvent = -1;              /* TriggerEvent_Request */
static int hf_mms_defineEventAction = -1;         /* DefineEventAction_Request */
static int hf_mms_deleteEventAction = -1;         /* DeleteEventAction_Request */
static int hf_mms_getEventActionAttributes = -1;  /* GetEventActionAttributes_Request */
static int hf_mms_reportEventActionStatus = -1;   /* ReportEventActionStatus_Request */
static int hf_mms_defineEventEnrollment = -1;     /* DefineEventEnrollment_Request */
static int hf_mms_deleteEventEnrollment = -1;     /* DeleteEventEnrollment_Request */
static int hf_mms_alterEventEnrollment = -1;      /* AlterEventEnrollment_Request */
static int hf_mms_reportEventEnrollmentStatus = -1;  /* ReportEventEnrollmentStatus_Request */
static int hf_mms_getEventEnrollmentAttributes = -1;  /* GetEventEnrollmentAttributes_Request */
static int hf_mms_acknowledgeEventNotification = -1;  /* AcknowledgeEventNotification_Request */
static int hf_mms_getAlarmSummary = -1;           /* GetAlarmSummary_Request */
static int hf_mms_getAlarmEnrollmentSummary = -1;  /* GetAlarmEnrollmentSummary_Request */
static int hf_mms_readJournal = -1;               /* ReadJournal_Request */
static int hf_mms_writeJournal = -1;              /* WriteJournal_Request */
static int hf_mms_initializeJournal = -1;         /* InitializeJournal_Request */
static int hf_mms_reportJournalStatus = -1;       /* ReportJournalStatus_Request */
static int hf_mms_createJournal = -1;             /* CreateJournal_Request */
static int hf_mms_deleteJournal = -1;             /* DeleteJournal_Request */
static int hf_mms_getCapabilityList = -1;         /* GetCapabilityList_Request */
static int hf_mms_fileOpen = -1;                  /* FileOpen_Request */
static int hf_mms_fileRead = -1;                  /* FileRead_Request */
static int hf_mms_fileClose = -1;                 /* FileClose_Request */
static int hf_mms_fileRename = -1;                /* FileRename_Request */
static int hf_mms_fileDelete = -1;                /* FileDelete_Request */
static int hf_mms_fileDirectory = -1;             /* FileDirectory_Request */
static int hf_mms_foo = -1;                       /* INTEGER */
static int hf_mms_status_01 = -1;                 /* Status_Response */
static int hf_mms_getNameList_01 = -1;            /* GetNameList_Response */
static int hf_mms_identify_01 = -1;               /* Identify_Response */
static int hf_mms_rename_01 = -1;                 /* Rename_Response */
static int hf_mms_read_01 = -1;                   /* Read_Response */
static int hf_mms_write_01 = -1;                  /* Write_Response */
static int hf_mms_getVariableAccessAttributes_01 = -1;  /* GetVariableAccessAttributes_Response */
static int hf_mms_defineNamedVariable_01 = -1;    /* DefineNamedVariable_Response */
static int hf_mms_defineScatteredAccess_01 = -1;  /* DefineScatteredAccess_Response */
static int hf_mms_getScatteredAccessAttributes_01 = -1;  /* GetScatteredAccessAttributes_Response */
static int hf_mms_deleteVariableAccess_01 = -1;   /* DeleteVariableAccess_Response */
static int hf_mms_defineNamedVariableList_01 = -1;  /* DefineNamedVariableList_Response */
static int hf_mms_getNamedVariableListAttributes_01 = -1;  /* GetNamedVariableListAttributes_Response */
static int hf_mms_deleteNamedVariableList_01 = -1;  /* DeleteNamedVariableList_Response */
static int hf_mms_defineNamedType_01 = -1;        /* DefineNamedType_Response */
static int hf_mms_getNamedTypeAttributes_01 = -1;  /* GetNamedTypeAttributes_Response */
static int hf_mms_deleteNamedType_01 = -1;        /* DeleteNamedType_Response */
static int hf_mms_input_01 = -1;                  /* Input_Response */
static int hf_mms_output_01 = -1;                 /* Output_Response */
static int hf_mms_takeControl_01 = -1;            /* TakeControl_Response */
static int hf_mms_relinquishControl_01 = -1;      /* RelinquishControl_Response */
static int hf_mms_defineSemaphore_01 = -1;        /* DefineSemaphore_Response */
static int hf_mms_deleteSemaphore_01 = -1;        /* DeleteSemaphore_Response */
static int hf_mms_reportSemaphoreStatus_01 = -1;  /* ReportSemaphoreStatus_Response */
static int hf_mms_reportPoolSemaphoreStatus_01 = -1;  /* ReportPoolSemaphoreStatus_Response */
static int hf_mms_reportSemaphoreEntryStatus_01 = -1;  /* ReportSemaphoreEntryStatus_Response */
static int hf_mms_initiateDownloadSequence_01 = -1;  /* InitiateDownloadSequence_Response */
static int hf_mms_downloadSegment_01 = -1;        /* DownloadSegment_Response */
static int hf_mms_terminateDownloadSequence_01 = -1;  /* TerminateDownloadSequence_Response */
static int hf_mms_initiateUploadSequence_01 = -1;  /* InitiateUploadSequence_Response */
static int hf_mms_uploadSegment_01 = -1;          /* UploadSegment_Response */
static int hf_mms_terminateUploadSequence_01 = -1;  /* TerminateUploadSequence_Response */
static int hf_mms_requestDomainDownLoad = -1;     /* RequestDomainDownload_Response */
static int hf_mms_requestDomainUpload_01 = -1;    /* RequestDomainUpload_Response */
static int hf_mms_loadDomainContent_01 = -1;      /* LoadDomainContent_Response */
static int hf_mms_storeDomainContent_01 = -1;     /* StoreDomainContent_Response */
static int hf_mms_deleteDomain_01 = -1;           /* DeleteDomain_Response */
static int hf_mms_getDomainAttributes_01 = -1;    /* GetDomainAttributes_Response */
static int hf_mms_createProgramInvocation_01 = -1;  /* CreateProgramInvocation_Response */
static int hf_mms_deleteProgramInvocation_01 = -1;  /* DeleteProgramInvocation_Response */
static int hf_mms_start_01 = -1;                  /* Start_Response */
static int hf_mms_stop_01 = -1;                   /* Stop_Response */
static int hf_mms_resume_01 = -1;                 /* Resume_Response */
static int hf_mms_reset_01 = -1;                  /* Reset_Response */
static int hf_mms_kill_01 = -1;                   /* Kill_Response */
static int hf_mms_getProgramInvocationAttributes_01 = -1;  /* GetProgramInvocationAttributes_Response */
static int hf_mms_obtainFile_01 = -1;             /* ObtainFile_Response */
static int hf_mms_fileOpen_01 = -1;               /* FileOpen_Response */
static int hf_mms_defineEventCondition_01 = -1;   /* DefineEventCondition_Response */
static int hf_mms_deleteEventCondition_01 = -1;   /* DeleteEventCondition_Response */
static int hf_mms_getEventConditionAttributes_01 = -1;  /* GetEventConditionAttributes_Response */
static int hf_mms_reportEventConditionStatus_01 = -1;  /* ReportEventConditionStatus_Response */
static int hf_mms_alterEventConditionMonitoring_01 = -1;  /* AlterEventConditionMonitoring_Response */
static int hf_mms_triggerEvent_01 = -1;           /* TriggerEvent_Response */
static int hf_mms_defineEventAction_01 = -1;      /* DefineEventAction_Response */
static int hf_mms_deleteEventAction_01 = -1;      /* DeleteEventAction_Response */
static int hf_mms_getEventActionAttributes_01 = -1;  /* GetEventActionAttributes_Response */
static int hf_mms_reportActionStatus = -1;        /* ReportEventActionStatus_Response */
static int hf_mms_defineEventEnrollment_01 = -1;  /* DefineEventEnrollment_Response */
static int hf_mms_deleteEventEnrollment_01 = -1;  /* DeleteEventEnrollment_Response */
static int hf_mms_alterEventEnrollment_01 = -1;   /* AlterEventEnrollment_Response */
static int hf_mms_reportEventEnrollmentStatus_01 = -1;  /* ReportEventEnrollmentStatus_Response */
static int hf_mms_getEventEnrollmentAttributes_01 = -1;  /* GetEventEnrollmentAttributes_Response */
static int hf_mms_acknowledgeEventNotification_01 = -1;  /* AcknowledgeEventNotification_Response */
static int hf_mms_getAlarmSummary_01 = -1;        /* GetAlarmSummary_Response */
static int hf_mms_getAlarmEnrollmentSummary_01 = -1;  /* GetAlarmEnrollmentSummary_Response */
static int hf_mms_readJournal_01 = -1;            /* ReadJournal_Response */
static int hf_mms_writeJournal_01 = -1;           /* WriteJournal_Response */
static int hf_mms_initializeJournal_01 = -1;      /* InitializeJournal_Response */
static int hf_mms_reportJournalStatus_01 = -1;    /* ReportJournalStatus_Response */
static int hf_mms_createJournal_01 = -1;          /* CreateJournal_Response */
static int hf_mms_deleteJournal_01 = -1;          /* DeleteJournal_Response */
static int hf_mms_getCapabilityList_01 = -1;      /* GetCapabilityList_Response */
static int hf_mms_fileRead_01 = -1;               /* FileRead_Response */
static int hf_mms_fileClose_01 = -1;              /* FileClose_Response */
static int hf_mms_fileRename_01 = -1;             /* FileRename_Response */
static int hf_mms_fileDelete_01 = -1;             /* FileDelete_Response */
static int hf_mms_fileDirectory_01 = -1;          /* FileDirectory_Response */
static int hf_mms_FileName_item = -1;             /* GraphicString */
static int hf_mms_vmd_specific = -1;              /* Identifier */
static int hf_mms_domain_specific = -1;           /* T_domain_specific */
static int hf_mms_domainId = -1;                  /* Identifier */
static int hf_mms_itemId = -1;                    /* Identifier */
static int hf_mms_aa_specific = -1;               /* Identifier */
static int hf_mms_ap_title = -1;                  /* T_ap_title */
static int hf_mms_ap_invocation_id = -1;          /* T_ap_invocation_id */
static int hf_mms_ae_qualifier = -1;              /* T_ae_qualifier */
static int hf_mms_ae_invocation_id = -1;          /* T_ae_invocation_id */
static int hf_mms_localDetailCalling = -1;        /* Integer32 */
static int hf_mms_proposedMaxServOutstandingCalling = -1;  /* Integer16 */
static int hf_mms_proposedMaxServOutstandingCalled = -1;  /* Integer16 */
static int hf_mms_proposedDataStructureNestingLevel = -1;  /* Integer8 */
static int hf_mms_mmsInitRequestDetail = -1;      /* InitRequestDetail */
static int hf_mms_proposedVersionNumber = -1;     /* Integer16 */
static int hf_mms_proposedParameterCBB = -1;      /* ParameterSupportOptions */
static int hf_mms_servicesSupportedCalling = -1;  /* ServiceSupportOptions */
static int hf_mms_localDetailCalled = -1;         /* Integer32 */
static int hf_mms_negociatedMaxServOutstandingCalling = -1;  /* Integer16 */
static int hf_mms_negociatedMaxServOutstandingCalled = -1;  /* Integer16 */
static int hf_mms_negociatedDataStructureNestingLevel = -1;  /* Integer8 */
static int hf_mms_mmsInitResponseDetail = -1;     /* InitResponseDetail */
static int hf_mms_negociatedVersionNumber = -1;   /* Integer16 */
static int hf_mms_negociatedParameterCBB = -1;    /* ParameterSupportOptions */
static int hf_mms_servicesSupportedCalled = -1;   /* ServiceSupportOptions */
static int hf_mms_originalInvokeID = -1;          /* Unsigned32 */
static int hf_mms_errorClass = -1;                /* T_errorClass */
static int hf_mms_vmd_state = -1;                 /* T_vmd_state */
static int hf_mms_application_reference = -1;     /* T_application_reference */
static int hf_mms_definition = -1;                /* T_definition */
static int hf_mms_resource = -1;                  /* T_resource */
static int hf_mms_service = -1;                   /* T_service */
static int hf_mms_service_preempt = -1;           /* T_service_preempt */
static int hf_mms_time_resolution = -1;           /* T_time_resolution */
static int hf_mms_access = -1;                    /* T_access */
static int hf_mms_initiate = -1;                  /* T_initiate */
static int hf_mms_conclude = -1;                  /* T_conclude */
static int hf_mms_cancel = -1;                    /* T_cancel */
static int hf_mms_file = -1;                      /* T_file */
static int hf_mms_others = -1;                    /* INTEGER */
static int hf_mms_additionalCode = -1;            /* INTEGER */
static int hf_mms_additionalDescription = -1;     /* VisibleString */
static int hf_mms_serviceSpecificInformation = -1;  /* T_serviceSpecificInformation */
static int hf_mms_obtainFile_02 = -1;             /* ObtainFile_Error */
static int hf_mms_start_02 = -1;                  /* Start_Error */
static int hf_mms_stop_02 = -1;                   /* Stop_Error */
static int hf_mms_resume_02 = -1;                 /* Resume_Error */
static int hf_mms_reset_02 = -1;                  /* Reset_Error */
static int hf_mms_deleteVariableAccess_02 = -1;   /* DeleteVariableAccess_Error */
static int hf_mms_deleteNamedVariableList_02 = -1;  /* DeleteNamedVariableList_Error */
static int hf_mms_deleteNamedType_02 = -1;        /* DeleteNamedType_Error */
static int hf_mms_defineEventEnrollment_Error = -1;  /* DefineEventEnrollment_Error */
static int hf_mms_fileRename_02 = -1;             /* FileRename_Error */
static int hf_mms_rejectReason = -1;              /* T_rejectReason */
static int hf_mms_confirmed_requestPDU = -1;      /* T_confirmed_requestPDU */
static int hf_mms_confirmed_responsePDU = -1;     /* T_confirmed_responsePDU */
static int hf_mms_confirmed_errorPDU = -1;        /* T_confirmed_errorPDU */
static int hf_mms_unconfirmedPDU = -1;            /* T_unconfirmedPDU */
static int hf_mms_pdu_error = -1;                 /* T_pdu_error */
static int hf_mms_cancel_requestPDU = -1;         /* T_cancel_requestPDU */
static int hf_mms_cancel_responsePDU = -1;        /* T_cancel_responsePDU */
static int hf_mms_cancel_errorPDU = -1;           /* T_cancel_errorPDU */
static int hf_mms_conclude_requestPDU = -1;       /* T_conclude_requestPDU */
static int hf_mms_conclude_responsePDU = -1;      /* T_conclude_responsePDU */
static int hf_mms_conclude_errorPDU = -1;         /* T_conclude_errorPDU */
static int hf_mms_vmdLogicalStatus = -1;          /* T_vmdLogicalStatus */
static int hf_mms_vmdPhysicalStatus = -1;         /* T_vmdPhysicalStatus */
static int hf_mms_localDetail = -1;               /* BIT_STRING_SIZE_0_128 */
static int hf_mms_extendedObjectClass = -1;       /* T_extendedObjectClass */
static int hf_mms_objectClass = -1;               /* T_objectClass */
static int hf_mms_objectScope = -1;               /* T_objectScope */
static int hf_mms_vmdSpecific = -1;               /* NULL */
static int hf_mms_domainSpecific = -1;            /* Identifier */
static int hf_mms_aaSpecific = -1;                /* NULL */
static int hf_mms_continueAfter = -1;             /* Identifier */
static int hf_mms_listOfIdentifier = -1;          /* SEQUENCE_OF_Identifier */
static int hf_mms_listOfIdentifier_item = -1;     /* Identifier */
static int hf_mms_moreFollows = -1;               /* BOOLEAN */
static int hf_mms_vendorName = -1;                /* VisibleString */
static int hf_mms_modelName = -1;                 /* VisibleString */
static int hf_mms_revision = -1;                  /* VisibleString */
static int hf_mms_listOfAbstractSyntaxes = -1;    /* T_listOfAbstractSyntaxes */
static int hf_mms_listOfAbstractSyntaxes_item = -1;  /* OBJECT_IDENTIFIER */
static int hf_mms_extendedObjectClass_01 = -1;    /* T_extendedObjectClass_01 */
static int hf_mms_objectClass_01 = -1;            /* T_objectClass_01 */
static int hf_mms_currentName = -1;               /* ObjectName */
static int hf_mms_newIdentifier = -1;             /* Identifier */
static int hf_mms_continueAfter_01 = -1;          /* VisibleString */
static int hf_mms_listOfCapabilities = -1;        /* T_listOfCapabilities */
static int hf_mms_listOfCapabilities_item = -1;   /* VisibleString */
static int hf_mms_domainName = -1;                /* Identifier */
static int hf_mms_listOfCapabilities_01 = -1;     /* T_listOfCapabilities_01 */
static int hf_mms_sharable = -1;                  /* BOOLEAN */
static int hf_mms_loadData = -1;                  /* T_loadData */
static int hf_mms_non_coded = -1;                 /* OCTET_STRING */
static int hf_mms_coded = -1;                     /* EXTERNALt */
static int hf_mms_discard = -1;                   /* ServiceError */
static int hf_mms_ulsmID = -1;                    /* Integer32 */
static int hf_mms_listOfCapabilities_02 = -1;     /* T_listOfCapabilities_02 */
static int hf_mms_loadData_01 = -1;               /* T_loadData_01 */
static int hf_mms_listOfCapabilities_03 = -1;     /* T_listOfCapabilities_03 */
static int hf_mms_fileName = -1;                  /* FileName */
static int hf_mms_listOfCapabilities_04 = -1;     /* T_listOfCapabilities_04 */
static int hf_mms_thirdParty = -1;                /* ApplicationReference */
static int hf_mms_filenName = -1;                 /* FileName */
static int hf_mms_listOfCapabilities_05 = -1;     /* T_listOfCapabilities_05 */
static int hf_mms_state = -1;                     /* DomainState */
static int hf_mms_mmsDeletable = -1;              /* BOOLEAN */
static int hf_mms_listOfProgramInvocations = -1;  /* SEQUENCE_OF_Identifier */
static int hf_mms_listOfProgramInvocations_item = -1;  /* Identifier */
static int hf_mms_uploadInProgress = -1;          /* Integer8 */
static int hf_mms_programInvocationName = -1;     /* Identifier */
static int hf_mms_listOfDomainName = -1;          /* SEQUENCE_OF_Identifier */
static int hf_mms_listOfDomainName_item = -1;     /* Identifier */
static int hf_mms_reusable = -1;                  /* BOOLEAN */
static int hf_mms_monitorType = -1;               /* BOOLEAN */
static int hf_mms_executionArgument = -1;         /* T_executionArgument */
static int hf_mms_simpleString = -1;              /* VisibleString */
static int hf_mms_encodedString = -1;             /* EXTERNALt */
static int hf_mms_executionArgument_01 = -1;      /* T_executionArgument_01 */
static int hf_mms_state_01 = -1;                  /* ProgramInvocationState */
static int hf_mms_listOfDomainNames = -1;         /* SEQUENCE_OF_Identifier */
static int hf_mms_listOfDomainNames_item = -1;    /* Identifier */
static int hf_mms_monitor = -1;                   /* BOOLEAN */
static int hf_mms_startArgument = -1;             /* VisibleString */
static int hf_mms_executionArgument_02 = -1;      /* T_executionArgument_02 */
static int hf_mms_typeName = -1;                  /* ObjectName */
static int hf_mms_array = -1;                     /* T_array */
static int hf_mms_packed = -1;                    /* BOOLEAN */
static int hf_mms_numberOfElements = -1;          /* Unsigned32 */
static int hf_mms_elementType = -1;               /* TypeSpecification */
static int hf_mms_structure = -1;                 /* T_structure */
static int hf_mms_components = -1;                /* T_components */
static int hf_mms_components_item = -1;           /* T_components_item */
static int hf_mms_componentName = -1;             /* Identifier */
static int hf_mms_componentType = -1;             /* TypeSpecification */
static int hf_mms_boolean = -1;                   /* NULL */
static int hf_mms_bit_string = -1;                /* Integer32 */
static int hf_mms_integer = -1;                   /* Unsigned8 */
static int hf_mms_unsigned = -1;                  /* Unsigned8 */
static int hf_mms_octet_string = -1;              /* Integer32 */
static int hf_mms_visible_string = -1;            /* Integer32 */
static int hf_mms_generalized_time = -1;          /* NULL */
static int hf_mms_binary_time = -1;               /* BOOLEAN */
static int hf_mms_bcd = -1;                       /* Unsigned8 */
static int hf_mms_objId = -1;                     /* NULL */
static int hf_mms_AlternateAccess_item = -1;      /* AlternateAccess_item */
static int hf_mms_unnamed = -1;                   /* AlternateAccessSelection */
static int hf_mms_named = -1;                     /* T_named */
static int hf_mms_accesst = -1;                   /* AlternateAccessSelection */
static int hf_mms_selectAlternateAccess = -1;     /* T_selectAlternateAccess */
static int hf_mms_accessSelection = -1;           /* T_accessSelection */
static int hf_mms_component = -1;                 /* Identifier */
static int hf_mms_index = -1;                     /* Unsigned32 */
static int hf_mms_indexRange = -1;                /* T_indexRange */
static int hf_mms_lowIndex = -1;                  /* Unsigned32 */
static int hf_mms_allElements = -1;               /* NULL */
static int hf_mms_alternateAccess = -1;           /* AlternateAccess */
static int hf_mms_selectAccess = -1;              /* T_selectAccess */
static int hf_mms_indexRange_01 = -1;             /* T_indexRange_01 */
static int hf_mms_nmberOfElements = -1;           /* Unsigned32 */
static int hf_mms_specificationWithResult = -1;   /* BOOLEAN */
static int hf_mms_variableAccessSpecificatn = -1;  /* VariableAccessSpecification */
static int hf_mms_listOfAccessResult = -1;        /* SEQUENCE_OF_AccessResult */
static int hf_mms_listOfAccessResult_item = -1;   /* AccessResult */
static int hf_mms_listOfData = -1;                /* SEQUENCE_OF_Data */
static int hf_mms_listOfData_item = -1;           /* Data */
static int hf_mms_Write_Response_item = -1;       /* Write_Response_item */
static int hf_mms_failure = -1;                   /* DataAccessError */
static int hf_mms_success = -1;                   /* NULL */
static int hf_mms_variableAccessSpecification = -1;  /* VariableAccessSpecification */
static int hf_mms_name = -1;                      /* ObjectName */
static int hf_mms_address = -1;                   /* Address */
static int hf_mms_typeSpecification = -1;         /* TypeSpecification */
static int hf_mms_variableName = -1;              /* ObjectName */
static int hf_mms_scatteredAccessName = -1;       /* ObjectName */
static int hf_mms_scatteredAccessDescription = -1;  /* ScatteredAccessDescription */
static int hf_mms_scopeOfDelete = -1;             /* T_scopeOfDelete */
static int hf_mms_listOfName = -1;                /* SEQUENCE_OF_ObjectName */
static int hf_mms_listOfName_item = -1;           /* ObjectName */
static int hf_mms_numberMatched = -1;             /* Unsigned32 */
static int hf_mms_numberDeleted = -1;             /* Unsigned32 */
static int hf_mms_variableListName = -1;          /* ObjectName */
static int hf_mms_listOfVariable = -1;            /* T_listOfVariable */
static int hf_mms_listOfVariable_item = -1;       /* T_listOfVariable_item */
static int hf_mms_variableSpecification = -1;     /* VariableSpecification */
static int hf_mms_listOfVariable_01 = -1;         /* T_listOfVariable_01 */
static int hf_mms_listOfVariable_item_01 = -1;    /* T_listOfVariable_item_01 */
static int hf_mms_scopeOfDelete_01 = -1;          /* T_scopeOfDelete_01 */
static int hf_mms_listOfVariableListName = -1;    /* SEQUENCE_OF_ObjectName */
static int hf_mms_listOfVariableListName_item = -1;  /* ObjectName */
static int hf_mms_scopeOfDelete_02 = -1;          /* T_scopeOfDelete_02 */
static int hf_mms_listOfTypeName = -1;            /* SEQUENCE_OF_ObjectName */
static int hf_mms_listOfTypeName_item = -1;       /* ObjectName */
static int hf_mms_success_01 = -1;                /* Data */
static int hf_mms_array_01 = -1;                  /* SEQUENCE_OF_Data */
static int hf_mms_array_item = -1;                /* Data */
static int hf_mms_structure_01 = -1;              /* SEQUENCE_OF_Data */
static int hf_mms_structure_item = -1;            /* Data */
static int hf_mms_boolean_01 = -1;                /* BOOLEAN */
static int hf_mms_bit_string_01 = -1;             /* BIT_STRING */
static int hf_mms_integer_01 = -1;                /* INTEGER */
static int hf_mms_unsigned_01 = -1;               /* INTEGER */
static int hf_mms_floating_point = -1;            /* FloatingPoint */
static int hf_mms_octet_string_01 = -1;           /* OCTET_STRING */
static int hf_mms_visible_string_01 = -1;         /* VisibleString */
static int hf_mms_binary_time_01 = -1;            /* TimeOfDay */
static int hf_mms_bcd_01 = -1;                    /* INTEGER */
static int hf_mms_booleanArray = -1;              /* BIT_STRING */
static int hf_mms_objId_01 = -1;                  /* OBJECT_IDENTIFIER */
static int hf_mms_mMSString = -1;                 /* MMSString */
static int hf_mms_utc_time = -1;                  /* UtcTime */
static int hf_mms_listOfVariable_02 = -1;         /* T_listOfVariable_02 */
static int hf_mms_listOfVariable_item_02 = -1;    /* T_listOfVariable_item_02 */
static int hf_mms_ScatteredAccessDescription_item = -1;  /* ScatteredAccessDescription_item */
static int hf_mms_variableDescription = -1;       /* T_variableDescription */
static int hf_mms_invalidated = -1;               /* NULL */
static int hf_mms_numericAddress = -1;            /* Unsigned32 */
static int hf_mms_symbolicAddress = -1;           /* VisibleString */
static int hf_mms_unconstrainedAddress = -1;      /* OCTET_STRING */
static int hf_mms_semaphoreName = -1;             /* ObjectName */
static int hf_mms_namedToken = -1;                /* Identifier */
static int hf_mms_priority = -1;                  /* Priority */
static int hf_mms_acceptableDelay = -1;           /* Unsigned32 */
static int hf_mms_controlTimeOut = -1;            /* Unsigned32 */
static int hf_mms_abortOnTimeOut = -1;            /* BOOLEAN */
static int hf_mms_relinquishIfConnectionLost = -1;  /* BOOLEAN */
static int hf_mms_applicationToPreempt = -1;      /* ApplicationReference */
static int hf_mms_noResult = -1;                  /* NULL */
static int hf_mms_numbersOfTokens = -1;           /* Unsigned16 */
static int hf_mms_class = -1;                     /* T_class */
static int hf_mms_numberOfTokens = -1;            /* Unsigned16 */
static int hf_mms_numberOfOwnedTokens = -1;       /* Unsigned16 */
static int hf_mms_numberOfHungTokens = -1;        /* Unsigned16 */
static int hf_mms_nameToStartAfter = -1;          /* Identifier */
static int hf_mms_listOfNamedTokens = -1;         /* T_listOfNamedTokens */
static int hf_mms_listOfNamedTokens_item = -1;    /* T_listOfNamedTokens_item */
static int hf_mms_freeNamedToken = -1;            /* Identifier */
static int hf_mms_ownedNamedToken = -1;           /* Identifier */
static int hf_mms_hungNamedToken = -1;            /* Identifier */
static int hf_mms_state_02 = -1;                  /* T_state */
static int hf_mms_entryIdToStartAfter = -1;       /* OCTET_STRING */
static int hf_mms_listOfSemaphoreEntry = -1;      /* SEQUENCE_OF_SemaphoreEntry */
static int hf_mms_listOfSemaphoreEntry_item = -1;  /* SemaphoreEntry */
static int hf_mms_entryId = -1;                   /* OCTET_STRING */
static int hf_mms_entryClass = -1;                /* T_entryClass */
static int hf_mms_applicationReference = -1;      /* ApplicationReference */
static int hf_mms_remainingTimeOut = -1;          /* Unsigned32 */
static int hf_mms_operatorStationName = -1;       /* Identifier */
static int hf_mms_echo = -1;                      /* BOOLEAN */
static int hf_mms_listOfPromptData = -1;          /* T_listOfPromptData */
static int hf_mms_listOfPromptData_item = -1;     /* VisibleString */
static int hf_mms_inputTimeOut = -1;              /* Unsigned32 */
static int hf_mms_listOfOutputData = -1;          /* T_listOfOutputData */
static int hf_mms_listOfOutputData_item = -1;     /* VisibleString */
static int hf_mms_eventConditionName = -1;        /* ObjectName */
static int hf_mms_class_01 = -1;                  /* EC_Class */
static int hf_mms_prio_rity = -1;                 /* Priority */
static int hf_mms_severity = -1;                  /* Unsigned8 */
static int hf_mms_alarmSummaryReports = -1;       /* BOOLEAN */
static int hf_mms_monitoredVariable = -1;         /* VariableSpecification */
static int hf_mms_evaluationInterval = -1;        /* Unsigned32 */
static int hf_mms_specific = -1;                  /* SEQUENCE_OF_ObjectName */
static int hf_mms_specific_item = -1;             /* ObjectName */
static int hf_mms_aa_specific_01 = -1;            /* NULL */
static int hf_mms_domain = -1;                    /* Identifier */
static int hf_mms_vmd = -1;                       /* NULL */
static int hf_mms_monitoredVariable_01 = -1;      /* T_monitoredVariable */
static int hf_mms_variableReference = -1;         /* VariableSpecification */
static int hf_mms_undefined = -1;                 /* NULL */
static int hf_mms_currentState = -1;              /* EC_State */
static int hf_mms_numberOfEventEnrollments = -1;  /* Unsigned32 */
static int hf_mms_enabled = -1;                   /* BOOLEAN */
static int hf_mms_timeOfLastTransitionToActive = -1;  /* EventTime */
static int hf_mms_timeOfLastTransitionToIdle = -1;  /* EventTime */
static int hf_mms_eventActionName = -1;           /* ObjectName */
static int hf_mms_eventEnrollmentName = -1;       /* ObjectName */
static int hf_mms_eventConditionTransition = -1;  /* Transitions */
static int hf_mms_alarmAcknowledgementRule = -1;  /* AlarmAckRule */
static int hf_mms_clientApplication = -1;         /* ApplicationReference */
static int hf_mms_ec = -1;                        /* ObjectName */
static int hf_mms_ea = -1;                        /* ObjectName */
static int hf_mms_scopeOfRequest = -1;            /* T_scopeOfRequest */
static int hf_mms_eventEnrollmentNames = -1;      /* SEQUENCE_OF_ObjectName */
static int hf_mms_eventEnrollmentNames_item = -1;  /* ObjectName */
static int hf_mms_continueAfter_02 = -1;          /* ObjectName */
static int hf_mms_eventConditionName_01 = -1;     /* T_eventConditionName */
static int hf_mms_eventCondition = -1;            /* ObjectName */
static int hf_mms_eventActionName_01 = -1;        /* T_eventActionName */
static int hf_mms_eventAction = -1;               /* ObjectName */
static int hf_mms_enrollmentClass = -1;           /* EE_Class */
static int hf_mms_duration = -1;                  /* EE_Duration */
static int hf_mms_remainingAcceptableDelay = -1;  /* Unsigned32 */
static int hf_mms_listOfEventEnrollment = -1;     /* SEQUENCE_OF_EventEnrollment */
static int hf_mms_listOfEventEnrollment_item = -1;  /* EventEnrollment */
static int hf_mms_eventConditionTransitions = -1;  /* Transitions */
static int hf_mms_notificationLost = -1;          /* BOOLEAN */
static int hf_mms_alarmAcknowledgmentRule = -1;   /* AlarmAckRule */
static int hf_mms_currentState_01 = -1;           /* EE_State */
static int hf_mms_currentState_02 = -1;           /* T_currentState */
static int hf_mms_state_03 = -1;                  /* EE_State */
static int hf_mms_transitionTime = -1;            /* EventTime */
static int hf_mms_acknowledgedState = -1;         /* EC_State */
static int hf_mms_timeOfAcknowledgedTransition = -1;  /* EventTime */
static int hf_mms_enrollmentsOnly = -1;           /* BOOLEAN */
static int hf_mms_activeAlarmsOnly = -1;          /* BOOLEAN */
static int hf_mms_acknowledgmentFilter = -1;      /* T_acknowledgmentFilter */
static int hf_mms_severityFilter = -1;            /* T_severityFilter */
static int hf_mms_mostSevere = -1;                /* Unsigned8 */
static int hf_mms_leastSevere = -1;               /* Unsigned8 */
static int hf_mms_listOfAlarmSummary = -1;        /* SEQUENCE_OF_AlarmSummary */
static int hf_mms_listOfAlarmSummary_item = -1;   /* AlarmSummary */
static int hf_mms_unacknowledgedState = -1;       /* T_unacknowledgedState */
static int hf_mms_acknowledgmentFilter_01 = -1;   /* T_acknowledgmentFilter_01 */
static int hf_mms_severityFilter_01 = -1;         /* T_severityFilter_01 */
static int hf_mms_listOfAlarmEnrollmentSummary = -1;  /* SEQUENCE_OF_AlarmEnrollmentSummary */
static int hf_mms_listOfAlarmEnrollmentSummary_item = -1;  /* AlarmEnrollmentSummary */
static int hf_mms_enrollementState = -1;          /* EE_State */
static int hf_mms_timeActiveAcknowledged = -1;    /* EventTime */
static int hf_mms_timeIdleAcknowledged = -1;      /* EventTime */
static int hf_mms_eventConditionName_02 = -1;     /* T_eventConditionName_01 */
static int hf_mms_actionResult = -1;              /* T_actionResult */
static int hf_mms_eventActioName = -1;            /* ObjectName */
static int hf_mms_eventActionResult = -1;         /* T_eventActionResult */
static int hf_mms_success_02 = -1;                /* ConfirmedServiceResponse */
static int hf_mms_failure_01 = -1;                /* ServiceError */
static int hf_mms_causingTransitions = -1;        /* Transitions */
static int hf_mms_timeOfDayT = -1;                /* TimeOfDay */
static int hf_mms_timeSequenceIdentifier = -1;    /* Unsigned32 */
static int hf_mms_journalName = -1;               /* ObjectName */
static int hf_mms_rangeStartSpecification = -1;   /* T_rangeStartSpecification */
static int hf_mms_startingTime = -1;              /* TimeOfDay */
static int hf_mms_startingEntry = -1;             /* OCTET_STRING */
static int hf_mms_rangeStopSpecification = -1;    /* T_rangeStopSpecification */
static int hf_mms_endingTime = -1;                /* TimeOfDay */
static int hf_mms_numberOfEntries = -1;           /* Integer32 */
static int hf_mms_listOfVariables = -1;           /* T_listOfVariables */
static int hf_mms_listOfVariables_item = -1;      /* VisibleString */
static int hf_mms_entryToStartAfter = -1;         /* T_entryToStartAfter */
static int hf_mms_timeSpecification = -1;         /* TimeOfDay */
static int hf_mms_entrySpecification = -1;        /* OCTET_STRING */
static int hf_mms_listOfJournalEntry = -1;        /* SEQUENCE_OF_JournalEntry */
static int hf_mms_listOfJournalEntry_item = -1;   /* JournalEntry */
static int hf_mms_entryIdentifier = -1;           /* OCTET_STRING */
static int hf_mms_originatingApplication = -1;    /* ApplicationReference */
static int hf_mms_entryContent = -1;              /* EntryContent */
static int hf_mms_listOfJournalEntry_01 = -1;     /* SEQUENCE_OF_EntryContent */
static int hf_mms_listOfJournalEntry_item_01 = -1;  /* EntryContent */
static int hf_mms_limitSpecification = -1;        /* T_limitSpecification */
static int hf_mms_limitingTime = -1;              /* TimeOfDay */
static int hf_mms_limitingEntry = -1;             /* OCTET_STRING */
static int hf_mms_currentEntries = -1;            /* Unsigned32 */
static int hf_mms_occurenceTime = -1;             /* TimeOfDay */
static int hf_mms_additionalDetail = -1;          /* JOU_Additional_Detail */
static int hf_mms_entryForm = -1;                 /* T_entryForm */
static int hf_mms_data = -1;                      /* T_data */
static int hf_mms_event = -1;                     /* T_event */
static int hf_mms_listOfVariables_01 = -1;        /* T_listOfVariables_01 */
static int hf_mms_listOfVariables_item_01 = -1;   /* T_listOfVariables_item */
static int hf_mms_variableTag = -1;               /* VisibleString */
static int hf_mms_valueSpecification = -1;        /* Data */
static int hf_mms_annotation = -1;                /* VisibleString */
static int hf_mms_sourceFileServer = -1;          /* ApplicationReference */
static int hf_mms_sourceFile = -1;                /* FileName */
static int hf_mms_destinationFile = -1;           /* FileName */
static int hf_mms_initialPosition = -1;           /* Unsigned32 */
static int hf_mms_frsmID = -1;                    /* Integer32 */
static int hf_mms_fileAttributes = -1;            /* FileAttributes */
static int hf_mms_fileData = -1;                  /* OCTET_STRING */
static int hf_mms_currentFileName = -1;           /* FileName */
static int hf_mms_newFileName = -1;               /* FileName */
static int hf_mms_fileSpecification = -1;         /* FileName */
static int hf_mms_continueAfter_03 = -1;          /* FileName */
static int hf_mms_listOfDirectoryEntry = -1;      /* SEQUENCE_OF_DirectoryEntry */
static int hf_mms_listOfDirectoryEntry_item = -1;  /* DirectoryEntry */
static int hf_mms_filename = -1;                  /* FileName */
static int hf_mms_sizeOfFile = -1;                /* Unsigned32 */
static int hf_mms_lastModified = -1;              /* GeneralizedTime */
/* named bits */
static int hf_mms_ParameterSupportOptions_str1 = -1;
static int hf_mms_ParameterSupportOptions_str2 = -1;
static int hf_mms_ParameterSupportOptions_vnam = -1;
static int hf_mms_ParameterSupportOptions_valt = -1;
static int hf_mms_ParameterSupportOptions_vadr = -1;
static int hf_mms_ParameterSupportOptions_vsca = -1;
static int hf_mms_ParameterSupportOptions_tpy = -1;
static int hf_mms_ParameterSupportOptions_vlis = -1;
static int hf_mms_ParameterSupportOptions_real = -1;
static int hf_mms_ParameterSupportOptions_cei = -1;
static int hf_mms_ServiceSupportOptions_status = -1;
static int hf_mms_ServiceSupportOptions_getNameList = -1;
static int hf_mms_ServiceSupportOptions_identify = -1;
static int hf_mms_ServiceSupportOptions_rename = -1;
static int hf_mms_ServiceSupportOptions_read = -1;
static int hf_mms_ServiceSupportOptions_write = -1;
static int hf_mms_ServiceSupportOptions_getVariableAccessAttributes = -1;
static int hf_mms_ServiceSupportOptions_defineNamedVariable = -1;
static int hf_mms_ServiceSupportOptions_defineScatteredAccess = -1;
static int hf_mms_ServiceSupportOptions_getScatteredAccessAttributes = -1;
static int hf_mms_ServiceSupportOptions_deleteVariableAccess = -1;
static int hf_mms_ServiceSupportOptions_defineNamedVariableList = -1;
static int hf_mms_ServiceSupportOptions_getNamedVariableListAttributes = -1;
static int hf_mms_ServiceSupportOptions_deleteNamedVariableList = -1;
static int hf_mms_ServiceSupportOptions_defineNamedType = -1;
static int hf_mms_ServiceSupportOptions_getNamedTypeAttributes = -1;
static int hf_mms_ServiceSupportOptions_deleteNamedType = -1;
static int hf_mms_ServiceSupportOptions_input = -1;
static int hf_mms_ServiceSupportOptions_output = -1;
static int hf_mms_ServiceSupportOptions_takeControl = -1;
static int hf_mms_ServiceSupportOptions_relinquishControl = -1;
static int hf_mms_ServiceSupportOptions_defineSemaphore = -1;
static int hf_mms_ServiceSupportOptions_deleteSemaphore = -1;
static int hf_mms_ServiceSupportOptions_reportSemaphoreStatus = -1;
static int hf_mms_ServiceSupportOptions_reportPoolSemaphoreStatus = -1;
static int hf_mms_ServiceSupportOptions_reportSemaphoreEntryStatus = -1;
static int hf_mms_ServiceSupportOptions_initiateDownloadSequence = -1;
static int hf_mms_ServiceSupportOptions_downloadSegment = -1;
static int hf_mms_ServiceSupportOptions_terminateDownloadSequence = -1;
static int hf_mms_ServiceSupportOptions_initiateUploadSequence = -1;
static int hf_mms_ServiceSupportOptions_uploadSegment = -1;
static int hf_mms_ServiceSupportOptions_terminateUploadSequence = -1;
static int hf_mms_ServiceSupportOptions_requestDomainDownload = -1;
static int hf_mms_ServiceSupportOptions_requestDomainUpload = -1;
static int hf_mms_ServiceSupportOptions_loadDomainContent = -1;
static int hf_mms_ServiceSupportOptions_storeDomainContent = -1;
static int hf_mms_ServiceSupportOptions_deleteDomain = -1;
static int hf_mms_ServiceSupportOptions_getDomainAttributes = -1;
static int hf_mms_ServiceSupportOptions_createProgramInvocation = -1;
static int hf_mms_ServiceSupportOptions_deleteProgramInvocation = -1;
static int hf_mms_ServiceSupportOptions_start = -1;
static int hf_mms_ServiceSupportOptions_stop = -1;
static int hf_mms_ServiceSupportOptions_resume = -1;
static int hf_mms_ServiceSupportOptions_reset = -1;
static int hf_mms_ServiceSupportOptions_kill = -1;
static int hf_mms_ServiceSupportOptions_getProgramInvocationAttributes = -1;
static int hf_mms_ServiceSupportOptions_obtainFile = -1;
static int hf_mms_ServiceSupportOptions_defineEventCondition = -1;
static int hf_mms_ServiceSupportOptions_deleteEventCondition = -1;
static int hf_mms_ServiceSupportOptions_getEventConditionAttributes = -1;
static int hf_mms_ServiceSupportOptions_reportEventConditionStatus = -1;
static int hf_mms_ServiceSupportOptions_alterEventConditionMonitoring = -1;
static int hf_mms_ServiceSupportOptions_triggerEvent = -1;
static int hf_mms_ServiceSupportOptions_defineEventAction = -1;
static int hf_mms_ServiceSupportOptions_deleteEventAction = -1;
static int hf_mms_ServiceSupportOptions_getEventActionAttributes = -1;
static int hf_mms_ServiceSupportOptions_reportActionStatus = -1;
static int hf_mms_ServiceSupportOptions_defineEventEnrollment = -1;
static int hf_mms_ServiceSupportOptions_deleteEventEnrollment = -1;
static int hf_mms_ServiceSupportOptions_alterEventEnrollment = -1;
static int hf_mms_ServiceSupportOptions_reportEventEnrollmentStatus = -1;
static int hf_mms_ServiceSupportOptions_getEventEnrollmentAttributes = -1;
static int hf_mms_ServiceSupportOptions_acknowledgeEventNotification = -1;
static int hf_mms_ServiceSupportOptions_getAlarmSummary = -1;
static int hf_mms_ServiceSupportOptions_getAlarmEnrollmentSummary = -1;
static int hf_mms_ServiceSupportOptions_readJournal = -1;
static int hf_mms_ServiceSupportOptions_writeJournal = -1;
static int hf_mms_ServiceSupportOptions_initializeJournal = -1;
static int hf_mms_ServiceSupportOptions_reportJournalStatus = -1;
static int hf_mms_ServiceSupportOptions_createJournal = -1;
static int hf_mms_ServiceSupportOptions_deleteJournal = -1;
static int hf_mms_ServiceSupportOptions_getCapabilityList = -1;
static int hf_mms_ServiceSupportOptions_fileOpen = -1;
static int hf_mms_ServiceSupportOptions_fileRead = -1;
static int hf_mms_ServiceSupportOptions_fileClose = -1;
static int hf_mms_ServiceSupportOptions_fileRename = -1;
static int hf_mms_ServiceSupportOptions_fileDelete = -1;
static int hf_mms_ServiceSupportOptions_fileDirectory = -1;
static int hf_mms_ServiceSupportOptions_unsolicitedStatus = -1;
static int hf_mms_ServiceSupportOptions_informationReport = -1;
static int hf_mms_ServiceSupportOptions_eventNotification = -1;
static int hf_mms_ServiceSupportOptions_attachToEventCondition = -1;
static int hf_mms_ServiceSupportOptions_attachToSemaphore = -1;
static int hf_mms_ServiceSupportOptions_conclude = -1;
static int hf_mms_ServiceSupportOptions_cancel = -1;
static int hf_mms_Transitions_idle_to_disabled = -1;
static int hf_mms_Transitions_active_to_disabled = -1;
static int hf_mms_Transitions_disabled_to_idle = -1;
static int hf_mms_Transitions_active_to_idle = -1;
static int hf_mms_Transitions_disabled_to_active = -1;
static int hf_mms_Transitions_idle_to_active = -1;
static int hf_mms_Transitions_any_to_deleted = -1;

/*--- End of included file: packet-mms-hf.c ---*/
#line 47 "../../asn1/mms/packet-mms-template.c"

/* Initialize the subtree pointers */
static gint ett_mms = -1;

/*--- Included file: packet-mms-ett.c ---*/
#line 1 "../../asn1/mms/packet-mms-ett.c"
static gint ett_mms_MMSpdu = -1;
static gint ett_mms_Confirmed_RequestPDU = -1;
static gint ett_mms_SEQUENCE_OF_Modifier = -1;
static gint ett_mms_Unconfirmed_PDU = -1;
static gint ett_mms_Confirmed_ResponsePDU = -1;
static gint ett_mms_Confirmed_ErrorPDU = -1;
static gint ett_mms_UnconfirmedService = -1;
static gint ett_mms_Modifier = -1;
static gint ett_mms_ConfirmedServiceRequest = -1;
static gint ett_mms_CS_Request_Detail = -1;
static gint ett_mms_ConfirmedServiceResponse = -1;
static gint ett_mms_FileName = -1;
static gint ett_mms_ObjectName = -1;
static gint ett_mms_T_domain_specific = -1;
static gint ett_mms_ApplicationReference = -1;
static gint ett_mms_Initiate_RequestPDU = -1;
static gint ett_mms_InitRequestDetail = -1;
static gint ett_mms_Initiate_ResponsePDU = -1;
static gint ett_mms_InitResponseDetail = -1;
static gint ett_mms_ParameterSupportOptions = -1;
static gint ett_mms_ServiceSupportOptions = -1;
static gint ett_mms_Cancel_ErrorPDU = -1;
static gint ett_mms_ServiceError = -1;
static gint ett_mms_T_errorClass = -1;
static gint ett_mms_T_serviceSpecificInformation = -1;
static gint ett_mms_RejectPDU = -1;
static gint ett_mms_T_rejectReason = -1;
static gint ett_mms_Status_Response = -1;
static gint ett_mms_GetNameList_Request = -1;
static gint ett_mms_T_extendedObjectClass = -1;
static gint ett_mms_T_objectScope = -1;
static gint ett_mms_GetNameList_Response = -1;
static gint ett_mms_SEQUENCE_OF_Identifier = -1;
static gint ett_mms_Identify_Response = -1;
static gint ett_mms_T_listOfAbstractSyntaxes = -1;
static gint ett_mms_Rename_Request = -1;
static gint ett_mms_T_extendedObjectClass_01 = -1;
static gint ett_mms_GetCapabilityList_Request = -1;
static gint ett_mms_GetCapabilityList_Response = -1;
static gint ett_mms_T_listOfCapabilities = -1;
static gint ett_mms_InitiateDownloadSequence_Request = -1;
static gint ett_mms_T_listOfCapabilities_01 = -1;
static gint ett_mms_DownloadSegment_Response = -1;
static gint ett_mms_T_loadData = -1;
static gint ett_mms_TerminateDownloadSequence_Request = -1;
static gint ett_mms_InitiateUploadSequence_Response = -1;
static gint ett_mms_T_listOfCapabilities_02 = -1;
static gint ett_mms_UploadSegment_Response = -1;
static gint ett_mms_T_loadData_01 = -1;
static gint ett_mms_RequestDomainDownload_Request = -1;
static gint ett_mms_T_listOfCapabilities_03 = -1;
static gint ett_mms_RequestDomainUpload_Request = -1;
static gint ett_mms_LoadDomainContent_Request = -1;
static gint ett_mms_T_listOfCapabilities_04 = -1;
static gint ett_mms_StoreDomainContent_Request = -1;
static gint ett_mms_GetDomainAttributes_Response = -1;
static gint ett_mms_T_listOfCapabilities_05 = -1;
static gint ett_mms_CreateProgramInvocation_Request = -1;
static gint ett_mms_Start_Request = -1;
static gint ett_mms_T_executionArgument = -1;
static gint ett_mms_Stop_Request = -1;
static gint ett_mms_Resume_Request = -1;
static gint ett_mms_T_executionArgument_01 = -1;
static gint ett_mms_Reset_Request = -1;
static gint ett_mms_Kill_Request = -1;
static gint ett_mms_GetProgramInvocationAttributes_Response = -1;
static gint ett_mms_T_executionArgument_02 = -1;
static gint ett_mms_TypeSpecification = -1;
static gint ett_mms_T_array = -1;
static gint ett_mms_T_structure = -1;
static gint ett_mms_T_components = -1;
static gint ett_mms_T_components_item = -1;
static gint ett_mms_AlternateAccess = -1;
static gint ett_mms_AlternateAccess_item = -1;
static gint ett_mms_T_named = -1;
static gint ett_mms_AlternateAccessSelection = -1;
static gint ett_mms_T_selectAlternateAccess = -1;
static gint ett_mms_T_accessSelection = -1;
static gint ett_mms_T_indexRange = -1;
static gint ett_mms_T_selectAccess = -1;
static gint ett_mms_T_indexRange_01 = -1;
static gint ett_mms_Read_Request = -1;
static gint ett_mms_Read_Response = -1;
static gint ett_mms_SEQUENCE_OF_AccessResult = -1;
static gint ett_mms_Write_Request = -1;
static gint ett_mms_SEQUENCE_OF_Data = -1;
static gint ett_mms_Write_Response = -1;
static gint ett_mms_Write_Response_item = -1;
static gint ett_mms_InformationReport = -1;
static gint ett_mms_GetVariableAccessAttributes_Request = -1;
static gint ett_mms_GetVariableAccessAttributes_Response = -1;
static gint ett_mms_DefineNamedVariable_Request = -1;
static gint ett_mms_DefineScatteredAccess_Request = -1;
static gint ett_mms_GetScatteredAccessAttributes_Response = -1;
static gint ett_mms_DeleteVariableAccess_Request = -1;
static gint ett_mms_SEQUENCE_OF_ObjectName = -1;
static gint ett_mms_DeleteVariableAccess_Response = -1;
static gint ett_mms_DefineNamedVariableList_Request = -1;
static gint ett_mms_T_listOfVariable = -1;
static gint ett_mms_T_listOfVariable_item = -1;
static gint ett_mms_GetNamedVariableListAttributes_Response = -1;
static gint ett_mms_T_listOfVariable_01 = -1;
static gint ett_mms_T_listOfVariable_item_01 = -1;
static gint ett_mms_DeleteNamedVariableList_Request = -1;
static gint ett_mms_DeleteNamedVariableList_Response = -1;
static gint ett_mms_DefineNamedType_Request = -1;
static gint ett_mms_GetNamedTypeAttributes_Response = -1;
static gint ett_mms_DeleteNamedType_Request = -1;
static gint ett_mms_DeleteNamedType_Response = -1;
static gint ett_mms_AccessResult = -1;
static gint ett_mms_Data = -1;
static gint ett_mms_VariableAccessSpecification = -1;
static gint ett_mms_T_listOfVariable_02 = -1;
static gint ett_mms_T_listOfVariable_item_02 = -1;
static gint ett_mms_ScatteredAccessDescription = -1;
static gint ett_mms_ScatteredAccessDescription_item = -1;
static gint ett_mms_VariableSpecification = -1;
static gint ett_mms_T_variableDescription = -1;
static gint ett_mms_Address = -1;
static gint ett_mms_TakeControl_Request = -1;
static gint ett_mms_TakeControl_Response = -1;
static gint ett_mms_RelinquishControl_Request = -1;
static gint ett_mms_DefineSemaphore_Request = -1;
static gint ett_mms_ReportSemaphoreStatus_Response = -1;
static gint ett_mms_ReportPoolSemaphoreStatus_Request = -1;
static gint ett_mms_ReportPoolSemaphoreStatus_Response = -1;
static gint ett_mms_T_listOfNamedTokens = -1;
static gint ett_mms_T_listOfNamedTokens_item = -1;
static gint ett_mms_ReportSemaphoreEntryStatus_Request = -1;
static gint ett_mms_ReportSemaphoreEntryStatus_Response = -1;
static gint ett_mms_SEQUENCE_OF_SemaphoreEntry = -1;
static gint ett_mms_AttachToSemaphore = -1;
static gint ett_mms_SemaphoreEntry = -1;
static gint ett_mms_Input_Request = -1;
static gint ett_mms_T_listOfPromptData = -1;
static gint ett_mms_Output_Request = -1;
static gint ett_mms_T_listOfOutputData = -1;
static gint ett_mms_DefineEventCondition_Request = -1;
static gint ett_mms_DeleteEventCondition_Request = -1;
static gint ett_mms_GetEventConditionAttributes_Response = -1;
static gint ett_mms_T_monitoredVariable = -1;
static gint ett_mms_ReportEventConditionStatus_Response = -1;
static gint ett_mms_AlterEventConditionMonitoring_Request = -1;
static gint ett_mms_TriggerEvent_Request = -1;
static gint ett_mms_DefineEventAction_Request = -1;
static gint ett_mms_DeleteEventAction_Request = -1;
static gint ett_mms_GetEventActionAttributes_Response = -1;
static gint ett_mms_DefineEventEnrollment_Request = -1;
static gint ett_mms_DeleteEventEnrollment_Request = -1;
static gint ett_mms_GetEventEnrollmentAttributes_Request = -1;
static gint ett_mms_EventEnrollment = -1;
static gint ett_mms_T_eventConditionName = -1;
static gint ett_mms_T_eventActionName = -1;
static gint ett_mms_GetEventEnrollmentAttributes_Response = -1;
static gint ett_mms_SEQUENCE_OF_EventEnrollment = -1;
static gint ett_mms_ReportEventEnrollmentStatus_Response = -1;
static gint ett_mms_AlterEventEnrollment_Request = -1;
static gint ett_mms_AlterEventEnrollment_Response = -1;
static gint ett_mms_T_currentState = -1;
static gint ett_mms_AcknowledgeEventNotification_Request = -1;
static gint ett_mms_GetAlarmSummary_Request = -1;
static gint ett_mms_T_severityFilter = -1;
static gint ett_mms_GetAlarmSummary_Response = -1;
static gint ett_mms_SEQUENCE_OF_AlarmSummary = -1;
static gint ett_mms_AlarmSummary = -1;
static gint ett_mms_GetAlarmEnrollmentSummary_Request = -1;
static gint ett_mms_T_severityFilter_01 = -1;
static gint ett_mms_GetAlarmEnrollmentSummary_Response = -1;
static gint ett_mms_SEQUENCE_OF_AlarmEnrollmentSummary = -1;
static gint ett_mms_AlarmEnrollmentSummary = -1;
static gint ett_mms_EventNotification = -1;
static gint ett_mms_T_eventConditionName_01 = -1;
static gint ett_mms_T_actionResult = -1;
static gint ett_mms_T_eventActionResult = -1;
static gint ett_mms_AttachToEventCondition = -1;
static gint ett_mms_EventTime = -1;
static gint ett_mms_Transitions = -1;
static gint ett_mms_ReadJournal_Request = -1;
static gint ett_mms_T_rangeStartSpecification = -1;
static gint ett_mms_T_rangeStopSpecification = -1;
static gint ett_mms_T_listOfVariables = -1;
static gint ett_mms_T_entryToStartAfter = -1;
static gint ett_mms_ReadJournal_Response = -1;
static gint ett_mms_SEQUENCE_OF_JournalEntry = -1;
static gint ett_mms_JournalEntry = -1;
static gint ett_mms_WriteJournal_Request = -1;
static gint ett_mms_SEQUENCE_OF_EntryContent = -1;
static gint ett_mms_InitializeJournal_Request = -1;
static gint ett_mms_T_limitSpecification = -1;
static gint ett_mms_ReportJournalStatus_Response = -1;
static gint ett_mms_CreateJournal_Request = -1;
static gint ett_mms_DeleteJournal_Request = -1;
static gint ett_mms_EntryContent = -1;
static gint ett_mms_T_entryForm = -1;
static gint ett_mms_T_data = -1;
static gint ett_mms_T_event = -1;
static gint ett_mms_T_listOfVariables_01 = -1;
static gint ett_mms_T_listOfVariables_item = -1;
static gint ett_mms_ObtainFile_Request = -1;
static gint ett_mms_FileOpen_Request = -1;
static gint ett_mms_FileOpen_Response = -1;
static gint ett_mms_FileRead_Response = -1;
static gint ett_mms_FileRename_Request = -1;
static gint ett_mms_FileDirectory_Request = -1;
static gint ett_mms_FileDirectory_Response = -1;
static gint ett_mms_SEQUENCE_OF_DirectoryEntry = -1;
static gint ett_mms_DirectoryEntry = -1;
static gint ett_mms_FileAttributes = -1;

/*--- End of included file: packet-mms-ett.c ---*/
#line 51 "../../asn1/mms/packet-mms-template.c"

static expert_field ei_mms_mal_timeofday_encoding = EI_INIT;
static expert_field ei_mms_mal_utctime_encoding = EI_INIT;


/*--- Included file: packet-mms-fn.c ---*/
#line 1 "../../asn1/mms/packet-mms-fn.c"
/*--- Cyclic dependencies ---*/

/* TypeSpecification -> TypeSpecification/array -> TypeSpecification */
/* TypeSpecification -> TypeSpecification/structure -> TypeSpecification/structure/components -> TypeSpecification/structure/components/_item -> TypeSpecification */
static int dissect_mms_TypeSpecification(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* VariableSpecification -> ScatteredAccessDescription -> ScatteredAccessDescription/_item -> VariableSpecification */
static int dissect_mms_VariableSpecification(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* AlternateAccess -> AlternateAccess/_item -> AlternateAccessSelection -> AlternateAccessSelection/selectAlternateAccess -> AlternateAccess */
static int dissect_mms_AlternateAccess(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* Data -> Data/array -> Data */
static int dissect_mms_Data(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);




static int
dissect_mms_Unsigned32(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_mms_Identifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_VisibleString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t T_domain_specific_sequence[] = {
  { &hf_mms_domainId        , BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_mms_Identifier },
  { &hf_mms_itemId          , BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_mms_Identifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_domain_specific(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_domain_specific_sequence, hf_index, ett_mms_T_domain_specific);

  return offset;
}


static const value_string mms_ObjectName_vals[] = {
  {   0, "vmd-specific" },
  {   1, "domain-specific" },
  {   2, "aa-specific" },
  { 0, NULL }
};

static const ber_choice_t ObjectName_choice[] = {
  {   0, &hf_mms_vmd_specific    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  {   1, &hf_mms_domain_specific , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_T_domain_specific },
  {   2, &hf_mms_aa_specific     , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_ObjectName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ObjectName_choice, hf_index, ett_mms_ObjectName,
                                 NULL);

  return offset;
}


static const asn_namedbit Transitions_bits[] = {
  {  0, &hf_mms_Transitions_idle_to_disabled, -1, -1, "idle-to-disabled", NULL },
  {  1, &hf_mms_Transitions_active_to_disabled, -1, -1, "active-to-disabled", NULL },
  {  2, &hf_mms_Transitions_disabled_to_idle, -1, -1, "disabled-to-idle", NULL },
  {  3, &hf_mms_Transitions_active_to_idle, -1, -1, "active-to-idle", NULL },
  {  4, &hf_mms_Transitions_disabled_to_active, -1, -1, "disabled-to-active", NULL },
  {  5, &hf_mms_Transitions_idle_to_active, -1, -1, "idle-to-active", NULL },
  {  6, &hf_mms_Transitions_any_to_deleted, -1, -1, "any-to-deleted", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_mms_Transitions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    Transitions_bits, hf_index, ett_mms_Transitions,
                                    NULL);

  return offset;
}


static const ber_sequence_t AttachToEventCondition_sequence[] = {
  { &hf_mms_eventEnrollmentName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { &hf_mms_eventConditionName, BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { &hf_mms_causingTransitions, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_Transitions },
  { &hf_mms_acceptableDelay , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_AttachToEventCondition(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttachToEventCondition_sequence, hf_index, ett_mms_AttachToEventCondition);

  return offset;
}



static int
dissect_mms_Unsigned8(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_mms_Priority(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Unsigned8(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_mms_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t AttachToSemaphore_sequence[] = {
  { &hf_mms_semaphoreName   , BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { &hf_mms_namedToken      , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { &hf_mms_priority        , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Priority },
  { &hf_mms_acceptableDelay , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  { &hf_mms_controlTimeOut  , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  { &hf_mms_abortOnTimeOut  , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_relinquishIfConnectionLost, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_AttachToSemaphore(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttachToSemaphore_sequence, hf_index, ett_mms_AttachToSemaphore);

  return offset;
}


static const value_string mms_Modifier_vals[] = {
  {   0, "attach-To-Event-Condition" },
  {   1, "attach-To-Semaphore" },
  { 0, NULL }
};

static const ber_choice_t Modifier_choice[] = {
  {   0, &hf_mms_attach_To_Event_Condition, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_AttachToEventCondition },
  {   1, &hf_mms_attach_To_Semaphore, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_AttachToSemaphore },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_Modifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Modifier_choice, hf_index, ett_mms_Modifier,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Modifier_sequence_of[1] = {
  { &hf_mms_listOfModifier_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_Modifier },
};

static int
dissect_mms_SEQUENCE_OF_Modifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Modifier_sequence_of, hf_index, ett_mms_SEQUENCE_OF_Modifier);

  return offset;
}



static int
dissect_mms_Status_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const value_string mms_T_objectClass_vals[] = {
  {   0, "nammedVariable" },
  {   1, "scatteredAccess" },
  {   2, "namedVariableList" },
  {   3, "namedType" },
  {   4, "semaphore" },
  {   5, "eventCondition" },
  {   6, "eventAction" },
  {   7, "eventEnrollment" },
  {   8, "journal" },
  {   9, "domain" },
  {  10, "programInvocation" },
  {  11, "operatorStation" },
  { 0, NULL }
};


static int
dissect_mms_T_objectClass(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string mms_T_extendedObjectClass_vals[] = {
  {   0, "objectClass" },
  { 0, NULL }
};

static const ber_choice_t T_extendedObjectClass_choice[] = {
  {   0, &hf_mms_objectClass     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_T_objectClass },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_extendedObjectClass(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_extendedObjectClass_choice, hf_index, ett_mms_T_extendedObjectClass,
                                 NULL);

  return offset;
}



static int
dissect_mms_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string mms_T_objectScope_vals[] = {
  {   0, "vmdSpecific" },
  {   1, "domainSpecific" },
  {   2, "aaSpecific" },
  { 0, NULL }
};

static const ber_choice_t T_objectScope_choice[] = {
  {   0, &hf_mms_vmdSpecific     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_NULL },
  {   1, &hf_mms_domainSpecific  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  {   2, &hf_mms_aaSpecific      , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_objectScope(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_objectScope_choice, hf_index, ett_mms_T_objectScope,
                                 NULL);

  return offset;
}


static const ber_sequence_t GetNameList_Request_sequence[] = {
  { &hf_mms_extendedObjectClass, BER_CLASS_CON, 0, 0, dissect_mms_T_extendedObjectClass },
  { &hf_mms_objectScope     , BER_CLASS_CON, 1, 0, dissect_mms_T_objectScope },
  { &hf_mms_continueAfter   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_GetNameList_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetNameList_Request_sequence, hf_index, ett_mms_GetNameList_Request);

  return offset;
}



static int
dissect_mms_Identify_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string mms_T_objectClass_01_vals[] = {
  {   0, "namedVariable" },
  {   1, "scatteredAccess" },
  {   2, "namedVariableList" },
  {   3, "namedType" },
  {   4, "semaphore" },
  {   5, "eventCondition" },
  {   6, "eventAction" },
  {   7, "eventEnrollment" },
  {   8, "journal" },
  {   9, "domain" },
  {  10, "programInvocation" },
  {  11, "operatorStation" },
  { 0, NULL }
};


static int
dissect_mms_T_objectClass_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string mms_T_extendedObjectClass_01_vals[] = {
  {   0, "objectClass" },
  { 0, NULL }
};

static const ber_choice_t T_extendedObjectClass_01_choice[] = {
  {   0, &hf_mms_objectClass_01  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_T_objectClass_01 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_extendedObjectClass_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_extendedObjectClass_01_choice, hf_index, ett_mms_T_extendedObjectClass_01,
                                 NULL);

  return offset;
}


static const ber_sequence_t Rename_Request_sequence[] = {
  { &hf_mms_extendedObjectClass_01, BER_CLASS_CON, 0, 0, dissect_mms_T_extendedObjectClass_01 },
  { &hf_mms_currentName     , BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { &hf_mms_newIdentifier   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_Rename_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Rename_Request_sequence, hf_index, ett_mms_Rename_Request);

  return offset;
}



static int
dissect_mms_VisibleString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_VisibleString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_mms_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string mms_Address_vals[] = {
  {   0, "numericAddress" },
  {   1, "symbolicAddress" },
  {   2, "unconstrainedAddress" },
  { 0, NULL }
};

static const ber_choice_t Address_choice[] = {
  {   0, &hf_mms_numericAddress  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  {   1, &hf_mms_symbolicAddress , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_VisibleString },
  {   2, &hf_mms_unconstrainedAddress, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_OCTET_STRING },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_Address(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Address_choice, hf_index, ett_mms_Address,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_array_sequence[] = {
  { &hf_mms_packed          , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_numberOfElements, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  { &hf_mms_elementType     , BER_CLASS_CON, 2, BER_FLAGS_NOTCHKTAG, dissect_mms_TypeSpecification },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_array(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_array_sequence, hf_index, ett_mms_T_array);

  return offset;
}


static const ber_sequence_t T_components_item_sequence[] = {
  { &hf_mms_componentName   , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { &hf_mms_componentType   , BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_mms_TypeSpecification },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_components_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_components_item_sequence, hf_index, ett_mms_T_components_item);

  return offset;
}


static const ber_sequence_t T_components_sequence_of[1] = {
  { &hf_mms_components_item , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_mms_T_components_item },
};

static int
dissect_mms_T_components(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_components_sequence_of, hf_index, ett_mms_T_components);

  return offset;
}


static const ber_sequence_t T_structure_sequence[] = {
  { &hf_mms_packed          , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_components      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_T_components },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_structure(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_structure_sequence, hf_index, ett_mms_T_structure);

  return offset;
}



static int
dissect_mms_Integer32(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string mms_TypeSpecification_vals[] = {
  {   0, "typeName" },
  {   1, "array" },
  {   2, "structure" },
  {   3, "boolean" },
  {   4, "bit-string" },
  {   5, "integer" },
  {   6, "unsigned" },
  {   9, "octet-string" },
  {  10, "visible-string" },
  {  11, "generalized-time" },
  {  12, "binary-time" },
  {  13, "bcd" },
  {  15, "objId" },
  { 0, NULL }
};

static const ber_choice_t TypeSpecification_choice[] = {
  {   0, &hf_mms_typeName        , BER_CLASS_CON, 0, 0, dissect_mms_ObjectName },
  {   1, &hf_mms_array           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_T_array },
  {   2, &hf_mms_structure       , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_T_structure },
  {   3, &hf_mms_boolean         , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_mms_NULL },
  {   4, &hf_mms_bit_string      , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_mms_Integer32 },
  {   5, &hf_mms_integer         , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned8 },
  {   6, &hf_mms_unsigned        , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned8 },
  {   9, &hf_mms_octet_string    , BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_mms_Integer32 },
  {  10, &hf_mms_visible_string  , BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_mms_Integer32 },
  {  11, &hf_mms_generalized_time, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_mms_NULL },
  {  12, &hf_mms_binary_time     , BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  {  13, &hf_mms_bcd             , BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned8 },
  {  15, &hf_mms_objId           , BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_mms_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_TypeSpecification(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 TypeSpecification_choice, hf_index, ett_mms_TypeSpecification,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_variableDescription_sequence[] = {
  { &hf_mms_address         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_Address },
  { &hf_mms_typeSpecification, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_TypeSpecification },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_variableDescription(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_variableDescription_sequence, hf_index, ett_mms_T_variableDescription);

  return offset;
}


static const ber_sequence_t T_indexRange_sequence[] = {
  { &hf_mms_lowIndex        , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  { &hf_mms_numberOfElements, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_indexRange(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_indexRange_sequence, hf_index, ett_mms_T_indexRange);

  return offset;
}


static const value_string mms_T_accessSelection_vals[] = {
  {   0, "component" },
  {   1, "index" },
  {   2, "indexRange" },
  {   3, "allElements" },
  { 0, NULL }
};

static const ber_choice_t T_accessSelection_choice[] = {
  {   0, &hf_mms_component       , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  {   1, &hf_mms_index           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  {   2, &hf_mms_indexRange      , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_T_indexRange },
  {   3, &hf_mms_allElements     , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_mms_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_accessSelection(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_accessSelection_choice, hf_index, ett_mms_T_accessSelection,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_selectAlternateAccess_sequence[] = {
  { &hf_mms_accessSelection , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_T_accessSelection },
  { &hf_mms_alternateAccess , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_mms_AlternateAccess },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_selectAlternateAccess(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_selectAlternateAccess_sequence, hf_index, ett_mms_T_selectAlternateAccess);

  return offset;
}


static const ber_sequence_t T_indexRange_01_sequence[] = {
  { &hf_mms_lowIndex        , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  { &hf_mms_nmberOfElements , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_indexRange_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_indexRange_01_sequence, hf_index, ett_mms_T_indexRange_01);

  return offset;
}


static const value_string mms_T_selectAccess_vals[] = {
  {   1, "component" },
  {   2, "index" },
  {   3, "indexRange" },
  {   4, "allElements" },
  { 0, NULL }
};

static const ber_choice_t T_selectAccess_choice[] = {
  {   1, &hf_mms_component       , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  {   2, &hf_mms_index           , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  {   3, &hf_mms_indexRange_01   , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_mms_T_indexRange_01 },
  {   4, &hf_mms_allElements     , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_mms_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_selectAccess(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_selectAccess_choice, hf_index, ett_mms_T_selectAccess,
                                 NULL);

  return offset;
}


static const value_string mms_AlternateAccessSelection_vals[] = {
  {   0, "selectAlternateAccess" },
  {   1, "selectAccess" },
  { 0, NULL }
};

static const ber_choice_t AlternateAccessSelection_choice[] = {
  {   0, &hf_mms_selectAlternateAccess, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_T_selectAlternateAccess },
  {   1, &hf_mms_selectAccess    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_mms_T_selectAccess },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_AlternateAccessSelection(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AlternateAccessSelection_choice, hf_index, ett_mms_AlternateAccessSelection,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_named_sequence[] = {
  { &hf_mms_componentName   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { &hf_mms_accesst         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_AlternateAccessSelection },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_named(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_named_sequence, hf_index, ett_mms_T_named);

  return offset;
}


static const value_string mms_AlternateAccess_item_vals[] = {
  {   0, "unnamed" },
  {   1, "named" },
  { 0, NULL }
};

static const ber_choice_t AlternateAccess_item_choice[] = {
  {   0, &hf_mms_unnamed         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_mms_AlternateAccessSelection },
  {   1, &hf_mms_named           , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_mms_T_named },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_AlternateAccess_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AlternateAccess_item_choice, hf_index, ett_mms_AlternateAccess_item,
                                 NULL);

  return offset;
}


static const ber_sequence_t AlternateAccess_sequence_of[1] = {
  { &hf_mms_AlternateAccess_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_AlternateAccess_item },
};

static int
dissect_mms_AlternateAccess(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      AlternateAccess_sequence_of, hf_index, ett_mms_AlternateAccess);

  return offset;
}


static const ber_sequence_t ScatteredAccessDescription_item_sequence[] = {
  { &hf_mms_componentName   , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { &hf_mms_variableSpecification, BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_mms_VariableSpecification },
  { &hf_mms_alternateAccess , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_AlternateAccess },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_ScatteredAccessDescription_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ScatteredAccessDescription_item_sequence, hf_index, ett_mms_ScatteredAccessDescription_item);

  return offset;
}


static const ber_sequence_t ScatteredAccessDescription_sequence_of[1] = {
  { &hf_mms_ScatteredAccessDescription_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_mms_ScatteredAccessDescription_item },
};

static int
dissect_mms_ScatteredAccessDescription(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      ScatteredAccessDescription_sequence_of, hf_index, ett_mms_ScatteredAccessDescription);

  return offset;
}


static const value_string mms_VariableSpecification_vals[] = {
  {   0, "name" },
  {   1, "address" },
  {   2, "variableDescription" },
  {   3, "scatteredAccessDescription" },
  {   4, "invalidated" },
  { 0, NULL }
};

static const ber_choice_t VariableSpecification_choice[] = {
  {   0, &hf_mms_name            , BER_CLASS_CON, 0, 0, dissect_mms_ObjectName },
  {   1, &hf_mms_address         , BER_CLASS_CON, 1, 0, dissect_mms_Address },
  {   2, &hf_mms_variableDescription, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_T_variableDescription },
  {   3, &hf_mms_scatteredAccessDescription, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_mms_ScatteredAccessDescription },
  {   4, &hf_mms_invalidated     , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_mms_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_VariableSpecification(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 VariableSpecification_choice, hf_index, ett_mms_VariableSpecification,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_listOfVariable_item_02_sequence[] = {
  { &hf_mms_variableSpecification, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_VariableSpecification },
  { &hf_mms_alternateAccess , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_AlternateAccess },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_listOfVariable_item_02(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_listOfVariable_item_02_sequence, hf_index, ett_mms_T_listOfVariable_item_02);

  return offset;
}


static const ber_sequence_t T_listOfVariable_02_sequence_of[1] = {
  { &hf_mms_listOfVariable_item_02, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_mms_T_listOfVariable_item_02 },
};

static int
dissect_mms_T_listOfVariable_02(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_listOfVariable_02_sequence_of, hf_index, ett_mms_T_listOfVariable_02);

  return offset;
}


static const value_string mms_VariableAccessSpecification_vals[] = {
  {   0, "listOfVariable" },
  {   1, "variableListName" },
  { 0, NULL }
};

static const ber_choice_t VariableAccessSpecification_choice[] = {
  {   0, &hf_mms_listOfVariable_02, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_T_listOfVariable_02 },
  {   1, &hf_mms_variableListName, BER_CLASS_CON, 1, 0, dissect_mms_ObjectName },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_VariableAccessSpecification(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 VariableAccessSpecification_choice, hf_index, ett_mms_VariableAccessSpecification,
                                 NULL);

  return offset;
}


static const ber_sequence_t Read_Request_sequence[] = {
  { &hf_mms_specificationWithResult, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_variableAccessSpecificatn, BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_mms_VariableAccessSpecification },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_Read_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Read_Request_sequence, hf_index, ett_mms_Read_Request);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Data_sequence_of[1] = {
  { &hf_mms_listOfData_item , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_Data },
};

static int
dissect_mms_SEQUENCE_OF_Data(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Data_sequence_of, hf_index, ett_mms_SEQUENCE_OF_Data);

  return offset;
}



static int
dissect_mms_BIT_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}



static int
dissect_mms_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_mms_FloatingPoint(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_mms_TimeOfDay(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 48 "../../asn1/mms/mms.cnf"

	guint32 len;
	guint32 milliseconds;
	guint16 days;
	gchar *	ptime;
	nstime_t ts;

	len = tvb_length_remaining(tvb, offset);

	if(len == 4)
	{
		milliseconds = tvb_get_ntohl(tvb, offset);
		ptime = time_msecs_to_str(wmem_packet_scope(), milliseconds);

		if(hf_index >= 0)
		{
			proto_tree_add_string(tree, hf_index, tvb, offset, len, ptime);
		}
		return offset;
	}

	if(len == 6)
	{
		milliseconds = tvb_get_ntohl(tvb, offset);
		days = tvb_get_ntohs(tvb, offset+4);

		/* 5113 days between 01-01-1970 and 01-01-1984 */
		/* 86400 seconds in one day */

		ts.secs = (days + 5113) * 86400 + milliseconds / 1000;
		ts.nsecs = (milliseconds % 1000) * 1000000U;

		ptime = abs_time_to_str(wmem_packet_scope(), &ts, ABSOLUTE_TIME_UTC, TRUE);
		if(hf_index >= 0)
		{
			proto_tree_add_string(tree, hf_index, tvb, offset, len, ptime);
		}

		return offset;
	}

	proto_tree_add_expert_format(tree, actx->pinfo, &ei_mms_mal_timeofday_encoding,
			tvb, offset, len, "BER Error: malformed TimeOfDay encoding, length must be 4 or 6 bytes");
	if(hf_index >= 0)
	{
		proto_tree_add_string(tree, hf_index, tvb, offset, len, "????");
	}
	return offset;




  return offset;
}



static int
dissect_mms_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_mms_MMSString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_mms_UtcTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 99 "../../asn1/mms/mms.cnf"

	guint32 len;
	guint32 seconds;
	guint32	fraction;
	guint32 nanoseconds;
	nstime_t ts;
	gchar *	ptime;

	len = tvb_length_remaining(tvb, offset);

	if(len != 8)
	{
		proto_tree_add_expert_format(tree, actx->pinfo, &ei_mms_mal_utctime_encoding,
				tvb, offset, len, "BER Error: malformed IEC61850 UTCTime encoding, length must be 8 bytes");
		if(hf_index >= 0)
		{
			proto_tree_add_string(tree, hf_index, tvb, offset, len, "????");
		}
		return offset;
	}

	seconds = tvb_get_ntohl(tvb, offset);
	fraction = tvb_get_ntoh24(tvb, offset+4) * 0x100; /* Only 3 bytes are recommended */
	nanoseconds = (guint32)( ((guint64)fraction * G_GUINT64_CONSTANT(1000000000)) / G_GUINT64_CONSTANT(0x100000000) ) ;

	ts.secs = seconds;
	ts.nsecs = nanoseconds;

	ptime = abs_time_to_str(wmem_packet_scope(), &ts, ABSOLUTE_TIME_UTC, TRUE);

	if(hf_index >= 0)
	{
		proto_tree_add_string(tree, hf_index, tvb, offset, len, ptime);
	}

	return offset;


  return offset;
}


static const value_string mms_Data_vals[] = {
  {   1, "array" },
  {   2, "structure" },
  {   3, "boolean" },
  {   4, "bit-string" },
  {   5, "integer" },
  {   6, "unsigned" },
  {   7, "floating-point" },
  {   9, "octet-string" },
  {  10, "visible-string" },
  {  12, "binary-time" },
  {  13, "bcd" },
  {  14, "booleanArray" },
  {  15, "objId" },
  {  16, "mMSString" },
  {  17, "utc-time" },
  { 0, NULL }
};

static const ber_choice_t Data_choice[] = {
  {   1, &hf_mms_array_01        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_SEQUENCE_OF_Data },
  {   2, &hf_mms_structure_01    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_SEQUENCE_OF_Data },
  {   3, &hf_mms_boolean_01      , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  {   4, &hf_mms_bit_string_01   , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_mms_BIT_STRING },
  {   5, &hf_mms_integer_01      , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_mms_INTEGER },
  {   6, &hf_mms_unsigned_01     , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_mms_INTEGER },
  {   7, &hf_mms_floating_point  , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_mms_FloatingPoint },
  {   9, &hf_mms_octet_string_01 , BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_mms_OCTET_STRING },
  {  10, &hf_mms_visible_string_01, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_mms_VisibleString },
  {  12, &hf_mms_binary_time_01  , BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_mms_TimeOfDay },
  {  13, &hf_mms_bcd_01          , BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_mms_INTEGER },
  {  14, &hf_mms_booleanArray    , BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_mms_BIT_STRING },
  {  15, &hf_mms_objId_01        , BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_mms_OBJECT_IDENTIFIER },
  {  16, &hf_mms_mMSString       , BER_CLASS_CON, 16, BER_FLAGS_IMPLTAG, dissect_mms_MMSString },
  {  17, &hf_mms_utc_time        , BER_CLASS_CON, 17, BER_FLAGS_IMPLTAG, dissect_mms_UtcTime },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_Data(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Data_choice, hf_index, ett_mms_Data,
                                 NULL);

  return offset;
}


static const ber_sequence_t Write_Request_sequence[] = {
  { &hf_mms_variableAccessSpecificatn, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_VariableAccessSpecification },
  { &hf_mms_listOfData      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_SEQUENCE_OF_Data },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_Write_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Write_Request_sequence, hf_index, ett_mms_Write_Request);

  return offset;
}


static const value_string mms_GetVariableAccessAttributes_Request_vals[] = {
  {   0, "name" },
  {   1, "address" },
  { 0, NULL }
};

static const ber_choice_t GetVariableAccessAttributes_Request_choice[] = {
  {   0, &hf_mms_name            , BER_CLASS_CON, 0, 0, dissect_mms_ObjectName },
  {   1, &hf_mms_address         , BER_CLASS_CON, 1, 0, dissect_mms_Address },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_GetVariableAccessAttributes_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 GetVariableAccessAttributes_Request_choice, hf_index, ett_mms_GetVariableAccessAttributes_Request,
                                 NULL);

  return offset;
}


static const ber_sequence_t DefineNamedVariable_Request_sequence[] = {
  { &hf_mms_variableName    , BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { &hf_mms_address         , BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_mms_Address },
  { &hf_mms_typeSpecification, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_mms_TypeSpecification },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_DefineNamedVariable_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DefineNamedVariable_Request_sequence, hf_index, ett_mms_DefineNamedVariable_Request);

  return offset;
}


static const ber_sequence_t DefineScatteredAccess_Request_sequence[] = {
  { &hf_mms_scatteredAccessName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { &hf_mms_scatteredAccessDescription, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_ScatteredAccessDescription },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_DefineScatteredAccess_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DefineScatteredAccess_Request_sequence, hf_index, ett_mms_DefineScatteredAccess_Request);

  return offset;
}



static int
dissect_mms_GetScatteredAccessAttributes_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_ObjectName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string mms_T_scopeOfDelete_vals[] = {
  {   0, "specific" },
  {   1, "aa-specific" },
  {   2, "domain" },
  {   3, "vmd" },
  { 0, NULL }
};


static int
dissect_mms_T_scopeOfDelete(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ObjectName_sequence_of[1] = {
  { &hf_mms_listOfName_item , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
};

static int
dissect_mms_SEQUENCE_OF_ObjectName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ObjectName_sequence_of, hf_index, ett_mms_SEQUENCE_OF_ObjectName);

  return offset;
}


static const ber_sequence_t DeleteVariableAccess_Request_sequence[] = {
  { &hf_mms_scopeOfDelete   , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_T_scopeOfDelete },
  { &hf_mms_listOfName      , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_SEQUENCE_OF_ObjectName },
  { &hf_mms_domainName      , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_DeleteVariableAccess_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DeleteVariableAccess_Request_sequence, hf_index, ett_mms_DeleteVariableAccess_Request);

  return offset;
}


static const ber_sequence_t T_listOfVariable_item_sequence[] = {
  { &hf_mms_variableSpecification, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_VariableSpecification },
  { &hf_mms_alternateAccess , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_AlternateAccess },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_listOfVariable_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_listOfVariable_item_sequence, hf_index, ett_mms_T_listOfVariable_item);

  return offset;
}


static const ber_sequence_t T_listOfVariable_sequence_of[1] = {
  { &hf_mms_listOfVariable_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_mms_T_listOfVariable_item },
};

static int
dissect_mms_T_listOfVariable(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_listOfVariable_sequence_of, hf_index, ett_mms_T_listOfVariable);

  return offset;
}


static const ber_sequence_t DefineNamedVariableList_Request_sequence[] = {
  { &hf_mms_variableListName, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { &hf_mms_listOfVariable  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_T_listOfVariable },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_DefineNamedVariableList_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DefineNamedVariableList_Request_sequence, hf_index, ett_mms_DefineNamedVariableList_Request);

  return offset;
}



static int
dissect_mms_GetNamedVariableListAttributes_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_ObjectName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string mms_T_scopeOfDelete_01_vals[] = {
  {   0, "specific" },
  {   1, "aa-specific" },
  {   2, "domain" },
  {   3, "vmd" },
  { 0, NULL }
};


static int
dissect_mms_T_scopeOfDelete_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t DeleteNamedVariableList_Request_sequence[] = {
  { &hf_mms_scopeOfDelete_01, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_T_scopeOfDelete_01 },
  { &hf_mms_listOfVariableListName, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_SEQUENCE_OF_ObjectName },
  { &hf_mms_domainName      , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_DeleteNamedVariableList_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DeleteNamedVariableList_Request_sequence, hf_index, ett_mms_DeleteNamedVariableList_Request);

  return offset;
}


static const ber_sequence_t DefineNamedType_Request_sequence[] = {
  { &hf_mms_typeName        , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { &hf_mms_typeSpecification, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_TypeSpecification },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_DefineNamedType_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DefineNamedType_Request_sequence, hf_index, ett_mms_DefineNamedType_Request);

  return offset;
}



static int
dissect_mms_GetNamedTypeAttributes_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_ObjectName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string mms_T_scopeOfDelete_02_vals[] = {
  {   0, "specific" },
  {   1, "aa-specific" },
  {   2, "domain" },
  {   3, "vmd" },
  { 0, NULL }
};


static int
dissect_mms_T_scopeOfDelete_02(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t DeleteNamedType_Request_sequence[] = {
  { &hf_mms_scopeOfDelete_02, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_T_scopeOfDelete_02 },
  { &hf_mms_listOfTypeName  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_SEQUENCE_OF_ObjectName },
  { &hf_mms_domainName      , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_DeleteNamedType_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DeleteNamedType_Request_sequence, hf_index, ett_mms_DeleteNamedType_Request);

  return offset;
}


static const ber_sequence_t T_listOfPromptData_sequence_of[1] = {
  { &hf_mms_listOfPromptData_item, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_mms_VisibleString },
};

static int
dissect_mms_T_listOfPromptData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_listOfPromptData_sequence_of, hf_index, ett_mms_T_listOfPromptData);

  return offset;
}


static const ber_sequence_t Input_Request_sequence[] = {
  { &hf_mms_operatorStationName, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { &hf_mms_echo            , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_listOfPromptData, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_T_listOfPromptData },
  { &hf_mms_inputTimeOut    , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_Input_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Input_Request_sequence, hf_index, ett_mms_Input_Request);

  return offset;
}


static const ber_sequence_t T_listOfOutputData_sequence_of[1] = {
  { &hf_mms_listOfOutputData_item, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_mms_VisibleString },
};

static int
dissect_mms_T_listOfOutputData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_listOfOutputData_sequence_of, hf_index, ett_mms_T_listOfOutputData);

  return offset;
}


static const ber_sequence_t Output_Request_sequence[] = {
  { &hf_mms_operatorStationName, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { &hf_mms_listOfOutputData, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_T_listOfOutputData },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_Output_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Output_Request_sequence, hf_index, ett_mms_Output_Request);

  return offset;
}



static int
dissect_mms_T_ap_title(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 25 "../../asn1/mms/mms.cnf"
  offset=dissect_acse_AP_title(FALSE, tvb, offset, actx, tree, hf_mms_ap_title);



  return offset;
}



static int
dissect_mms_T_ap_invocation_id(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 28 "../../asn1/mms/mms.cnf"
  offset=dissect_acse_AP_invocation_identifier(FALSE, tvb, offset, actx, tree, hf_mms_ap_invocation_id);



  return offset;
}



static int
dissect_mms_T_ae_qualifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 31 "../../asn1/mms/mms.cnf"
  offset=dissect_acse_AE_qualifier(FALSE, tvb, offset, actx, tree, hf_mms_ae_qualifier);



  return offset;
}



static int
dissect_mms_T_ae_invocation_id(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 34 "../../asn1/mms/mms.cnf"
  offset=dissect_acse_AE_invocation_identifier(FALSE, tvb, offset, actx, tree, hf_mms_ae_invocation_id);



  return offset;
}


static const ber_sequence_t ApplicationReference_sequence[] = {
  { &hf_mms_ap_title        , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_mms_T_ap_title },
  { &hf_mms_ap_invocation_id, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_mms_T_ap_invocation_id },
  { &hf_mms_ae_qualifier    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_mms_T_ae_qualifier },
  { &hf_mms_ae_invocation_id, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_mms_T_ae_invocation_id },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_ApplicationReference(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ApplicationReference_sequence, hf_index, ett_mms_ApplicationReference);

  return offset;
}


static const ber_sequence_t TakeControl_Request_sequence[] = {
  { &hf_mms_semaphoreName   , BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { &hf_mms_namedToken      , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { &hf_mms_priority        , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Priority },
  { &hf_mms_acceptableDelay , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  { &hf_mms_controlTimeOut  , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  { &hf_mms_abortOnTimeOut  , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_relinquishIfConnectionLost, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_applicationToPreempt, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_ApplicationReference },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_TakeControl_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TakeControl_Request_sequence, hf_index, ett_mms_TakeControl_Request);

  return offset;
}


static const ber_sequence_t RelinquishControl_Request_sequence[] = {
  { &hf_mms_semaphoreName   , BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { &hf_mms_namedToken      , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_RelinquishControl_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RelinquishControl_Request_sequence, hf_index, ett_mms_RelinquishControl_Request);

  return offset;
}



static int
dissect_mms_Unsigned16(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t DefineSemaphore_Request_sequence[] = {
  { &hf_mms_semaphoreName   , BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { &hf_mms_numbersOfTokens , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned16 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_DefineSemaphore_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DefineSemaphore_Request_sequence, hf_index, ett_mms_DefineSemaphore_Request);

  return offset;
}



static int
dissect_mms_DeleteSemaphore_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_ObjectName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_mms_ReportSemaphoreStatus_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_ObjectName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t ReportPoolSemaphoreStatus_Request_sequence[] = {
  { &hf_mms_semaphoreName   , BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { &hf_mms_nameToStartAfter, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_ReportPoolSemaphoreStatus_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReportPoolSemaphoreStatus_Request_sequence, hf_index, ett_mms_ReportPoolSemaphoreStatus_Request);

  return offset;
}


static const value_string mms_T_state_vals[] = {
  {   0, "queued" },
  {   1, "owner" },
  {   2, "hung" },
  { 0, NULL }
};


static int
dissect_mms_T_state(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t ReportSemaphoreEntryStatus_Request_sequence[] = {
  { &hf_mms_semaphoreName   , BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { &hf_mms_state_02        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_T_state },
  { &hf_mms_entryIdToStartAfter, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_ReportSemaphoreEntryStatus_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReportSemaphoreEntryStatus_Request_sequence, hf_index, ett_mms_ReportSemaphoreEntryStatus_Request);

  return offset;
}


static const ber_sequence_t T_listOfCapabilities_01_sequence_of[1] = {
  { &hf_mms_listOfCapabilities_item, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_mms_VisibleString },
};

static int
dissect_mms_T_listOfCapabilities_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_listOfCapabilities_01_sequence_of, hf_index, ett_mms_T_listOfCapabilities_01);

  return offset;
}


static const ber_sequence_t InitiateDownloadSequence_Request_sequence[] = {
  { &hf_mms_domainName      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { &hf_mms_listOfCapabilities_01, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_T_listOfCapabilities_01 },
  { &hf_mms_sharable        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_InitiateDownloadSequence_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InitiateDownloadSequence_Request_sequence, hf_index, ett_mms_InitiateDownloadSequence_Request);

  return offset;
}



static int
dissect_mms_DownloadSegment_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Identifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string mms_T_vmd_state_vals[] = {
  {   0, "other" },
  {   1, "vmd-state-conflict" },
  {   2, "vmd-operational-problem" },
  {   3, "domain-transfer-problem" },
  {   4, "state-machine-id-invalid" },
  { 0, NULL }
};


static int
dissect_mms_T_vmd_state(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string mms_T_application_reference_vals[] = {
  {   0, "other" },
  {   1, "aplication-unreachable" },
  {   2, "connection-lost" },
  {   3, "application-reference-invalid" },
  {   4, "context-unsupported" },
  { 0, NULL }
};


static int
dissect_mms_T_application_reference(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string mms_T_definition_vals[] = {
  {   0, "other" },
  {   1, "object-undefined" },
  {   2, "invalid-address" },
  {   3, "type-unsupported" },
  {   4, "type-inconsistent" },
  {   5, "object-exists" },
  {   6, "object-attribute-inconsistent" },
  { 0, NULL }
};


static int
dissect_mms_T_definition(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string mms_T_resource_vals[] = {
  {   0, "other" },
  {   1, "memory-unavailable" },
  {   2, "processor-resource-unavailable" },
  {   3, "mass-storage-unavailable" },
  {   4, "capability-unavailable" },
  {   5, "capability-unknown" },
  { 0, NULL }
};


static int
dissect_mms_T_resource(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string mms_T_service_vals[] = {
  {   0, "other" },
  {   1, "primitives-out-of-sequence" },
  {   2, "object-sate-conflict" },
  {   3, "pdu-size" },
  {   4, "continuation-invalid" },
  {   5, "object-constraint-conflict" },
  { 0, NULL }
};


static int
dissect_mms_T_service(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string mms_T_service_preempt_vals[] = {
  {   0, "other" },
  {   1, "timeout" },
  {   2, "deadlock" },
  {   3, "cancel" },
  { 0, NULL }
};


static int
dissect_mms_T_service_preempt(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string mms_T_time_resolution_vals[] = {
  {   0, "other" },
  {   1, "unsupportable-time-resolution" },
  { 0, NULL }
};


static int
dissect_mms_T_time_resolution(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string mms_T_access_vals[] = {
  {   0, "other" },
  {   1, "object-access-unsupported" },
  {   2, "object-non-existent" },
  {   3, "object-access-denied" },
  {   4, "object-invalidated" },
  { 0, NULL }
};


static int
dissect_mms_T_access(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string mms_T_initiate_vals[] = {
  {   0, "other" },
  {   1, "version-incompatible" },
  {   2, "max-segment-insufficient" },
  {   3, "max-services-outstanding-calling-insufficient" },
  {   4, "max-services-outstanding-called-insufficient" },
  {   5, "service-CBB-insufficient" },
  {   6, "parameter-CBB-insufficient" },
  {   7, "nesting-level-insufficient" },
  { 0, NULL }
};


static int
dissect_mms_T_initiate(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string mms_T_conclude_vals[] = {
  {   0, "other" },
  {   1, "further-communication-required" },
  { 0, NULL }
};


static int
dissect_mms_T_conclude(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string mms_T_cancel_vals[] = {
  {   0, "other" },
  {   1, "invoke-id-unknown" },
  {   2, "cancel-not-possible" },
  { 0, NULL }
};


static int
dissect_mms_T_cancel(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string mms_T_file_vals[] = {
  {   0, "other" },
  {   1, "filename-ambiguous" },
  {   2, "file-busy" },
  {   3, "filename-syntax-error" },
  {   4, "content-type-invalid" },
  {   5, "position-invalid" },
  {   6, "file-acces-denied" },
  {   7, "file-non-existent" },
  {   8, "duplicate-filename" },
  {   9, "insufficient-space-in-filestore" },
  { 0, NULL }
};


static int
dissect_mms_T_file(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string mms_T_errorClass_vals[] = {
  {   0, "vmd-state" },
  {   1, "application-reference" },
  {   2, "definition" },
  {   3, "resource" },
  {   4, "service" },
  {   5, "service-preempt" },
  {   6, "time-resolution" },
  {   7, "access" },
  {   8, "initiate" },
  {   9, "conclude" },
  {  10, "cancel" },
  {  11, "file" },
  {  12, "others" },
  { 0, NULL }
};

static const ber_choice_t T_errorClass_choice[] = {
  {   0, &hf_mms_vmd_state       , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_T_vmd_state },
  {   1, &hf_mms_application_reference, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_T_application_reference },
  {   2, &hf_mms_definition      , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_T_definition },
  {   3, &hf_mms_resource        , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_mms_T_resource },
  {   4, &hf_mms_service         , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_mms_T_service },
  {   5, &hf_mms_service_preempt , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_mms_T_service_preempt },
  {   6, &hf_mms_time_resolution , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_mms_T_time_resolution },
  {   7, &hf_mms_access          , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_mms_T_access },
  {   8, &hf_mms_initiate        , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_mms_T_initiate },
  {   9, &hf_mms_conclude        , BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_mms_T_conclude },
  {  10, &hf_mms_cancel          , BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_mms_T_cancel },
  {  11, &hf_mms_file            , BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_mms_T_file },
  {  12, &hf_mms_others          , BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_mms_INTEGER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_errorClass(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_errorClass_choice, hf_index, ett_mms_T_errorClass,
                                 NULL);

  return offset;
}


static const value_string mms_ObtainFile_Error_vals[] = {
  {   0, "source-file" },
  {   1, "destination-file" },
  { 0, NULL }
};


static int
dissect_mms_ObtainFile_Error(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string mms_ProgramInvocationState_vals[] = {
  {   0, "non-existent" },
  {   1, "unrunable" },
  {   2, "idle" },
  {   3, "running" },
  {   4, "stopped" },
  {   5, "starting" },
  {   6, "stopping" },
  {   7, "resuming" },
  {   8, "resetting" },
  { 0, NULL }
};


static int
dissect_mms_ProgramInvocationState(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_mms_Start_Error(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_ProgramInvocationState(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_mms_Stop_Error(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_ProgramInvocationState(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_mms_Resume_Error(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_ProgramInvocationState(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_mms_Reset_Error(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_ProgramInvocationState(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_mms_DeleteVariableAccess_Error(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Unsigned32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_mms_DeleteNamedVariableList_Error(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Unsigned32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_mms_DeleteNamedType_Error(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Unsigned32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_mms_DefineEventEnrollment_Error(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_ObjectName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string mms_FileRename_Error_vals[] = {
  {   0, "source-file" },
  {   1, "destination-file" },
  { 0, NULL }
};


static int
dissect_mms_FileRename_Error(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string mms_T_serviceSpecificInformation_vals[] = {
  {   0, "obtainFile" },
  {   1, "start" },
  {   2, "stop" },
  {   3, "resume" },
  {   4, "reset" },
  {   5, "deleteVariableAccess" },
  {   6, "deleteNamedVariableList" },
  {   7, "deleteNamedType" },
  {   8, "defineEventEnrollment-Error" },
  {   9, "fileRename" },
  { 0, NULL }
};

static const ber_choice_t T_serviceSpecificInformation_choice[] = {
  {   0, &hf_mms_obtainFile_02   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_ObtainFile_Error },
  {   1, &hf_mms_start_02        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_Start_Error },
  {   2, &hf_mms_stop_02         , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_Stop_Error },
  {   3, &hf_mms_resume_02       , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_mms_Resume_Error },
  {   4, &hf_mms_reset_02        , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_mms_Reset_Error },
  {   5, &hf_mms_deleteVariableAccess_02, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_mms_DeleteVariableAccess_Error },
  {   6, &hf_mms_deleteNamedVariableList_02, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_mms_DeleteNamedVariableList_Error },
  {   7, &hf_mms_deleteNamedType_02, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_mms_DeleteNamedType_Error },
  {   8, &hf_mms_defineEventEnrollment_Error, BER_CLASS_CON, 8, 0, dissect_mms_DefineEventEnrollment_Error },
  {   9, &hf_mms_fileRename_02   , BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_mms_FileRename_Error },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_serviceSpecificInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_serviceSpecificInformation_choice, hf_index, ett_mms_T_serviceSpecificInformation,
                                 NULL);

  return offset;
}


static const ber_sequence_t ServiceError_sequence[] = {
  { &hf_mms_errorClass      , BER_CLASS_CON, 0, 0, dissect_mms_T_errorClass },
  { &hf_mms_additionalCode  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_INTEGER },
  { &hf_mms_additionalDescription, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_VisibleString },
  { &hf_mms_serviceSpecificInformation, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_mms_T_serviceSpecificInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_ServiceError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ServiceError_sequence, hf_index, ett_mms_ServiceError);

  return offset;
}


static const ber_sequence_t TerminateDownloadSequence_Request_sequence[] = {
  { &hf_mms_domainName      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { &hf_mms_discard         , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_ServiceError },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_TerminateDownloadSequence_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TerminateDownloadSequence_Request_sequence, hf_index, ett_mms_TerminateDownloadSequence_Request);

  return offset;
}



static int
dissect_mms_InitiateUploadSequence_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Identifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_mms_UploadSegment_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Integer32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_mms_TerminateUploadSequence_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Integer32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t T_listOfCapabilities_03_sequence_of[1] = {
  { &hf_mms_listOfCapabilities_item, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_mms_VisibleString },
};

static int
dissect_mms_T_listOfCapabilities_03(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_listOfCapabilities_03_sequence_of, hf_index, ett_mms_T_listOfCapabilities_03);

  return offset;
}



static int
dissect_mms_GraphicString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GraphicString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t FileName_sequence_of[1] = {
  { &hf_mms_FileName_item   , BER_CLASS_UNI, BER_UNI_TAG_GraphicString, BER_FLAGS_NOOWNTAG, dissect_mms_GraphicString },
};

static int
dissect_mms_FileName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      FileName_sequence_of, hf_index, ett_mms_FileName);

  return offset;
}


static const ber_sequence_t RequestDomainDownload_Request_sequence[] = {
  { &hf_mms_domainName      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { &hf_mms_listOfCapabilities_03, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_T_listOfCapabilities_03 },
  { &hf_mms_sharable        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_fileName        , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_mms_FileName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_RequestDomainDownload_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RequestDomainDownload_Request_sequence, hf_index, ett_mms_RequestDomainDownload_Request);

  return offset;
}


static const ber_sequence_t RequestDomainUpload_Request_sequence[] = {
  { &hf_mms_domainName      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { &hf_mms_fileName        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_FileName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_RequestDomainUpload_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RequestDomainUpload_Request_sequence, hf_index, ett_mms_RequestDomainUpload_Request);

  return offset;
}


static const ber_sequence_t T_listOfCapabilities_04_sequence_of[1] = {
  { &hf_mms_listOfCapabilities_item, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_mms_VisibleString },
};

static int
dissect_mms_T_listOfCapabilities_04(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_listOfCapabilities_04_sequence_of, hf_index, ett_mms_T_listOfCapabilities_04);

  return offset;
}


static const ber_sequence_t LoadDomainContent_Request_sequence[] = {
  { &hf_mms_domainName      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { &hf_mms_listOfCapabilities_04, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_T_listOfCapabilities_04 },
  { &hf_mms_sharable        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_fileName        , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_mms_FileName },
  { &hf_mms_thirdParty      , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_ApplicationReference },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_LoadDomainContent_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   LoadDomainContent_Request_sequence, hf_index, ett_mms_LoadDomainContent_Request);

  return offset;
}


static const ber_sequence_t StoreDomainContent_Request_sequence[] = {
  { &hf_mms_domainName      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { &hf_mms_filenName       , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_FileName },
  { &hf_mms_thirdParty      , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_ApplicationReference },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_StoreDomainContent_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   StoreDomainContent_Request_sequence, hf_index, ett_mms_StoreDomainContent_Request);

  return offset;
}



static int
dissect_mms_DeleteDomain_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Identifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_mms_GetDomainAttributes_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Identifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Identifier_sequence_of[1] = {
  { &hf_mms_listOfIdentifier_item, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_mms_Identifier },
};

static int
dissect_mms_SEQUENCE_OF_Identifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Identifier_sequence_of, hf_index, ett_mms_SEQUENCE_OF_Identifier);

  return offset;
}


static const ber_sequence_t CreateProgramInvocation_Request_sequence[] = {
  { &hf_mms_programInvocationName, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { &hf_mms_listOfDomainName, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_SEQUENCE_OF_Identifier },
  { &hf_mms_reusable        , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_monitorType     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_CreateProgramInvocation_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CreateProgramInvocation_Request_sequence, hf_index, ett_mms_CreateProgramInvocation_Request);

  return offset;
}



static int
dissect_mms_DeleteProgramInvocation_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Identifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string mms_T_executionArgument_vals[] = {
  {   0, "simpleString" },
  {   1, "encodedString" },
  { 0, NULL }
};

static const ber_choice_t T_executionArgument_choice[] = {
  {   0, &hf_mms_simpleString    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_VisibleString },
  {   1, &hf_mms_encodedString   , BER_CLASS_UNI, 8, BER_FLAGS_NOOWNTAG, dissect_acse_EXTERNALt },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_executionArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_executionArgument_choice, hf_index, ett_mms_T_executionArgument,
                                 NULL);

  return offset;
}


static const ber_sequence_t Start_Request_sequence[] = {
  { &hf_mms_programInvocationName, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { &hf_mms_executionArgument, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_T_executionArgument },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_Start_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Start_Request_sequence, hf_index, ett_mms_Start_Request);

  return offset;
}


static const ber_sequence_t Stop_Request_sequence[] = {
  { &hf_mms_programInvocationName, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_Stop_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Stop_Request_sequence, hf_index, ett_mms_Stop_Request);

  return offset;
}


static const value_string mms_T_executionArgument_01_vals[] = {
  {   0, "simpleString" },
  {   1, "encodedString" },
  { 0, NULL }
};

static const ber_choice_t T_executionArgument_01_choice[] = {
  {   0, &hf_mms_simpleString    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_VisibleString },
  {   1, &hf_mms_encodedString   , BER_CLASS_UNI, 8, BER_FLAGS_NOOWNTAG, dissect_acse_EXTERNALt },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_executionArgument_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_executionArgument_01_choice, hf_index, ett_mms_T_executionArgument_01,
                                 NULL);

  return offset;
}


static const ber_sequence_t Resume_Request_sequence[] = {
  { &hf_mms_programInvocationName, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { &hf_mms_executionArgument_01, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_T_executionArgument_01 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_Resume_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Resume_Request_sequence, hf_index, ett_mms_Resume_Request);

  return offset;
}


static const ber_sequence_t Reset_Request_sequence[] = {
  { &hf_mms_programInvocationName, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_Reset_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Reset_Request_sequence, hf_index, ett_mms_Reset_Request);

  return offset;
}


static const ber_sequence_t Kill_Request_sequence[] = {
  { &hf_mms_programInvocationName, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_Kill_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Kill_Request_sequence, hf_index, ett_mms_Kill_Request);

  return offset;
}



static int
dissect_mms_GetProgramInvocationAttributes_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Identifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t ObtainFile_Request_sequence[] = {
  { &hf_mms_sourceFileServer, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_ApplicationReference },
  { &hf_mms_sourceFile      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_FileName },
  { &hf_mms_destinationFile , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_FileName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_ObtainFile_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ObtainFile_Request_sequence, hf_index, ett_mms_ObtainFile_Request);

  return offset;
}


static const value_string mms_EC_Class_vals[] = {
  {   0, "network-triggered" },
  {   1, "monitored" },
  { 0, NULL }
};


static int
dissect_mms_EC_Class(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t DefineEventCondition_Request_sequence[] = {
  { &hf_mms_eventConditionName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { &hf_mms_class_01        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_EC_Class },
  { &hf_mms_prio_rity       , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Priority },
  { &hf_mms_severity        , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Unsigned8 },
  { &hf_mms_alarmSummaryReports, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_monitoredVariable, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_mms_VariableSpecification },
  { &hf_mms_evaluationInterval, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_DefineEventCondition_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DefineEventCondition_Request_sequence, hf_index, ett_mms_DefineEventCondition_Request);

  return offset;
}


static const value_string mms_DeleteEventCondition_Request_vals[] = {
  {   0, "specific" },
  {   1, "aa-specific" },
  {   2, "domain" },
  {   3, "vmd" },
  { 0, NULL }
};

static const ber_choice_t DeleteEventCondition_Request_choice[] = {
  {   0, &hf_mms_specific        , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_SEQUENCE_OF_ObjectName },
  {   1, &hf_mms_aa_specific_01  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_NULL },
  {   2, &hf_mms_domain          , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  {   3, &hf_mms_vmd             , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_mms_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_DeleteEventCondition_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 DeleteEventCondition_Request_choice, hf_index, ett_mms_DeleteEventCondition_Request,
                                 NULL);

  return offset;
}



static int
dissect_mms_GetEventConditionAttributes_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_ObjectName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_mms_ReportEventConditionStatus_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_ObjectName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t AlterEventConditionMonitoring_Request_sequence[] = {
  { &hf_mms_eventConditionName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { &hf_mms_enabled         , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_priority        , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Priority },
  { &hf_mms_alarmSummaryReports, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_evaluationInterval, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_AlterEventConditionMonitoring_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AlterEventConditionMonitoring_Request_sequence, hf_index, ett_mms_AlterEventConditionMonitoring_Request);

  return offset;
}


static const ber_sequence_t TriggerEvent_Request_sequence[] = {
  { &hf_mms_eventConditionName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { &hf_mms_priority        , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Priority },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_TriggerEvent_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TriggerEvent_Request_sequence, hf_index, ett_mms_TriggerEvent_Request);

  return offset;
}


static const ber_sequence_t DefineEventAction_Request_sequence[] = {
  { &hf_mms_eventActionName , BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { &hf_mms_listOfModifier  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_SEQUENCE_OF_Modifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_DefineEventAction_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DefineEventAction_Request_sequence, hf_index, ett_mms_DefineEventAction_Request);

  return offset;
}


static const value_string mms_DeleteEventAction_Request_vals[] = {
  {   0, "specific" },
  {   1, "aa-specific" },
  {   3, "domain" },
  {   4, "vmd" },
  { 0, NULL }
};

static const ber_choice_t DeleteEventAction_Request_choice[] = {
  {   0, &hf_mms_specific        , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_SEQUENCE_OF_ObjectName },
  {   1, &hf_mms_aa_specific_01  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_NULL },
  {   3, &hf_mms_domain          , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  {   4, &hf_mms_vmd             , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_mms_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_DeleteEventAction_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 DeleteEventAction_Request_choice, hf_index, ett_mms_DeleteEventAction_Request,
                                 NULL);

  return offset;
}



static int
dissect_mms_GetEventActionAttributes_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_ObjectName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_mms_ReportEventActionStatus_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_ObjectName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string mms_AlarmAckRule_vals[] = {
  {   0, "none" },
  {   1, "simple" },
  {   2, "ack-active" },
  {   3, "ack-all" },
  { 0, NULL }
};


static int
dissect_mms_AlarmAckRule(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t DefineEventEnrollment_Request_sequence[] = {
  { &hf_mms_eventEnrollmentName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { &hf_mms_eventConditionName, BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { &hf_mms_eventConditionTransition, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_Transitions },
  { &hf_mms_alarmAcknowledgementRule, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_mms_AlarmAckRule },
  { &hf_mms_eventActionName , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { &hf_mms_clientApplication, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_mms_ApplicationReference },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_DefineEventEnrollment_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DefineEventEnrollment_Request_sequence, hf_index, ett_mms_DefineEventEnrollment_Request);

  return offset;
}


static const value_string mms_DeleteEventEnrollment_Request_vals[] = {
  {   0, "specific" },
  {   1, "ec" },
  {   2, "ea" },
  { 0, NULL }
};

static const ber_choice_t DeleteEventEnrollment_Request_choice[] = {
  {   0, &hf_mms_specific        , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_SEQUENCE_OF_ObjectName },
  {   1, &hf_mms_ec              , BER_CLASS_CON, 1, 0, dissect_mms_ObjectName },
  {   2, &hf_mms_ea              , BER_CLASS_CON, 2, 0, dissect_mms_ObjectName },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_DeleteEventEnrollment_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 DeleteEventEnrollment_Request_choice, hf_index, ett_mms_DeleteEventEnrollment_Request,
                                 NULL);

  return offset;
}


static const ber_sequence_t AlterEventEnrollment_Request_sequence[] = {
  { &hf_mms_eventEnrollmentName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { &hf_mms_eventConditionTransitions, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Transitions },
  { &hf_mms_alarmAcknowledgmentRule, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_AlarmAckRule },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_AlterEventEnrollment_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AlterEventEnrollment_Request_sequence, hf_index, ett_mms_AlterEventEnrollment_Request);

  return offset;
}



static int
dissect_mms_ReportEventEnrollmentStatus_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_ObjectName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string mms_T_scopeOfRequest_vals[] = {
  {   0, "specific" },
  {   1, "client" },
  {   2, "ec" },
  {   3, "ea" },
  { 0, NULL }
};


static int
dissect_mms_T_scopeOfRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t GetEventEnrollmentAttributes_Request_sequence[] = {
  { &hf_mms_scopeOfRequest  , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_T_scopeOfRequest },
  { &hf_mms_eventEnrollmentNames, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_SEQUENCE_OF_ObjectName },
  { &hf_mms_clientApplication, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_mms_ApplicationReference },
  { &hf_mms_eventConditionName, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { &hf_mms_eventActionName , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { &hf_mms_continueAfter_02, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_GetEventEnrollmentAttributes_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetEventEnrollmentAttributes_Request_sequence, hf_index, ett_mms_GetEventEnrollmentAttributes_Request);

  return offset;
}


static const value_string mms_EC_State_vals[] = {
  {   0, "disabled" },
  {   1, "idle" },
  {   2, "active" },
  { 0, NULL }
};


static int
dissect_mms_EC_State(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string mms_EventTime_vals[] = {
  {   0, "timeOfDayT" },
  {   1, "timeSequenceIdentifier" },
  { 0, NULL }
};

static const ber_choice_t EventTime_choice[] = {
  {   0, &hf_mms_timeOfDayT      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_TimeOfDay },
  {   1, &hf_mms_timeSequenceIdentifier, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_EventTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 EventTime_choice, hf_index, ett_mms_EventTime,
                                 NULL);

  return offset;
}


static const ber_sequence_t AcknowledgeEventNotification_Request_sequence[] = {
  { &hf_mms_eventEnrollmentName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { &hf_mms_acknowledgedState, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_EC_State },
  { &hf_mms_timeOfAcknowledgedTransition, BER_CLASS_CON, 3, BER_FLAGS_NOTCHKTAG, dissect_mms_EventTime },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_AcknowledgeEventNotification_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AcknowledgeEventNotification_Request_sequence, hf_index, ett_mms_AcknowledgeEventNotification_Request);

  return offset;
}


static const value_string mms_T_acknowledgmentFilter_vals[] = {
  {   0, "not-acked" },
  {   1, "acked" },
  {   2, "all" },
  { 0, NULL }
};


static int
dissect_mms_T_acknowledgmentFilter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t T_severityFilter_sequence[] = {
  { &hf_mms_mostSevere      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned8 },
  { &hf_mms_leastSevere     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned8 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_severityFilter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_severityFilter_sequence, hf_index, ett_mms_T_severityFilter);

  return offset;
}


static const ber_sequence_t GetAlarmSummary_Request_sequence[] = {
  { &hf_mms_enrollmentsOnly , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_activeAlarmsOnly, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_acknowledgmentFilter, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_T_acknowledgmentFilter },
  { &hf_mms_severityFilter  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_T_severityFilter },
  { &hf_mms_continueAfter_02, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_GetAlarmSummary_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetAlarmSummary_Request_sequence, hf_index, ett_mms_GetAlarmSummary_Request);

  return offset;
}


static const value_string mms_T_acknowledgmentFilter_01_vals[] = {
  {   0, "not-acked" },
  {   1, "acked" },
  {   2, "all" },
  { 0, NULL }
};


static int
dissect_mms_T_acknowledgmentFilter_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t T_severityFilter_01_sequence[] = {
  { &hf_mms_mostSevere      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned8 },
  { &hf_mms_leastSevere     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned8 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_severityFilter_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_severityFilter_01_sequence, hf_index, ett_mms_T_severityFilter_01);

  return offset;
}


static const ber_sequence_t GetAlarmEnrollmentSummary_Request_sequence[] = {
  { &hf_mms_enrollmentsOnly , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_activeAlarmsOnly, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_acknowledgmentFilter_01, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_T_acknowledgmentFilter_01 },
  { &hf_mms_severityFilter_01, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_T_severityFilter_01 },
  { &hf_mms_continueAfter_02, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_GetAlarmEnrollmentSummary_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetAlarmEnrollmentSummary_Request_sequence, hf_index, ett_mms_GetAlarmEnrollmentSummary_Request);

  return offset;
}


static const value_string mms_T_rangeStartSpecification_vals[] = {
  {   0, "startingTime" },
  {   1, "startingEntry" },
  { 0, NULL }
};

static const ber_choice_t T_rangeStartSpecification_choice[] = {
  {   0, &hf_mms_startingTime    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_TimeOfDay },
  {   1, &hf_mms_startingEntry   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_OCTET_STRING },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_rangeStartSpecification(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_rangeStartSpecification_choice, hf_index, ett_mms_T_rangeStartSpecification,
                                 NULL);

  return offset;
}


static const value_string mms_T_rangeStopSpecification_vals[] = {
  {   0, "endingTime" },
  {   1, "numberOfEntries" },
  { 0, NULL }
};

static const ber_choice_t T_rangeStopSpecification_choice[] = {
  {   0, &hf_mms_endingTime      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_TimeOfDay },
  {   1, &hf_mms_numberOfEntries , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_Integer32 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_rangeStopSpecification(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_rangeStopSpecification_choice, hf_index, ett_mms_T_rangeStopSpecification,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_listOfVariables_sequence_of[1] = {
  { &hf_mms_listOfVariables_item, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_mms_VisibleString },
};

static int
dissect_mms_T_listOfVariables(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_listOfVariables_sequence_of, hf_index, ett_mms_T_listOfVariables);

  return offset;
}


static const ber_sequence_t T_entryToStartAfter_sequence[] = {
  { &hf_mms_timeSpecification, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_TimeOfDay },
  { &hf_mms_entrySpecification, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_entryToStartAfter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_entryToStartAfter_sequence, hf_index, ett_mms_T_entryToStartAfter);

  return offset;
}


static const ber_sequence_t ReadJournal_Request_sequence[] = {
  { &hf_mms_journalName     , BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { &hf_mms_rangeStartSpecification, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_mms_T_rangeStartSpecification },
  { &hf_mms_rangeStopSpecification, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_mms_T_rangeStopSpecification },
  { &hf_mms_listOfVariables , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_T_listOfVariables },
  { &hf_mms_entryToStartAfter, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_mms_T_entryToStartAfter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_ReadJournal_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReadJournal_Request_sequence, hf_index, ett_mms_ReadJournal_Request);

  return offset;
}



static int
dissect_mms_JOU_Additional_Detail(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t T_event_sequence[] = {
  { &hf_mms_eventConditionName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { &hf_mms_currentState    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_EC_State },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_event(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_event_sequence, hf_index, ett_mms_T_event);

  return offset;
}


static const ber_sequence_t T_listOfVariables_item_sequence[] = {
  { &hf_mms_variableTag     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_VisibleString },
  { &hf_mms_valueSpecification, BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_mms_Data },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_listOfVariables_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_listOfVariables_item_sequence, hf_index, ett_mms_T_listOfVariables_item);

  return offset;
}


static const ber_sequence_t T_listOfVariables_01_sequence_of[1] = {
  { &hf_mms_listOfVariables_item_01, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_mms_T_listOfVariables_item },
};

static int
dissect_mms_T_listOfVariables_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_listOfVariables_01_sequence_of, hf_index, ett_mms_T_listOfVariables_01);

  return offset;
}


static const ber_sequence_t T_data_sequence[] = {
  { &hf_mms_event           , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_T_event },
  { &hf_mms_listOfVariables_01, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_T_listOfVariables_01 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_data(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_data_sequence, hf_index, ett_mms_T_data);

  return offset;
}


static const value_string mms_T_entryForm_vals[] = {
  {   2, "data" },
  {   3, "annotation" },
  { 0, NULL }
};

static const ber_choice_t T_entryForm_choice[] = {
  {   2, &hf_mms_data            , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_T_data },
  {   3, &hf_mms_annotation      , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_mms_VisibleString },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_entryForm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_entryForm_choice, hf_index, ett_mms_T_entryForm,
                                 NULL);

  return offset;
}


static const ber_sequence_t EntryContent_sequence[] = {
  { &hf_mms_occurenceTime   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_TimeOfDay },
  { &hf_mms_additionalDetail, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_mms_JOU_Additional_Detail },
  { &hf_mms_entryForm       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_T_entryForm },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_EntryContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EntryContent_sequence, hf_index, ett_mms_EntryContent);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_EntryContent_sequence_of[1] = {
  { &hf_mms_listOfJournalEntry_item_01, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_mms_EntryContent },
};

static int
dissect_mms_SEQUENCE_OF_EntryContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_EntryContent_sequence_of, hf_index, ett_mms_SEQUENCE_OF_EntryContent);

  return offset;
}


static const ber_sequence_t WriteJournal_Request_sequence[] = {
  { &hf_mms_journalName     , BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { &hf_mms_listOfJournalEntry_01, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_SEQUENCE_OF_EntryContent },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_WriteJournal_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   WriteJournal_Request_sequence, hf_index, ett_mms_WriteJournal_Request);

  return offset;
}


static const ber_sequence_t T_limitSpecification_sequence[] = {
  { &hf_mms_limitingTime    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_TimeOfDay },
  { &hf_mms_limitingEntry   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_limitSpecification(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_limitSpecification_sequence, hf_index, ett_mms_T_limitSpecification);

  return offset;
}


static const ber_sequence_t InitializeJournal_Request_sequence[] = {
  { &hf_mms_journalName     , BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { &hf_mms_limitSpecification, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_T_limitSpecification },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_InitializeJournal_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InitializeJournal_Request_sequence, hf_index, ett_mms_InitializeJournal_Request);

  return offset;
}



static int
dissect_mms_ReportJournalStatus_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_ObjectName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t CreateJournal_Request_sequence[] = {
  { &hf_mms_journalName     , BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_CreateJournal_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CreateJournal_Request_sequence, hf_index, ett_mms_CreateJournal_Request);

  return offset;
}


static const ber_sequence_t DeleteJournal_Request_sequence[] = {
  { &hf_mms_journalName     , BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_DeleteJournal_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DeleteJournal_Request_sequence, hf_index, ett_mms_DeleteJournal_Request);

  return offset;
}


static const ber_sequence_t GetCapabilityList_Request_sequence[] = {
  { &hf_mms_continueAfter_01, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_mms_VisibleString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_GetCapabilityList_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetCapabilityList_Request_sequence, hf_index, ett_mms_GetCapabilityList_Request);

  return offset;
}


static const ber_sequence_t FileOpen_Request_sequence[] = {
  { &hf_mms_fileName        , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_FileName },
  { &hf_mms_initialPosition , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_FileOpen_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   FileOpen_Request_sequence, hf_index, ett_mms_FileOpen_Request);

  return offset;
}



static int
dissect_mms_FileRead_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Integer32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_mms_FileClose_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Integer32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t FileRename_Request_sequence[] = {
  { &hf_mms_currentFileName , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_FileName },
  { &hf_mms_newFileName     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_FileName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_FileRename_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   FileRename_Request_sequence, hf_index, ett_mms_FileRename_Request);

  return offset;
}



static int
dissect_mms_FileDelete_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_FileName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t FileDirectory_Request_sequence[] = {
  { &hf_mms_fileSpecification, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_FileName },
  { &hf_mms_continueAfter_03, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_FileName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_FileDirectory_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   FileDirectory_Request_sequence, hf_index, ett_mms_FileDirectory_Request);

  return offset;
}


static const value_string mms_ConfirmedServiceRequest_vals[] = {
  {   0, "status" },
  {   1, "getNameList" },
  {   2, "identify" },
  {   3, "rename" },
  {   4, "read" },
  {   5, "write" },
  {   6, "getVariableAccessAttributes" },
  {   7, "defineNamedVariable" },
  {   8, "defineScatteredAccess" },
  {   9, "getScatteredAccessAttributes" },
  {  10, "deleteVariableAccess" },
  {  11, "defineNamedVariableList" },
  {  12, "getNamedVariableListAttributes" },
  {  13, "deleteNamedVariableList" },
  {  14, "defineNamedType" },
  {  15, "getNamedTypeAttributes" },
  {  16, "deleteNamedType" },
  {  17, "input" },
  {  18, "output" },
  {  19, "takeControl" },
  {  20, "relinquishControl" },
  {  21, "defineSemaphore" },
  {  22, "deleteSemaphore" },
  {  23, "reportSemaphoreStatus" },
  {  24, "reportPoolSemaphoreStatus" },
  {  25, "reportSemaphoreEntryStatus" },
  {  26, "initiateDownloadSequence" },
  {  27, "downloadSegment" },
  {  28, "terminateDownloadSequence" },
  {  29, "initiateUploadSequence" },
  {  30, "uploadSegment" },
  {  31, "terminateUploadSequence" },
  {  32, "requestDomainDownload" },
  {  33, "requestDomainUpload" },
  {  34, "loadDomainContent" },
  {  35, "storeDomainContent" },
  {  36, "deleteDomain" },
  {  37, "getDomainAttributes" },
  {  38, "createProgramInvocation" },
  {  39, "deleteProgramInvocation" },
  {  40, "start" },
  {  41, "stop" },
  {  42, "resume" },
  {  43, "reset" },
  {  44, "kill" },
  {  45, "getProgramInvocationAttributes" },
  {  46, "obtainFile" },
  {  47, "defineEventCondition" },
  {  48, "deleteEventCondition" },
  {  49, "getEventConditionAttributes" },
  {  50, "reportEventConditionStatus" },
  {  51, "alterEventConditionMonitoring" },
  {  52, "triggerEvent" },
  {  53, "defineEventAction" },
  {  54, "deleteEventAction" },
  {  55, "getEventActionAttributes" },
  {  56, "reportEventActionStatus" },
  {  57, "defineEventEnrollment" },
  {  58, "deleteEventEnrollment" },
  {  59, "alterEventEnrollment" },
  {  60, "reportEventEnrollmentStatus" },
  {  61, "getEventEnrollmentAttributes" },
  {  62, "acknowledgeEventNotification" },
  {  63, "getAlarmSummary" },
  {  64, "getAlarmEnrollmentSummary" },
  {  65, "readJournal" },
  {  66, "writeJournal" },
  {  67, "initializeJournal" },
  {  68, "reportJournalStatus" },
  {  69, "createJournal" },
  {  70, "deleteJournal" },
  {  71, "getCapabilityList" },
  {  72, "fileOpen" },
  {  73, "fileRead" },
  {  74, "fileClose" },
  {  75, "fileRename" },
  {  76, "fileDelete" },
  {  77, "fileDirectory" },
  { 0, NULL }
};

static const ber_choice_t ConfirmedServiceRequest_choice[] = {
  {   0, &hf_mms_status          , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Status_Request },
  {   1, &hf_mms_getNameList     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_GetNameList_Request },
  {   2, &hf_mms_identify        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_Identify_Request },
  {   3, &hf_mms_rename          , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_mms_Rename_Request },
  {   4, &hf_mms_read            , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_mms_Read_Request },
  {   5, &hf_mms_write           , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_mms_Write_Request },
  {   6, &hf_mms_getVariableAccessAttributes, BER_CLASS_CON, 6, 0, dissect_mms_GetVariableAccessAttributes_Request },
  {   7, &hf_mms_defineNamedVariable, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_mms_DefineNamedVariable_Request },
  {   8, &hf_mms_defineScatteredAccess, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_mms_DefineScatteredAccess_Request },
  {   9, &hf_mms_getScatteredAccessAttributes, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_mms_GetScatteredAccessAttributes_Request },
  {  10, &hf_mms_deleteVariableAccess, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_mms_DeleteVariableAccess_Request },
  {  11, &hf_mms_defineNamedVariableList, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_mms_DefineNamedVariableList_Request },
  {  12, &hf_mms_getNamedVariableListAttributes, BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_mms_GetNamedVariableListAttributes_Request },
  {  13, &hf_mms_deleteNamedVariableList, BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_mms_DeleteNamedVariableList_Request },
  {  14, &hf_mms_defineNamedType , BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_mms_DefineNamedType_Request },
  {  15, &hf_mms_getNamedTypeAttributes, BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_mms_GetNamedTypeAttributes_Request },
  {  16, &hf_mms_deleteNamedType , BER_CLASS_CON, 16, BER_FLAGS_IMPLTAG, dissect_mms_DeleteNamedType_Request },
  {  17, &hf_mms_input           , BER_CLASS_CON, 17, BER_FLAGS_IMPLTAG, dissect_mms_Input_Request },
  {  18, &hf_mms_output          , BER_CLASS_CON, 18, BER_FLAGS_IMPLTAG, dissect_mms_Output_Request },
  {  19, &hf_mms_takeControl     , BER_CLASS_CON, 19, BER_FLAGS_IMPLTAG, dissect_mms_TakeControl_Request },
  {  20, &hf_mms_relinquishControl, BER_CLASS_CON, 20, BER_FLAGS_IMPLTAG, dissect_mms_RelinquishControl_Request },
  {  21, &hf_mms_defineSemaphore , BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_mms_DefineSemaphore_Request },
  {  22, &hf_mms_deleteSemaphore , BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_mms_DeleteSemaphore_Request },
  {  23, &hf_mms_reportSemaphoreStatus, BER_CLASS_CON, 23, BER_FLAGS_IMPLTAG, dissect_mms_ReportSemaphoreStatus_Request },
  {  24, &hf_mms_reportPoolSemaphoreStatus, BER_CLASS_CON, 24, BER_FLAGS_IMPLTAG, dissect_mms_ReportPoolSemaphoreStatus_Request },
  {  25, &hf_mms_reportSemaphoreEntryStatus, BER_CLASS_CON, 25, BER_FLAGS_IMPLTAG, dissect_mms_ReportSemaphoreEntryStatus_Request },
  {  26, &hf_mms_initiateDownloadSequence, BER_CLASS_CON, 26, BER_FLAGS_IMPLTAG, dissect_mms_InitiateDownloadSequence_Request },
  {  27, &hf_mms_downloadSegment , BER_CLASS_CON, 27, BER_FLAGS_IMPLTAG, dissect_mms_DownloadSegment_Request },
  {  28, &hf_mms_terminateDownloadSequence, BER_CLASS_CON, 28, BER_FLAGS_IMPLTAG, dissect_mms_TerminateDownloadSequence_Request },
  {  29, &hf_mms_initiateUploadSequence, BER_CLASS_CON, 29, BER_FLAGS_IMPLTAG, dissect_mms_InitiateUploadSequence_Request },
  {  30, &hf_mms_uploadSegment   , BER_CLASS_CON, 30, BER_FLAGS_IMPLTAG, dissect_mms_UploadSegment_Request },
  {  31, &hf_mms_terminateUploadSequence, BER_CLASS_CON, 31, BER_FLAGS_IMPLTAG, dissect_mms_TerminateUploadSequence_Request },
  {  32, &hf_mms_requestDomainDownload, BER_CLASS_CON, 32, BER_FLAGS_IMPLTAG, dissect_mms_RequestDomainDownload_Request },
  {  33, &hf_mms_requestDomainUpload, BER_CLASS_CON, 33, BER_FLAGS_IMPLTAG, dissect_mms_RequestDomainUpload_Request },
  {  34, &hf_mms_loadDomainContent, BER_CLASS_CON, 34, BER_FLAGS_IMPLTAG, dissect_mms_LoadDomainContent_Request },
  {  35, &hf_mms_storeDomainContent, BER_CLASS_CON, 35, BER_FLAGS_IMPLTAG, dissect_mms_StoreDomainContent_Request },
  {  36, &hf_mms_deleteDomain    , BER_CLASS_CON, 36, BER_FLAGS_IMPLTAG, dissect_mms_DeleteDomain_Request },
  {  37, &hf_mms_getDomainAttributes, BER_CLASS_CON, 37, BER_FLAGS_IMPLTAG, dissect_mms_GetDomainAttributes_Request },
  {  38, &hf_mms_createProgramInvocation, BER_CLASS_CON, 38, BER_FLAGS_IMPLTAG, dissect_mms_CreateProgramInvocation_Request },
  {  39, &hf_mms_deleteProgramInvocation, BER_CLASS_CON, 39, BER_FLAGS_IMPLTAG, dissect_mms_DeleteProgramInvocation_Request },
  {  40, &hf_mms_start           , BER_CLASS_CON, 40, BER_FLAGS_IMPLTAG, dissect_mms_Start_Request },
  {  41, &hf_mms_stop            , BER_CLASS_CON, 41, BER_FLAGS_IMPLTAG, dissect_mms_Stop_Request },
  {  42, &hf_mms_resume          , BER_CLASS_CON, 42, BER_FLAGS_IMPLTAG, dissect_mms_Resume_Request },
  {  43, &hf_mms_reset           , BER_CLASS_CON, 43, BER_FLAGS_IMPLTAG, dissect_mms_Reset_Request },
  {  44, &hf_mms_kill            , BER_CLASS_CON, 44, BER_FLAGS_IMPLTAG, dissect_mms_Kill_Request },
  {  45, &hf_mms_getProgramInvocationAttributes, BER_CLASS_CON, 45, BER_FLAGS_IMPLTAG, dissect_mms_GetProgramInvocationAttributes_Request },
  {  46, &hf_mms_obtainFile      , BER_CLASS_CON, 46, BER_FLAGS_IMPLTAG, dissect_mms_ObtainFile_Request },
  {  47, &hf_mms_defineEventCondition, BER_CLASS_CON, 47, BER_FLAGS_IMPLTAG, dissect_mms_DefineEventCondition_Request },
  {  48, &hf_mms_deleteEventCondition, BER_CLASS_CON, 48, 0, dissect_mms_DeleteEventCondition_Request },
  {  49, &hf_mms_getEventConditionAttributes, BER_CLASS_CON, 49, 0, dissect_mms_GetEventConditionAttributes_Request },
  {  50, &hf_mms_reportEventConditionStatus, BER_CLASS_CON, 50, 0, dissect_mms_ReportEventConditionStatus_Request },
  {  51, &hf_mms_alterEventConditionMonitoring, BER_CLASS_CON, 51, BER_FLAGS_IMPLTAG, dissect_mms_AlterEventConditionMonitoring_Request },
  {  52, &hf_mms_triggerEvent    , BER_CLASS_CON, 52, BER_FLAGS_IMPLTAG, dissect_mms_TriggerEvent_Request },
  {  53, &hf_mms_defineEventAction, BER_CLASS_CON, 53, BER_FLAGS_IMPLTAG, dissect_mms_DefineEventAction_Request },
  {  54, &hf_mms_deleteEventAction, BER_CLASS_CON, 54, 0, dissect_mms_DeleteEventAction_Request },
  {  55, &hf_mms_getEventActionAttributes, BER_CLASS_CON, 55, 0, dissect_mms_GetEventActionAttributes_Request },
  {  56, &hf_mms_reportEventActionStatus, BER_CLASS_CON, 56, 0, dissect_mms_ReportEventActionStatus_Request },
  {  57, &hf_mms_defineEventEnrollment, BER_CLASS_CON, 57, BER_FLAGS_IMPLTAG, dissect_mms_DefineEventEnrollment_Request },
  {  58, &hf_mms_deleteEventEnrollment, BER_CLASS_CON, 58, 0, dissect_mms_DeleteEventEnrollment_Request },
  {  59, &hf_mms_alterEventEnrollment, BER_CLASS_CON, 59, BER_FLAGS_IMPLTAG, dissect_mms_AlterEventEnrollment_Request },
  {  60, &hf_mms_reportEventEnrollmentStatus, BER_CLASS_CON, 60, 0, dissect_mms_ReportEventEnrollmentStatus_Request },
  {  61, &hf_mms_getEventEnrollmentAttributes, BER_CLASS_CON, 61, BER_FLAGS_IMPLTAG, dissect_mms_GetEventEnrollmentAttributes_Request },
  {  62, &hf_mms_acknowledgeEventNotification, BER_CLASS_CON, 62, BER_FLAGS_IMPLTAG, dissect_mms_AcknowledgeEventNotification_Request },
  {  63, &hf_mms_getAlarmSummary , BER_CLASS_CON, 63, BER_FLAGS_IMPLTAG, dissect_mms_GetAlarmSummary_Request },
  {  64, &hf_mms_getAlarmEnrollmentSummary, BER_CLASS_CON, 64, BER_FLAGS_IMPLTAG, dissect_mms_GetAlarmEnrollmentSummary_Request },
  {  65, &hf_mms_readJournal     , BER_CLASS_CON, 65, BER_FLAGS_IMPLTAG, dissect_mms_ReadJournal_Request },
  {  66, &hf_mms_writeJournal    , BER_CLASS_CON, 66, BER_FLAGS_IMPLTAG, dissect_mms_WriteJournal_Request },
  {  67, &hf_mms_initializeJournal, BER_CLASS_CON, 67, BER_FLAGS_IMPLTAG, dissect_mms_InitializeJournal_Request },
  {  68, &hf_mms_reportJournalStatus, BER_CLASS_CON, 68, BER_FLAGS_IMPLTAG, dissect_mms_ReportJournalStatus_Request },
  {  69, &hf_mms_createJournal   , BER_CLASS_CON, 69, BER_FLAGS_IMPLTAG, dissect_mms_CreateJournal_Request },
  {  70, &hf_mms_deleteJournal   , BER_CLASS_CON, 70, BER_FLAGS_IMPLTAG, dissect_mms_DeleteJournal_Request },
  {  71, &hf_mms_getCapabilityList, BER_CLASS_CON, 71, BER_FLAGS_IMPLTAG, dissect_mms_GetCapabilityList_Request },
  {  72, &hf_mms_fileOpen        , BER_CLASS_CON, 72, BER_FLAGS_IMPLTAG, dissect_mms_FileOpen_Request },
  {  73, &hf_mms_fileRead        , BER_CLASS_CON, 73, BER_FLAGS_IMPLTAG, dissect_mms_FileRead_Request },
  {  74, &hf_mms_fileClose       , BER_CLASS_CON, 74, BER_FLAGS_IMPLTAG, dissect_mms_FileClose_Request },
  {  75, &hf_mms_fileRename      , BER_CLASS_CON, 75, BER_FLAGS_IMPLTAG, dissect_mms_FileRename_Request },
  {  76, &hf_mms_fileDelete      , BER_CLASS_CON, 76, BER_FLAGS_IMPLTAG, dissect_mms_FileDelete_Request },
  {  77, &hf_mms_fileDirectory   , BER_CLASS_CON, 77, BER_FLAGS_IMPLTAG, dissect_mms_FileDirectory_Request },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_ConfirmedServiceRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ConfirmedServiceRequest_choice, hf_index, ett_mms_ConfirmedServiceRequest,
                                 NULL);

  return offset;
}


static const value_string mms_CS_Request_Detail_vals[] = {
  {   0, "foo" },
  { 0, NULL }
};

static const ber_choice_t CS_Request_Detail_choice[] = {
  {   0, &hf_mms_foo             , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_mms_INTEGER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_CS_Request_Detail(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CS_Request_Detail_choice, hf_index, ett_mms_CS_Request_Detail,
                                 NULL);

  return offset;
}


static const ber_sequence_t Confirmed_RequestPDU_sequence[] = {
  { &hf_mms_invokeID        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_mms_Unsigned32 },
  { &hf_mms_listOfModifier  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_mms_SEQUENCE_OF_Modifier },
  { &hf_mms_confirmedServiceRequest, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_ConfirmedServiceRequest },
  { &hf_mms_cs_request_detail, BER_CLASS_CON, 79, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_mms_CS_Request_Detail },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_Confirmed_RequestPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Confirmed_RequestPDU_sequence, hf_index, ett_mms_Confirmed_RequestPDU);

  return offset;
}


static const value_string mms_T_vmdLogicalStatus_vals[] = {
  {   0, "state-changes-allowed" },
  {   1, "no-state-changes-allowed" },
  {   2, "limited-services-allowed" },
  {   3, "support-services-allowed" },
  { 0, NULL }
};


static int
dissect_mms_T_vmdLogicalStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string mms_T_vmdPhysicalStatus_vals[] = {
  {   0, "operational" },
  {   1, "partially-operational" },
  {   2, "inoperable" },
  {   3, "needs-commissioning" },
  { 0, NULL }
};


static int
dissect_mms_T_vmdPhysicalStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_mms_BIT_STRING_SIZE_0_128(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}


static const ber_sequence_t Status_Response_sequence[] = {
  { &hf_mms_vmdLogicalStatus, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_T_vmdLogicalStatus },
  { &hf_mms_vmdPhysicalStatus, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_T_vmdPhysicalStatus },
  { &hf_mms_localDetail     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BIT_STRING_SIZE_0_128 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_Status_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Status_Response_sequence, hf_index, ett_mms_Status_Response);

  return offset;
}


static const ber_sequence_t GetNameList_Response_sequence[] = {
  { &hf_mms_listOfIdentifier, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_SEQUENCE_OF_Identifier },
  { &hf_mms_moreFollows     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_GetNameList_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetNameList_Response_sequence, hf_index, ett_mms_GetNameList_Response);

  return offset;
}


static const ber_sequence_t T_listOfAbstractSyntaxes_sequence_of[1] = {
  { &hf_mms_listOfAbstractSyntaxes_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_mms_OBJECT_IDENTIFIER },
};

static int
dissect_mms_T_listOfAbstractSyntaxes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_listOfAbstractSyntaxes_sequence_of, hf_index, ett_mms_T_listOfAbstractSyntaxes);

  return offset;
}


static const ber_sequence_t Identify_Response_sequence[] = {
  { &hf_mms_vendorName      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_VisibleString },
  { &hf_mms_modelName       , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_VisibleString },
  { &hf_mms_revision        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_VisibleString },
  { &hf_mms_listOfAbstractSyntaxes, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_T_listOfAbstractSyntaxes },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_Identify_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Identify_Response_sequence, hf_index, ett_mms_Identify_Response);

  return offset;
}



static int
dissect_mms_Rename_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string mms_DataAccessError_vals[] = {
  {   0, "object-invalidated" },
  {   1, "hardware-fault" },
  {   2, "temporarily-unavailable" },
  {   3, "object-access-denied" },
  {   4, "object-undefined" },
  {   5, "invalid-address" },
  {   6, "type-unsupported" },
  {   7, "type-inconsistent" },
  {   8, "object-attribute-inconsistent" },
  {   9, "object-access-unsupported" },
  {  10, "object-non-existent" },
  { 0, NULL }
};


static int
dissect_mms_DataAccessError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string mms_AccessResult_vals[] = {
  {   0, "failure" },
  {   1, "success" },
  { 0, NULL }
};

static const ber_choice_t AccessResult_choice[] = {
  {   0, &hf_mms_failure         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_DataAccessError },
  {   1, &hf_mms_success_01      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_mms_Data },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_AccessResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AccessResult_choice, hf_index, ett_mms_AccessResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_AccessResult_sequence_of[1] = {
  { &hf_mms_listOfAccessResult_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_AccessResult },
};

static int
dissect_mms_SEQUENCE_OF_AccessResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_AccessResult_sequence_of, hf_index, ett_mms_SEQUENCE_OF_AccessResult);

  return offset;
}


static const ber_sequence_t Read_Response_sequence[] = {
  { &hf_mms_variableAccessSpecificatn, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_mms_VariableAccessSpecification },
  { &hf_mms_listOfAccessResult, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_SEQUENCE_OF_AccessResult },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_Read_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Read_Response_sequence, hf_index, ett_mms_Read_Response);

  return offset;
}


static const value_string mms_Write_Response_item_vals[] = {
  {   0, "failure" },
  {   1, "success" },
  { 0, NULL }
};

static const ber_choice_t Write_Response_item_choice[] = {
  {   0, &hf_mms_failure         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_DataAccessError },
  {   1, &hf_mms_success         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_Write_Response_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Write_Response_item_choice, hf_index, ett_mms_Write_Response_item,
                                 NULL);

  return offset;
}


static const ber_sequence_t Write_Response_sequence_of[1] = {
  { &hf_mms_Write_Response_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_Write_Response_item },
};

static int
dissect_mms_Write_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Write_Response_sequence_of, hf_index, ett_mms_Write_Response);

  return offset;
}


static const ber_sequence_t GetVariableAccessAttributes_Response_sequence[] = {
  { &hf_mms_mmsDeletable    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_address         , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_mms_Address },
  { &hf_mms_typeSpecification, BER_CLASS_CON, 2, BER_FLAGS_NOTCHKTAG, dissect_mms_TypeSpecification },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_GetVariableAccessAttributes_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetVariableAccessAttributes_Response_sequence, hf_index, ett_mms_GetVariableAccessAttributes_Response);

  return offset;
}



static int
dissect_mms_DefineNamedVariable_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_DefineScatteredAccess_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t GetScatteredAccessAttributes_Response_sequence[] = {
  { &hf_mms_mmsDeletable    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_scatteredAccessDescription, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_ScatteredAccessDescription },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_GetScatteredAccessAttributes_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetScatteredAccessAttributes_Response_sequence, hf_index, ett_mms_GetScatteredAccessAttributes_Response);

  return offset;
}


static const ber_sequence_t DeleteVariableAccess_Response_sequence[] = {
  { &hf_mms_numberMatched   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  { &hf_mms_numberDeleted   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_DeleteVariableAccess_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DeleteVariableAccess_Response_sequence, hf_index, ett_mms_DeleteVariableAccess_Response);

  return offset;
}



static int
dissect_mms_DefineNamedVariableList_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t T_listOfVariable_item_01_sequence[] = {
  { &hf_mms_variableSpecification, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_VariableSpecification },
  { &hf_mms_alternateAccess , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_AlternateAccess },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_listOfVariable_item_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_listOfVariable_item_01_sequence, hf_index, ett_mms_T_listOfVariable_item_01);

  return offset;
}


static const ber_sequence_t T_listOfVariable_01_sequence_of[1] = {
  { &hf_mms_listOfVariable_item_01, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_mms_T_listOfVariable_item_01 },
};

static int
dissect_mms_T_listOfVariable_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_listOfVariable_01_sequence_of, hf_index, ett_mms_T_listOfVariable_01);

  return offset;
}


static const ber_sequence_t GetNamedVariableListAttributes_Response_sequence[] = {
  { &hf_mms_mmsDeletable    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_listOfVariable_01, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_T_listOfVariable_01 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_GetNamedVariableListAttributes_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetNamedVariableListAttributes_Response_sequence, hf_index, ett_mms_GetNamedVariableListAttributes_Response);

  return offset;
}


static const ber_sequence_t DeleteNamedVariableList_Response_sequence[] = {
  { &hf_mms_numberMatched   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  { &hf_mms_numberDeleted   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_DeleteNamedVariableList_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DeleteNamedVariableList_Response_sequence, hf_index, ett_mms_DeleteNamedVariableList_Response);

  return offset;
}



static int
dissect_mms_DefineNamedType_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t GetNamedTypeAttributes_Response_sequence[] = {
  { &hf_mms_mmsDeletable    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_typeSpecification, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_TypeSpecification },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_GetNamedTypeAttributes_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetNamedTypeAttributes_Response_sequence, hf_index, ett_mms_GetNamedTypeAttributes_Response);

  return offset;
}


static const ber_sequence_t DeleteNamedType_Response_sequence[] = {
  { &hf_mms_numberMatched   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  { &hf_mms_numberDeleted   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_DeleteNamedType_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DeleteNamedType_Response_sequence, hf_index, ett_mms_DeleteNamedType_Response);

  return offset;
}



static int
dissect_mms_Input_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_VisibleString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_mms_Output_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string mms_TakeControl_Response_vals[] = {
  {   0, "noResult" },
  {   1, "namedToken" },
  { 0, NULL }
};

static const ber_choice_t TakeControl_Response_choice[] = {
  {   0, &hf_mms_noResult        , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_NULL },
  {   1, &hf_mms_namedToken      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_TakeControl_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 TakeControl_Response_choice, hf_index, ett_mms_TakeControl_Response,
                                 NULL);

  return offset;
}



static int
dissect_mms_RelinquishControl_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_DefineSemaphore_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_DeleteSemaphore_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string mms_T_class_vals[] = {
  {   0, "token" },
  {   1, "pool" },
  { 0, NULL }
};


static int
dissect_mms_T_class(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t ReportSemaphoreStatus_Response_sequence[] = {
  { &hf_mms_mmsDeletable    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_class           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_T_class },
  { &hf_mms_numberOfTokens  , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned16 },
  { &hf_mms_numberOfOwnedTokens, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned16 },
  { &hf_mms_numberOfHungTokens, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned16 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_ReportSemaphoreStatus_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReportSemaphoreStatus_Response_sequence, hf_index, ett_mms_ReportSemaphoreStatus_Response);

  return offset;
}


static const value_string mms_T_listOfNamedTokens_item_vals[] = {
  {   0, "freeNamedToken" },
  {   1, "ownedNamedToken" },
  {   2, "hungNamedToken" },
  { 0, NULL }
};

static const ber_choice_t T_listOfNamedTokens_item_choice[] = {
  {   0, &hf_mms_freeNamedToken  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  {   1, &hf_mms_ownedNamedToken , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  {   2, &hf_mms_hungNamedToken  , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_listOfNamedTokens_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_listOfNamedTokens_item_choice, hf_index, ett_mms_T_listOfNamedTokens_item,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_listOfNamedTokens_sequence_of[1] = {
  { &hf_mms_listOfNamedTokens_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_T_listOfNamedTokens_item },
};

static int
dissect_mms_T_listOfNamedTokens(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_listOfNamedTokens_sequence_of, hf_index, ett_mms_T_listOfNamedTokens);

  return offset;
}


static const ber_sequence_t ReportPoolSemaphoreStatus_Response_sequence[] = {
  { &hf_mms_listOfNamedTokens, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_T_listOfNamedTokens },
  { &hf_mms_moreFollows     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_ReportPoolSemaphoreStatus_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReportPoolSemaphoreStatus_Response_sequence, hf_index, ett_mms_ReportPoolSemaphoreStatus_Response);

  return offset;
}


static const value_string mms_T_entryClass_vals[] = {
  {   0, "simple" },
  {   1, "modifier" },
  { 0, NULL }
};


static int
dissect_mms_T_entryClass(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t SemaphoreEntry_sequence[] = {
  { &hf_mms_entryId         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_OCTET_STRING },
  { &hf_mms_entryClass      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_T_entryClass },
  { &hf_mms_applicationReference, BER_CLASS_CON, 2, 0, dissect_mms_ApplicationReference },
  { &hf_mms_namedToken      , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { &hf_mms_priority        , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Priority },
  { &hf_mms_remainingTimeOut, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  { &hf_mms_abortOnTimeOut  , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_relinquishIfConnectionLost, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_SemaphoreEntry(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SemaphoreEntry_sequence, hf_index, ett_mms_SemaphoreEntry);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_SemaphoreEntry_sequence_of[1] = {
  { &hf_mms_listOfSemaphoreEntry_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_mms_SemaphoreEntry },
};

static int
dissect_mms_SEQUENCE_OF_SemaphoreEntry(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_SemaphoreEntry_sequence_of, hf_index, ett_mms_SEQUENCE_OF_SemaphoreEntry);

  return offset;
}


static const ber_sequence_t ReportSemaphoreEntryStatus_Response_sequence[] = {
  { &hf_mms_listOfSemaphoreEntry, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_SEQUENCE_OF_SemaphoreEntry },
  { &hf_mms_moreFollows     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_ReportSemaphoreEntryStatus_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReportSemaphoreEntryStatus_Response_sequence, hf_index, ett_mms_ReportSemaphoreEntryStatus_Response);

  return offset;
}



static int
dissect_mms_InitiateDownloadSequence_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string mms_T_loadData_vals[] = {
  {   0, "non-coded" },
  {   1, "coded" },
  { 0, NULL }
};

static const ber_choice_t T_loadData_choice[] = {
  {   0, &hf_mms_non_coded       , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_OCTET_STRING },
  {   1, &hf_mms_coded           , BER_CLASS_UNI, 8, BER_FLAGS_NOOWNTAG, dissect_acse_EXTERNALt },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_loadData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_loadData_choice, hf_index, ett_mms_T_loadData,
                                 NULL);

  return offset;
}


static const ber_sequence_t DownloadSegment_Response_sequence[] = {
  { &hf_mms_loadData        , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_T_loadData },
  { &hf_mms_moreFollows     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_DownloadSegment_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DownloadSegment_Response_sequence, hf_index, ett_mms_DownloadSegment_Response);

  return offset;
}



static int
dissect_mms_TerminateDownloadSequence_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t T_listOfCapabilities_02_sequence_of[1] = {
  { &hf_mms_listOfCapabilities_item, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_mms_VisibleString },
};

static int
dissect_mms_T_listOfCapabilities_02(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_listOfCapabilities_02_sequence_of, hf_index, ett_mms_T_listOfCapabilities_02);

  return offset;
}


static const ber_sequence_t InitiateUploadSequence_Response_sequence[] = {
  { &hf_mms_ulsmID          , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Integer32 },
  { &hf_mms_listOfCapabilities_02, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_T_listOfCapabilities_02 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_InitiateUploadSequence_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InitiateUploadSequence_Response_sequence, hf_index, ett_mms_InitiateUploadSequence_Response);

  return offset;
}


static const value_string mms_T_loadData_01_vals[] = {
  {   0, "non-coded" },
  {   1, "coded" },
  { 0, NULL }
};

static const ber_choice_t T_loadData_01_choice[] = {
  {   0, &hf_mms_non_coded       , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_OCTET_STRING },
  {   1, &hf_mms_coded           , BER_CLASS_UNI, 8, BER_FLAGS_NOOWNTAG, dissect_acse_EXTERNALt },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_loadData_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_loadData_01_choice, hf_index, ett_mms_T_loadData_01,
                                 NULL);

  return offset;
}


static const ber_sequence_t UploadSegment_Response_sequence[] = {
  { &hf_mms_loadData_01     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_T_loadData_01 },
  { &hf_mms_moreFollows     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_UploadSegment_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UploadSegment_Response_sequence, hf_index, ett_mms_UploadSegment_Response);

  return offset;
}



static int
dissect_mms_TerminateUploadSequence_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_RequestDomainDownload_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_RequestDomainUpload_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_LoadDomainContent_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_StoreDomainContent_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_DeleteDomain_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t T_listOfCapabilities_05_sequence_of[1] = {
  { &hf_mms_listOfCapabilities_item, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_mms_VisibleString },
};

static int
dissect_mms_T_listOfCapabilities_05(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_listOfCapabilities_05_sequence_of, hf_index, ett_mms_T_listOfCapabilities_05);

  return offset;
}


static const value_string mms_DomainState_vals[] = {
  {   0, "non-existent" },
  {   1, "loading" },
  {   2, "ready" },
  {   3, "in-use" },
  {   4, "complete" },
  {   5, "incomplete" },
  {   7, "d1" },
  {   8, "d2" },
  {   9, "d3" },
  {  10, "d4" },
  {  11, "d5" },
  {  12, "d6" },
  {  13, "d7" },
  {  14, "d8" },
  {  15, "d9" },
  { 0, NULL }
};


static int
dissect_mms_DomainState(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_mms_Integer8(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t GetDomainAttributes_Response_sequence[] = {
  { &hf_mms_listOfCapabilities_05, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_T_listOfCapabilities_05 },
  { &hf_mms_state           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_DomainState },
  { &hf_mms_mmsDeletable    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_sharable        , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_listOfProgramInvocations, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_mms_SEQUENCE_OF_Identifier },
  { &hf_mms_uploadInProgress, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_mms_Integer8 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_GetDomainAttributes_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetDomainAttributes_Response_sequence, hf_index, ett_mms_GetDomainAttributes_Response);

  return offset;
}



static int
dissect_mms_CreateProgramInvocation_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_DeleteProgramInvocation_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_Start_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_Stop_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_Resume_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_Reset_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_Kill_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string mms_T_executionArgument_02_vals[] = {
  {   0, "simpleString" },
  {   1, "encodedString" },
  { 0, NULL }
};

static const ber_choice_t T_executionArgument_02_choice[] = {
  {   0, &hf_mms_simpleString    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_VisibleString },
  {   1, &hf_mms_encodedString   , BER_CLASS_UNI, 8, BER_FLAGS_NOOWNTAG, dissect_acse_EXTERNALt },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_executionArgument_02(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_executionArgument_02_choice, hf_index, ett_mms_T_executionArgument_02,
                                 NULL);

  return offset;
}


static const ber_sequence_t GetProgramInvocationAttributes_Response_sequence[] = {
  { &hf_mms_state_01        , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_ProgramInvocationState },
  { &hf_mms_listOfDomainNames, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_SEQUENCE_OF_Identifier },
  { &hf_mms_mmsDeletable    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_reusable        , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_monitor         , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_startArgument   , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_mms_VisibleString },
  { &hf_mms_executionArgument_02, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_T_executionArgument_02 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_GetProgramInvocationAttributes_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetProgramInvocationAttributes_Response_sequence, hf_index, ett_mms_GetProgramInvocationAttributes_Response);

  return offset;
}



static int
dissect_mms_ObtainFile_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_GeneralizedTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t FileAttributes_sequence[] = {
  { &hf_mms_sizeOfFile      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  { &hf_mms_lastModified    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_GeneralizedTime },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_FileAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   FileAttributes_sequence, hf_index, ett_mms_FileAttributes);

  return offset;
}


static const ber_sequence_t FileOpen_Response_sequence[] = {
  { &hf_mms_frsmID          , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Integer32 },
  { &hf_mms_fileAttributes  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_FileAttributes },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_FileOpen_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   FileOpen_Response_sequence, hf_index, ett_mms_FileOpen_Response);

  return offset;
}



static int
dissect_mms_DefineEventCondition_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_DeleteEventCondition_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Unsigned32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string mms_T_monitoredVariable_vals[] = {
  {   0, "variableReference" },
  {   1, "undefined" },
  { 0, NULL }
};

static const ber_choice_t T_monitoredVariable_choice[] = {
  {   0, &hf_mms_variableReference, BER_CLASS_CON, 0, 0, dissect_mms_VariableSpecification },
  {   1, &hf_mms_undefined       , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_monitoredVariable(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_monitoredVariable_choice, hf_index, ett_mms_T_monitoredVariable,
                                 NULL);

  return offset;
}


static const ber_sequence_t GetEventConditionAttributes_Response_sequence[] = {
  { &hf_mms_mmsDeletable    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_class_01        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_EC_Class },
  { &hf_mms_prio_rity       , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Priority },
  { &hf_mms_severity        , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Unsigned8 },
  { &hf_mms_alarmSummaryReports, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_monitoredVariable_01, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_mms_T_monitoredVariable },
  { &hf_mms_evaluationInterval, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_GetEventConditionAttributes_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetEventConditionAttributes_Response_sequence, hf_index, ett_mms_GetEventConditionAttributes_Response);

  return offset;
}


static const ber_sequence_t ReportEventConditionStatus_Response_sequence[] = {
  { &hf_mms_currentState    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_EC_State },
  { &hf_mms_numberOfEventEnrollments, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  { &hf_mms_enabled         , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_timeOfLastTransitionToActive, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_mms_EventTime },
  { &hf_mms_timeOfLastTransitionToIdle, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_mms_EventTime },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_ReportEventConditionStatus_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReportEventConditionStatus_Response_sequence, hf_index, ett_mms_ReportEventConditionStatus_Response);

  return offset;
}



static int
dissect_mms_AlterEventConditionMonitoring_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_TriggerEvent_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_DefineEventAction_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_DeleteEventAction_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Unsigned32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t GetEventActionAttributes_Response_sequence[] = {
  { &hf_mms_mmsDeletable    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_listOfModifier  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_SEQUENCE_OF_Modifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_GetEventActionAttributes_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetEventActionAttributes_Response_sequence, hf_index, ett_mms_GetEventActionAttributes_Response);

  return offset;
}



static int
dissect_mms_ReportEventActionStatus_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Unsigned32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_mms_DefineEventEnrollment_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_DeleteEventEnrollment_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Unsigned32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string mms_EE_State_vals[] = {
  {   0, "disabled" },
  {   1, "idle" },
  {   2, "active" },
  {   3, "activeNoAckA" },
  {   4, "idleNoAckI" },
  {   5, "idleNoAckA" },
  {   6, "idleAcked" },
  {   7, "activeAcked" },
  { 0, NULL }
};


static int
dissect_mms_EE_State(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string mms_T_currentState_vals[] = {
  {   0, "state" },
  {   1, "undefined" },
  { 0, NULL }
};

static const ber_choice_t T_currentState_choice[] = {
  {   0, &hf_mms_state_03        , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_EE_State },
  {   1, &hf_mms_undefined       , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_currentState(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_currentState_choice, hf_index, ett_mms_T_currentState,
                                 NULL);

  return offset;
}


static const ber_sequence_t AlterEventEnrollment_Response_sequence[] = {
  { &hf_mms_currentState_02 , BER_CLASS_CON, 0, 0, dissect_mms_T_currentState },
  { &hf_mms_transitionTime  , BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_mms_EventTime },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_AlterEventEnrollment_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AlterEventEnrollment_Response_sequence, hf_index, ett_mms_AlterEventEnrollment_Response);

  return offset;
}


static const value_string mms_EE_Duration_vals[] = {
  {   0, "current" },
  {   1, "permanent" },
  { 0, NULL }
};


static int
dissect_mms_EE_Duration(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t ReportEventEnrollmentStatus_Response_sequence[] = {
  { &hf_mms_eventConditionTransitions, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Transitions },
  { &hf_mms_notificationLost, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_duration        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_EE_Duration },
  { &hf_mms_alarmAcknowledgmentRule, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_AlarmAckRule },
  { &hf_mms_currentState_01 , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_mms_EE_State },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_ReportEventEnrollmentStatus_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReportEventEnrollmentStatus_Response_sequence, hf_index, ett_mms_ReportEventEnrollmentStatus_Response);

  return offset;
}


static const value_string mms_T_eventConditionName_vals[] = {
  {   0, "eventCondition" },
  {   1, "undefined" },
  { 0, NULL }
};

static const ber_choice_t T_eventConditionName_choice[] = {
  {   0, &hf_mms_eventCondition  , BER_CLASS_CON, 0, 0, dissect_mms_ObjectName },
  {   1, &hf_mms_undefined       , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_eventConditionName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_eventConditionName_choice, hf_index, ett_mms_T_eventConditionName,
                                 NULL);

  return offset;
}


static const value_string mms_T_eventActionName_vals[] = {
  {   0, "eventAction" },
  {   1, "undefined" },
  { 0, NULL }
};

static const ber_choice_t T_eventActionName_choice[] = {
  {   0, &hf_mms_eventAction     , BER_CLASS_CON, 0, 0, dissect_mms_ObjectName },
  {   1, &hf_mms_undefined       , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_eventActionName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_eventActionName_choice, hf_index, ett_mms_T_eventActionName,
                                 NULL);

  return offset;
}


static const value_string mms_EE_Class_vals[] = {
  {   0, "modifier" },
  {   1, "notification" },
  { 0, NULL }
};


static int
dissect_mms_EE_Class(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t EventEnrollment_sequence[] = {
  { &hf_mms_eventEnrollmentName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { &hf_mms_eventConditionName_01, BER_CLASS_CON, 1, 0, dissect_mms_T_eventConditionName },
  { &hf_mms_eventActionName_01, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_mms_T_eventActionName },
  { &hf_mms_clientApplication, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_mms_ApplicationReference },
  { &hf_mms_mmsDeletable    , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_enrollmentClass , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_mms_EE_Class },
  { &hf_mms_duration        , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_EE_Duration },
  { &hf_mms_invokeID        , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  { &hf_mms_remainingAcceptableDelay, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_EventEnrollment(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EventEnrollment_sequence, hf_index, ett_mms_EventEnrollment);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_EventEnrollment_sequence_of[1] = {
  { &hf_mms_listOfEventEnrollment_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_mms_EventEnrollment },
};

static int
dissect_mms_SEQUENCE_OF_EventEnrollment(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_EventEnrollment_sequence_of, hf_index, ett_mms_SEQUENCE_OF_EventEnrollment);

  return offset;
}


static const ber_sequence_t GetEventEnrollmentAttributes_Response_sequence[] = {
  { &hf_mms_listOfEventEnrollment, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_SEQUENCE_OF_EventEnrollment },
  { &hf_mms_moreFollows     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_GetEventEnrollmentAttributes_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetEventEnrollmentAttributes_Response_sequence, hf_index, ett_mms_GetEventEnrollmentAttributes_Response);

  return offset;
}



static int
dissect_mms_AcknowledgeEventNotification_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string mms_T_unacknowledgedState_vals[] = {
  {   0, "none" },
  {   1, "active" },
  {   2, "idle" },
  {   3, "both" },
  { 0, NULL }
};


static int
dissect_mms_T_unacknowledgedState(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t AlarmSummary_sequence[] = {
  { &hf_mms_eventConditionName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { &hf_mms_severity        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned8 },
  { &hf_mms_currentState    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_EC_State },
  { &hf_mms_unacknowledgedState, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_mms_T_unacknowledgedState },
  { &hf_mms_timeOfLastTransitionToActive, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_mms_EventTime },
  { &hf_mms_timeOfLastTransitionToIdle, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_mms_EventTime },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_AlarmSummary(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AlarmSummary_sequence, hf_index, ett_mms_AlarmSummary);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_AlarmSummary_sequence_of[1] = {
  { &hf_mms_listOfAlarmSummary_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_mms_AlarmSummary },
};

static int
dissect_mms_SEQUENCE_OF_AlarmSummary(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_AlarmSummary_sequence_of, hf_index, ett_mms_SEQUENCE_OF_AlarmSummary);

  return offset;
}


static const ber_sequence_t GetAlarmSummary_Response_sequence[] = {
  { &hf_mms_listOfAlarmSummary, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_SEQUENCE_OF_AlarmSummary },
  { &hf_mms_moreFollows     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_GetAlarmSummary_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetAlarmSummary_Response_sequence, hf_index, ett_mms_GetAlarmSummary_Response);

  return offset;
}


static const ber_sequence_t AlarmEnrollmentSummary_sequence[] = {
  { &hf_mms_eventEnrollmentName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { &hf_mms_clientApplication, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_mms_ApplicationReference },
  { &hf_mms_severity        , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned8 },
  { &hf_mms_currentState    , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_mms_EC_State },
  { &hf_mms_notificationLost, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_alarmAcknowledgmentRule, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_AlarmAckRule },
  { &hf_mms_enrollementState, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_EE_State },
  { &hf_mms_timeOfLastTransitionToActive, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_mms_EventTime },
  { &hf_mms_timeActiveAcknowledged, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_mms_EventTime },
  { &hf_mms_timeOfLastTransitionToIdle, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_mms_EventTime },
  { &hf_mms_timeIdleAcknowledged, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_mms_EventTime },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_AlarmEnrollmentSummary(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AlarmEnrollmentSummary_sequence, hf_index, ett_mms_AlarmEnrollmentSummary);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_AlarmEnrollmentSummary_sequence_of[1] = {
  { &hf_mms_listOfAlarmEnrollmentSummary_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_mms_AlarmEnrollmentSummary },
};

static int
dissect_mms_SEQUENCE_OF_AlarmEnrollmentSummary(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_AlarmEnrollmentSummary_sequence_of, hf_index, ett_mms_SEQUENCE_OF_AlarmEnrollmentSummary);

  return offset;
}


static const ber_sequence_t GetAlarmEnrollmentSummary_Response_sequence[] = {
  { &hf_mms_listOfAlarmEnrollmentSummary, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_SEQUENCE_OF_AlarmEnrollmentSummary },
  { &hf_mms_moreFollows     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_GetAlarmEnrollmentSummary_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetAlarmEnrollmentSummary_Response_sequence, hf_index, ett_mms_GetAlarmEnrollmentSummary_Response);

  return offset;
}


static const ber_sequence_t JournalEntry_sequence[] = {
  { &hf_mms_entryIdentifier , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_OCTET_STRING },
  { &hf_mms_originatingApplication, BER_CLASS_CON, 1, 0, dissect_mms_ApplicationReference },
  { &hf_mms_entryContent    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_EntryContent },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_JournalEntry(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   JournalEntry_sequence, hf_index, ett_mms_JournalEntry);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_JournalEntry_sequence_of[1] = {
  { &hf_mms_listOfJournalEntry_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_mms_JournalEntry },
};

static int
dissect_mms_SEQUENCE_OF_JournalEntry(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_JournalEntry_sequence_of, hf_index, ett_mms_SEQUENCE_OF_JournalEntry);

  return offset;
}


static const ber_sequence_t ReadJournal_Response_sequence[] = {
  { &hf_mms_listOfJournalEntry, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_SEQUENCE_OF_JournalEntry },
  { &hf_mms_moreFollows     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_ReadJournal_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReadJournal_Response_sequence, hf_index, ett_mms_ReadJournal_Response);

  return offset;
}



static int
dissect_mms_WriteJournal_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_InitializeJournal_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Unsigned32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t ReportJournalStatus_Response_sequence[] = {
  { &hf_mms_currentEntries  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  { &hf_mms_mmsDeletable    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_ReportJournalStatus_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReportJournalStatus_Response_sequence, hf_index, ett_mms_ReportJournalStatus_Response);

  return offset;
}



static int
dissect_mms_CreateJournal_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_DeleteJournal_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t T_listOfCapabilities_sequence_of[1] = {
  { &hf_mms_listOfCapabilities_item, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_mms_VisibleString },
};

static int
dissect_mms_T_listOfCapabilities(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_listOfCapabilities_sequence_of, hf_index, ett_mms_T_listOfCapabilities);

  return offset;
}


static const ber_sequence_t GetCapabilityList_Response_sequence[] = {
  { &hf_mms_listOfCapabilities, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_T_listOfCapabilities },
  { &hf_mms_moreFollows     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_GetCapabilityList_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetCapabilityList_Response_sequence, hf_index, ett_mms_GetCapabilityList_Response);

  return offset;
}


static const ber_sequence_t FileRead_Response_sequence[] = {
  { &hf_mms_fileData        , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_OCTET_STRING },
  { &hf_mms_moreFollows     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_FileRead_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   FileRead_Response_sequence, hf_index, ett_mms_FileRead_Response);

  return offset;
}



static int
dissect_mms_FileClose_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_FileRename_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_FileDelete_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t DirectoryEntry_sequence[] = {
  { &hf_mms_filename        , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_FileName },
  { &hf_mms_fileAttributes  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_FileAttributes },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_DirectoryEntry(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DirectoryEntry_sequence, hf_index, ett_mms_DirectoryEntry);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_DirectoryEntry_sequence_of[1] = {
  { &hf_mms_listOfDirectoryEntry_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_mms_DirectoryEntry },
};

static int
dissect_mms_SEQUENCE_OF_DirectoryEntry(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_DirectoryEntry_sequence_of, hf_index, ett_mms_SEQUENCE_OF_DirectoryEntry);

  return offset;
}


static const ber_sequence_t FileDirectory_Response_sequence[] = {
  { &hf_mms_listOfDirectoryEntry, BER_CLASS_CON, 0, 0, dissect_mms_SEQUENCE_OF_DirectoryEntry },
  { &hf_mms_moreFollows     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_FileDirectory_Response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   FileDirectory_Response_sequence, hf_index, ett_mms_FileDirectory_Response);

  return offset;
}


static const value_string mms_ConfirmedServiceResponse_vals[] = {
  {   0, "status" },
  {   1, "getNameList" },
  {   2, "identify" },
  {   3, "rename" },
  {   4, "read" },
  {   5, "write" },
  {   6, "getVariableAccessAttributes" },
  {   7, "defineNamedVariable" },
  {   8, "defineScatteredAccess" },
  {   9, "getScatteredAccessAttributes" },
  {  10, "deleteVariableAccess" },
  {  11, "defineNamedVariableList" },
  {  12, "getNamedVariableListAttributes" },
  {  13, "deleteNamedVariableList" },
  {  14, "defineNamedType" },
  {  15, "getNamedTypeAttributes" },
  {  16, "deleteNamedType" },
  {  17, "input" },
  {  18, "output" },
  {  19, "takeControl" },
  {  20, "relinquishControl" },
  {  21, "defineSemaphore" },
  {  22, "deleteSemaphore" },
  {  23, "reportSemaphoreStatus" },
  {  24, "reportPoolSemaphoreStatus" },
  {  25, "reportSemaphoreEntryStatus" },
  {  26, "initiateDownloadSequence" },
  {  27, "downloadSegment" },
  {  28, "terminateDownloadSequence" },
  {  29, "initiateUploadSequence" },
  {  30, "uploadSegment" },
  {  31, "terminateUploadSequence" },
  {  32, "requestDomainDownLoad" },
  {  33, "requestDomainUpload" },
  {  34, "loadDomainContent" },
  {  35, "storeDomainContent" },
  {  36, "deleteDomain" },
  {  37, "getDomainAttributes" },
  {  38, "createProgramInvocation" },
  {  39, "deleteProgramInvocation" },
  {  40, "start" },
  {  41, "stop" },
  {  42, "resume" },
  {  43, "reset" },
  {  44, "kill" },
  {  45, "getProgramInvocationAttributes" },
  {  46, "obtainFile" },
  {  72, "fileOpen" },
  {  47, "defineEventCondition" },
  {  48, "deleteEventCondition" },
  {  49, "getEventConditionAttributes" },
  {  50, "reportEventConditionStatus" },
  {  51, "alterEventConditionMonitoring" },
  {  52, "triggerEvent" },
  {  53, "defineEventAction" },
  {  54, "deleteEventAction" },
  {  55, "getEventActionAttributes" },
  {  56, "reportActionStatus" },
  {  57, "defineEventEnrollment" },
  {  58, "deleteEventEnrollment" },
  {  59, "alterEventEnrollment" },
  {  60, "reportEventEnrollmentStatus" },
  {  61, "getEventEnrollmentAttributes" },
  {  62, "acknowledgeEventNotification" },
  {  63, "getAlarmSummary" },
  {  64, "getAlarmEnrollmentSummary" },
  {  65, "readJournal" },
  {  66, "writeJournal" },
  {  67, "initializeJournal" },
  {  68, "reportJournalStatus" },
  {  69, "createJournal" },
  {  70, "deleteJournal" },
  {  71, "getCapabilityList" },
  {  73, "fileRead" },
  {  74, "fileClose" },
  {  75, "fileRename" },
  {  76, "fileDelete" },
  {  77, "fileDirectory" },
  { 0, NULL }
};

static const ber_choice_t ConfirmedServiceResponse_choice[] = {
  {   0, &hf_mms_status_01       , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Status_Response },
  {   1, &hf_mms_getNameList_01  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_GetNameList_Response },
  {   2, &hf_mms_identify_01     , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_Identify_Response },
  {   3, &hf_mms_rename_01       , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_mms_Rename_Response },
  {   4, &hf_mms_read_01         , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_mms_Read_Response },
  {   5, &hf_mms_write_01        , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_mms_Write_Response },
  {   6, &hf_mms_getVariableAccessAttributes_01, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_mms_GetVariableAccessAttributes_Response },
  {   7, &hf_mms_defineNamedVariable_01, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_mms_DefineNamedVariable_Response },
  {   8, &hf_mms_defineScatteredAccess_01, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_mms_DefineScatteredAccess_Response },
  {   9, &hf_mms_getScatteredAccessAttributes_01, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_mms_GetScatteredAccessAttributes_Response },
  {  10, &hf_mms_deleteVariableAccess_01, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_mms_DeleteVariableAccess_Response },
  {  11, &hf_mms_defineNamedVariableList_01, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_mms_DefineNamedVariableList_Response },
  {  12, &hf_mms_getNamedVariableListAttributes_01, BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_mms_GetNamedVariableListAttributes_Response },
  {  13, &hf_mms_deleteNamedVariableList_01, BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_mms_DeleteNamedVariableList_Response },
  {  14, &hf_mms_defineNamedType_01, BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_mms_DefineNamedType_Response },
  {  15, &hf_mms_getNamedTypeAttributes_01, BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_mms_GetNamedTypeAttributes_Response },
  {  16, &hf_mms_deleteNamedType_01, BER_CLASS_CON, 16, BER_FLAGS_IMPLTAG, dissect_mms_DeleteNamedType_Response },
  {  17, &hf_mms_input_01        , BER_CLASS_CON, 17, BER_FLAGS_IMPLTAG, dissect_mms_Input_Response },
  {  18, &hf_mms_output_01       , BER_CLASS_CON, 18, BER_FLAGS_IMPLTAG, dissect_mms_Output_Response },
  {  19, &hf_mms_takeControl_01  , BER_CLASS_CON, 19, 0, dissect_mms_TakeControl_Response },
  {  20, &hf_mms_relinquishControl_01, BER_CLASS_CON, 20, BER_FLAGS_IMPLTAG, dissect_mms_RelinquishControl_Response },
  {  21, &hf_mms_defineSemaphore_01, BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_mms_DefineSemaphore_Response },
  {  22, &hf_mms_deleteSemaphore_01, BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_mms_DeleteSemaphore_Response },
  {  23, &hf_mms_reportSemaphoreStatus_01, BER_CLASS_CON, 23, BER_FLAGS_IMPLTAG, dissect_mms_ReportSemaphoreStatus_Response },
  {  24, &hf_mms_reportPoolSemaphoreStatus_01, BER_CLASS_CON, 24, BER_FLAGS_IMPLTAG, dissect_mms_ReportPoolSemaphoreStatus_Response },
  {  25, &hf_mms_reportSemaphoreEntryStatus_01, BER_CLASS_CON, 25, BER_FLAGS_IMPLTAG, dissect_mms_ReportSemaphoreEntryStatus_Response },
  {  26, &hf_mms_initiateDownloadSequence_01, BER_CLASS_CON, 26, BER_FLAGS_IMPLTAG, dissect_mms_InitiateDownloadSequence_Response },
  {  27, &hf_mms_downloadSegment_01, BER_CLASS_CON, 27, BER_FLAGS_IMPLTAG, dissect_mms_DownloadSegment_Response },
  {  28, &hf_mms_terminateDownloadSequence_01, BER_CLASS_CON, 28, BER_FLAGS_IMPLTAG, dissect_mms_TerminateDownloadSequence_Response },
  {  29, &hf_mms_initiateUploadSequence_01, BER_CLASS_CON, 29, BER_FLAGS_IMPLTAG, dissect_mms_InitiateUploadSequence_Response },
  {  30, &hf_mms_uploadSegment_01, BER_CLASS_CON, 30, BER_FLAGS_IMPLTAG, dissect_mms_UploadSegment_Response },
  {  31, &hf_mms_terminateUploadSequence_01, BER_CLASS_CON, 31, BER_FLAGS_IMPLTAG, dissect_mms_TerminateUploadSequence_Response },
  {  32, &hf_mms_requestDomainDownLoad, BER_CLASS_CON, 32, BER_FLAGS_IMPLTAG, dissect_mms_RequestDomainDownload_Response },
  {  33, &hf_mms_requestDomainUpload_01, BER_CLASS_CON, 33, BER_FLAGS_IMPLTAG, dissect_mms_RequestDomainUpload_Response },
  {  34, &hf_mms_loadDomainContent_01, BER_CLASS_CON, 34, BER_FLAGS_IMPLTAG, dissect_mms_LoadDomainContent_Response },
  {  35, &hf_mms_storeDomainContent_01, BER_CLASS_CON, 35, BER_FLAGS_IMPLTAG, dissect_mms_StoreDomainContent_Response },
  {  36, &hf_mms_deleteDomain_01 , BER_CLASS_CON, 36, BER_FLAGS_IMPLTAG, dissect_mms_DeleteDomain_Response },
  {  37, &hf_mms_getDomainAttributes_01, BER_CLASS_CON, 37, BER_FLAGS_IMPLTAG, dissect_mms_GetDomainAttributes_Response },
  {  38, &hf_mms_createProgramInvocation_01, BER_CLASS_CON, 38, BER_FLAGS_IMPLTAG, dissect_mms_CreateProgramInvocation_Response },
  {  39, &hf_mms_deleteProgramInvocation_01, BER_CLASS_CON, 39, BER_FLAGS_IMPLTAG, dissect_mms_DeleteProgramInvocation_Response },
  {  40, &hf_mms_start_01        , BER_CLASS_CON, 40, BER_FLAGS_IMPLTAG, dissect_mms_Start_Response },
  {  41, &hf_mms_stop_01         , BER_CLASS_CON, 41, BER_FLAGS_IMPLTAG, dissect_mms_Stop_Response },
  {  42, &hf_mms_resume_01       , BER_CLASS_CON, 42, BER_FLAGS_IMPLTAG, dissect_mms_Resume_Response },
  {  43, &hf_mms_reset_01        , BER_CLASS_CON, 43, BER_FLAGS_IMPLTAG, dissect_mms_Reset_Response },
  {  44, &hf_mms_kill_01         , BER_CLASS_CON, 44, BER_FLAGS_IMPLTAG, dissect_mms_Kill_Response },
  {  45, &hf_mms_getProgramInvocationAttributes_01, BER_CLASS_CON, 45, BER_FLAGS_IMPLTAG, dissect_mms_GetProgramInvocationAttributes_Response },
  {  46, &hf_mms_obtainFile_01   , BER_CLASS_CON, 46, BER_FLAGS_IMPLTAG, dissect_mms_ObtainFile_Response },
  {  72, &hf_mms_fileOpen_01     , BER_CLASS_CON, 72, BER_FLAGS_IMPLTAG, dissect_mms_FileOpen_Response },
  {  47, &hf_mms_defineEventCondition_01, BER_CLASS_CON, 47, BER_FLAGS_IMPLTAG, dissect_mms_DefineEventCondition_Response },
  {  48, &hf_mms_deleteEventCondition_01, BER_CLASS_CON, 48, BER_FLAGS_IMPLTAG, dissect_mms_DeleteEventCondition_Response },
  {  49, &hf_mms_getEventConditionAttributes_01, BER_CLASS_CON, 49, BER_FLAGS_IMPLTAG, dissect_mms_GetEventConditionAttributes_Response },
  {  50, &hf_mms_reportEventConditionStatus_01, BER_CLASS_CON, 50, BER_FLAGS_IMPLTAG, dissect_mms_ReportEventConditionStatus_Response },
  {  51, &hf_mms_alterEventConditionMonitoring_01, BER_CLASS_CON, 51, BER_FLAGS_IMPLTAG, dissect_mms_AlterEventConditionMonitoring_Response },
  {  52, &hf_mms_triggerEvent_01 , BER_CLASS_CON, 52, BER_FLAGS_IMPLTAG, dissect_mms_TriggerEvent_Response },
  {  53, &hf_mms_defineEventAction_01, BER_CLASS_CON, 53, BER_FLAGS_IMPLTAG, dissect_mms_DefineEventAction_Response },
  {  54, &hf_mms_deleteEventAction_01, BER_CLASS_CON, 54, BER_FLAGS_IMPLTAG, dissect_mms_DeleteEventAction_Response },
  {  55, &hf_mms_getEventActionAttributes_01, BER_CLASS_CON, 55, BER_FLAGS_IMPLTAG, dissect_mms_GetEventActionAttributes_Response },
  {  56, &hf_mms_reportActionStatus, BER_CLASS_CON, 56, BER_FLAGS_IMPLTAG, dissect_mms_ReportEventActionStatus_Response },
  {  57, &hf_mms_defineEventEnrollment_01, BER_CLASS_CON, 57, BER_FLAGS_IMPLTAG, dissect_mms_DefineEventEnrollment_Response },
  {  58, &hf_mms_deleteEventEnrollment_01, BER_CLASS_CON, 58, BER_FLAGS_IMPLTAG, dissect_mms_DeleteEventEnrollment_Response },
  {  59, &hf_mms_alterEventEnrollment_01, BER_CLASS_CON, 59, BER_FLAGS_IMPLTAG, dissect_mms_AlterEventEnrollment_Response },
  {  60, &hf_mms_reportEventEnrollmentStatus_01, BER_CLASS_CON, 60, BER_FLAGS_IMPLTAG, dissect_mms_ReportEventEnrollmentStatus_Response },
  {  61, &hf_mms_getEventEnrollmentAttributes_01, BER_CLASS_CON, 61, BER_FLAGS_IMPLTAG, dissect_mms_GetEventEnrollmentAttributes_Response },
  {  62, &hf_mms_acknowledgeEventNotification_01, BER_CLASS_CON, 62, BER_FLAGS_IMPLTAG, dissect_mms_AcknowledgeEventNotification_Response },
  {  63, &hf_mms_getAlarmSummary_01, BER_CLASS_CON, 63, BER_FLAGS_IMPLTAG, dissect_mms_GetAlarmSummary_Response },
  {  64, &hf_mms_getAlarmEnrollmentSummary_01, BER_CLASS_CON, 64, BER_FLAGS_IMPLTAG, dissect_mms_GetAlarmEnrollmentSummary_Response },
  {  65, &hf_mms_readJournal_01  , BER_CLASS_CON, 65, BER_FLAGS_IMPLTAG, dissect_mms_ReadJournal_Response },
  {  66, &hf_mms_writeJournal_01 , BER_CLASS_CON, 66, BER_FLAGS_IMPLTAG, dissect_mms_WriteJournal_Response },
  {  67, &hf_mms_initializeJournal_01, BER_CLASS_CON, 67, BER_FLAGS_IMPLTAG, dissect_mms_InitializeJournal_Response },
  {  68, &hf_mms_reportJournalStatus_01, BER_CLASS_CON, 68, BER_FLAGS_IMPLTAG, dissect_mms_ReportJournalStatus_Response },
  {  69, &hf_mms_createJournal_01, BER_CLASS_CON, 69, BER_FLAGS_IMPLTAG, dissect_mms_CreateJournal_Response },
  {  70, &hf_mms_deleteJournal_01, BER_CLASS_CON, 70, BER_FLAGS_IMPLTAG, dissect_mms_DeleteJournal_Response },
  {  71, &hf_mms_getCapabilityList_01, BER_CLASS_CON, 71, BER_FLAGS_IMPLTAG, dissect_mms_GetCapabilityList_Response },
  {  73, &hf_mms_fileRead_01     , BER_CLASS_CON, 73, BER_FLAGS_IMPLTAG, dissect_mms_FileRead_Response },
  {  74, &hf_mms_fileClose_01    , BER_CLASS_CON, 74, BER_FLAGS_IMPLTAG, dissect_mms_FileClose_Response },
  {  75, &hf_mms_fileRename_01   , BER_CLASS_CON, 75, BER_FLAGS_IMPLTAG, dissect_mms_FileRename_Response },
  {  76, &hf_mms_fileDelete_01   , BER_CLASS_CON, 76, BER_FLAGS_IMPLTAG, dissect_mms_FileDelete_Response },
  {  77, &hf_mms_fileDirectory_01, BER_CLASS_CON, 77, BER_FLAGS_IMPLTAG, dissect_mms_FileDirectory_Response },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_ConfirmedServiceResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ConfirmedServiceResponse_choice, hf_index, ett_mms_ConfirmedServiceResponse,
                                 NULL);

  return offset;
}


static const ber_sequence_t Confirmed_ResponsePDU_sequence[] = {
  { &hf_mms_invokeID        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_mms_Unsigned32 },
  { &hf_mms_confirmedServiceResponse, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_ConfirmedServiceResponse },
  { &hf_mms_cs_request_detail, BER_CLASS_CON, 79, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_mms_CS_Request_Detail },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_Confirmed_ResponsePDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Confirmed_ResponsePDU_sequence, hf_index, ett_mms_Confirmed_ResponsePDU);

  return offset;
}


static const ber_sequence_t Confirmed_ErrorPDU_sequence[] = {
  { &hf_mms_invokeID        , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  { &hf_mms_modifierPosition, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  { &hf_mms_serviceError    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_ServiceError },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_Confirmed_ErrorPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Confirmed_ErrorPDU_sequence, hf_index, ett_mms_Confirmed_ErrorPDU);

  return offset;
}


static const ber_sequence_t InformationReport_sequence[] = {
  { &hf_mms_variableAccessSpecification, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_VariableAccessSpecification },
  { &hf_mms_listOfAccessResult, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_SEQUENCE_OF_AccessResult },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_InformationReport(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InformationReport_sequence, hf_index, ett_mms_InformationReport);

  return offset;
}



static int
dissect_mms_UnsolicitedStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Status_Response(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string mms_T_eventConditionName_01_vals[] = {
  {   0, "eventCondition" },
  {   1, "undefined" },
  { 0, NULL }
};

static const ber_choice_t T_eventConditionName_01_choice[] = {
  {   0, &hf_mms_eventCondition  , BER_CLASS_CON, 0, 0, dissect_mms_ObjectName },
  {   1, &hf_mms_undefined       , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_eventConditionName_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_eventConditionName_01_choice, hf_index, ett_mms_T_eventConditionName_01,
                                 NULL);

  return offset;
}


static const value_string mms_T_eventActionResult_vals[] = {
  {   0, "success" },
  {   1, "failure" },
  { 0, NULL }
};

static const ber_choice_t T_eventActionResult_choice[] = {
  {   0, &hf_mms_success_02      , BER_CLASS_CON, 0, 0, dissect_mms_ConfirmedServiceResponse },
  {   1, &hf_mms_failure_01      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_ServiceError },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_eventActionResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_eventActionResult_choice, hf_index, ett_mms_T_eventActionResult,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_actionResult_sequence[] = {
  { &hf_mms_eventActioName  , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { &hf_mms_eventActionResult, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_T_eventActionResult },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_actionResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_actionResult_sequence, hf_index, ett_mms_T_actionResult);

  return offset;
}


static const ber_sequence_t EventNotification_sequence[] = {
  { &hf_mms_eventEnrollmentName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { &hf_mms_eventConditionName_02, BER_CLASS_CON, 1, 0, dissect_mms_T_eventConditionName_01 },
  { &hf_mms_severity        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned8 },
  { &hf_mms_currentState    , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_EC_State },
  { &hf_mms_transitionTime  , BER_CLASS_CON, 4, BER_FLAGS_NOTCHKTAG, dissect_mms_EventTime },
  { &hf_mms_notificationLost, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_alarmAcknowledgmentRule, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_AlarmAckRule },
  { &hf_mms_actionResult    , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_T_actionResult },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_EventNotification(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EventNotification_sequence, hf_index, ett_mms_EventNotification);

  return offset;
}


static const value_string mms_UnconfirmedService_vals[] = {
  {   0, "informationReport" },
  {   1, "unsolicitedStatus" },
  {   2, "eventNotification" },
  { 0, NULL }
};

static const ber_choice_t UnconfirmedService_choice[] = {
  {   0, &hf_mms_informationReport, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_InformationReport },
  {   1, &hf_mms_unsolicitedStatus, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_UnsolicitedStatus },
  {   2, &hf_mms_eventNotification, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_EventNotification },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_UnconfirmedService(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 UnconfirmedService_choice, hf_index, ett_mms_UnconfirmedService,
                                 NULL);

  return offset;
}


static const ber_sequence_t Unconfirmed_PDU_sequence[] = {
  { &hf_mms_unconfirmedService, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_UnconfirmedService },
  { &hf_mms_cs_request_detail, BER_CLASS_CON, 79, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_mms_CS_Request_Detail },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_Unconfirmed_PDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Unconfirmed_PDU_sequence, hf_index, ett_mms_Unconfirmed_PDU);

  return offset;
}


static const value_string mms_T_confirmed_requestPDU_vals[] = {
  {   0, "other" },
  {   1, "unrecognized-service" },
  {   2, "unrecognized-modifier" },
  {   3, "invalid-invokeID" },
  {   4, "invalid-argument" },
  {   5, "invalid-modifier" },
  {   6, "max-serv-outstanding-exceeded" },
  {   8, "max-recursion-exceeded" },
  {   9, "value-out-of-range" },
  { 0, NULL }
};


static int
dissect_mms_T_confirmed_requestPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string mms_T_confirmed_responsePDU_vals[] = {
  {   0, "other" },
  {   1, "unrecognized-service" },
  {   2, "invalid-invokeID" },
  {   3, "invalid-result" },
  {   5, "max-recursion-exceeded" },
  {   6, "value-out-of-range" },
  { 0, NULL }
};


static int
dissect_mms_T_confirmed_responsePDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string mms_T_confirmed_errorPDU_vals[] = {
  {   0, "other" },
  {   1, "unrecognized-service" },
  {   2, "invalid-invokeID" },
  {   3, "invalid-serviceError" },
  {   4, "value-out-of-range" },
  { 0, NULL }
};


static int
dissect_mms_T_confirmed_errorPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string mms_T_unconfirmedPDU_vals[] = {
  {   0, "other" },
  {   1, "unrecognized-service" },
  {   2, "invalid-argument" },
  {   3, "max-recursion-exceeded" },
  {   4, "value-out-of-range" },
  { 0, NULL }
};


static int
dissect_mms_T_unconfirmedPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string mms_T_pdu_error_vals[] = {
  {   0, "unknown-pdu-type" },
  {   1, "invalid-pdu" },
  {   2, "illegal-acse-mapping" },
  { 0, NULL }
};


static int
dissect_mms_T_pdu_error(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string mms_T_cancel_requestPDU_vals[] = {
  {   0, "other" },
  {   1, "invalid-invokeID" },
  { 0, NULL }
};


static int
dissect_mms_T_cancel_requestPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string mms_T_cancel_responsePDU_vals[] = {
  {   0, "other" },
  {   1, "invalid-invokeID" },
  { 0, NULL }
};


static int
dissect_mms_T_cancel_responsePDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string mms_T_cancel_errorPDU_vals[] = {
  {   0, "other" },
  {   1, "invalid-invokeID" },
  {   2, "invalid-serviceError" },
  {   3, "value-out-of-range" },
  { 0, NULL }
};


static int
dissect_mms_T_cancel_errorPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string mms_T_conclude_requestPDU_vals[] = {
  {   0, "other" },
  {   1, "invalid-argument" },
  { 0, NULL }
};


static int
dissect_mms_T_conclude_requestPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string mms_T_conclude_responsePDU_vals[] = {
  {   0, "other" },
  {   1, "invalid-result" },
  { 0, NULL }
};


static int
dissect_mms_T_conclude_responsePDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string mms_T_conclude_errorPDU_vals[] = {
  {   0, "other" },
  {   1, "invalid-serviceError" },
  {   2, "value-out-of-range" },
  { 0, NULL }
};


static int
dissect_mms_T_conclude_errorPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string mms_T_rejectReason_vals[] = {
  {   1, "confirmed-requestPDU" },
  {   2, "confirmed-responsePDU" },
  {   3, "confirmed-errorPDU" },
  {   4, "unconfirmedPDU" },
  {   5, "pdu-error" },
  {   6, "cancel-requestPDU" },
  {   7, "cancel-responsePDU" },
  {   8, "cancel-errorPDU" },
  {   9, "conclude-requestPDU" },
  {  10, "conclude-responsePDU" },
  {  11, "conclude-errorPDU" },
  { 0, NULL }
};

static const ber_choice_t T_rejectReason_choice[] = {
  {   1, &hf_mms_confirmed_requestPDU, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_T_confirmed_requestPDU },
  {   2, &hf_mms_confirmed_responsePDU, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_T_confirmed_responsePDU },
  {   3, &hf_mms_confirmed_errorPDU, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_mms_T_confirmed_errorPDU },
  {   4, &hf_mms_unconfirmedPDU  , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_mms_T_unconfirmedPDU },
  {   5, &hf_mms_pdu_error       , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_mms_T_pdu_error },
  {   6, &hf_mms_cancel_requestPDU, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_mms_T_cancel_requestPDU },
  {   7, &hf_mms_cancel_responsePDU, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_mms_T_cancel_responsePDU },
  {   8, &hf_mms_cancel_errorPDU , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_mms_T_cancel_errorPDU },
  {   9, &hf_mms_conclude_requestPDU, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_mms_T_conclude_requestPDU },
  {  10, &hf_mms_conclude_responsePDU, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_mms_T_conclude_responsePDU },
  {  11, &hf_mms_conclude_errorPDU, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_mms_T_conclude_errorPDU },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_rejectReason(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_rejectReason_choice, hf_index, ett_mms_T_rejectReason,
                                 NULL);

  return offset;
}


static const ber_sequence_t RejectPDU_sequence[] = {
  { &hf_mms_originalInvokeID, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  { &hf_mms_rejectReason    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_T_rejectReason },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_RejectPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RejectPDU_sequence, hf_index, ett_mms_RejectPDU);

  return offset;
}



static int
dissect_mms_Cancel_RequestPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Unsigned32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_mms_Cancel_ResponsePDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Unsigned32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t Cancel_ErrorPDU_sequence[] = {
  { &hf_mms_originalInvokeID, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  { &hf_mms_serviceError    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_ServiceError },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_Cancel_ErrorPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Cancel_ErrorPDU_sequence, hf_index, ett_mms_Cancel_ErrorPDU);

  return offset;
}



static int
dissect_mms_Integer16(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const asn_namedbit ParameterSupportOptions_bits[] = {
  {  0, &hf_mms_ParameterSupportOptions_str1, -1, -1, "str1", NULL },
  {  1, &hf_mms_ParameterSupportOptions_str2, -1, -1, "str2", NULL },
  {  2, &hf_mms_ParameterSupportOptions_vnam, -1, -1, "vnam", NULL },
  {  3, &hf_mms_ParameterSupportOptions_valt, -1, -1, "valt", NULL },
  {  4, &hf_mms_ParameterSupportOptions_vadr, -1, -1, "vadr", NULL },
  {  5, &hf_mms_ParameterSupportOptions_vsca, -1, -1, "vsca", NULL },
  {  6, &hf_mms_ParameterSupportOptions_tpy, -1, -1, "tpy", NULL },
  {  7, &hf_mms_ParameterSupportOptions_vlis, -1, -1, "vlis", NULL },
  {  8, &hf_mms_ParameterSupportOptions_real, -1, -1, "real", NULL },
  { 10, &hf_mms_ParameterSupportOptions_cei, -1, -1, "cei", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_mms_ParameterSupportOptions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    ParameterSupportOptions_bits, hf_index, ett_mms_ParameterSupportOptions,
                                    NULL);

  return offset;
}


static const asn_namedbit ServiceSupportOptions_bits[] = {
  {  0, &hf_mms_ServiceSupportOptions_status, -1, -1, "status", NULL },
  {  1, &hf_mms_ServiceSupportOptions_getNameList, -1, -1, "getNameList", NULL },
  {  2, &hf_mms_ServiceSupportOptions_identify, -1, -1, "identify", NULL },
  {  3, &hf_mms_ServiceSupportOptions_rename, -1, -1, "rename", NULL },
  {  4, &hf_mms_ServiceSupportOptions_read, -1, -1, "read", NULL },
  {  5, &hf_mms_ServiceSupportOptions_write, -1, -1, "write", NULL },
  {  6, &hf_mms_ServiceSupportOptions_getVariableAccessAttributes, -1, -1, "getVariableAccessAttributes", NULL },
  {  7, &hf_mms_ServiceSupportOptions_defineNamedVariable, -1, -1, "defineNamedVariable", NULL },
  {  8, &hf_mms_ServiceSupportOptions_defineScatteredAccess, -1, -1, "defineScatteredAccess", NULL },
  {  9, &hf_mms_ServiceSupportOptions_getScatteredAccessAttributes, -1, -1, "getScatteredAccessAttributes", NULL },
  { 10, &hf_mms_ServiceSupportOptions_deleteVariableAccess, -1, -1, "deleteVariableAccess", NULL },
  { 11, &hf_mms_ServiceSupportOptions_defineNamedVariableList, -1, -1, "defineNamedVariableList", NULL },
  { 12, &hf_mms_ServiceSupportOptions_getNamedVariableListAttributes, -1, -1, "getNamedVariableListAttributes", NULL },
  { 13, &hf_mms_ServiceSupportOptions_deleteNamedVariableList, -1, -1, "deleteNamedVariableList", NULL },
  { 14, &hf_mms_ServiceSupportOptions_defineNamedType, -1, -1, "defineNamedType", NULL },
  { 15, &hf_mms_ServiceSupportOptions_getNamedTypeAttributes, -1, -1, "getNamedTypeAttributes", NULL },
  { 16, &hf_mms_ServiceSupportOptions_deleteNamedType, -1, -1, "deleteNamedType", NULL },
  { 17, &hf_mms_ServiceSupportOptions_input, -1, -1, "input", NULL },
  { 18, &hf_mms_ServiceSupportOptions_output, -1, -1, "output", NULL },
  { 19, &hf_mms_ServiceSupportOptions_takeControl, -1, -1, "takeControl", NULL },
  { 20, &hf_mms_ServiceSupportOptions_relinquishControl, -1, -1, "relinquishControl", NULL },
  { 21, &hf_mms_ServiceSupportOptions_defineSemaphore, -1, -1, "defineSemaphore", NULL },
  { 22, &hf_mms_ServiceSupportOptions_deleteSemaphore, -1, -1, "deleteSemaphore", NULL },
  { 23, &hf_mms_ServiceSupportOptions_reportSemaphoreStatus, -1, -1, "reportSemaphoreStatus", NULL },
  { 24, &hf_mms_ServiceSupportOptions_reportPoolSemaphoreStatus, -1, -1, "reportPoolSemaphoreStatus", NULL },
  { 25, &hf_mms_ServiceSupportOptions_reportSemaphoreEntryStatus, -1, -1, "reportSemaphoreEntryStatus", NULL },
  { 26, &hf_mms_ServiceSupportOptions_initiateDownloadSequence, -1, -1, "initiateDownloadSequence", NULL },
  { 27, &hf_mms_ServiceSupportOptions_downloadSegment, -1, -1, "downloadSegment", NULL },
  { 28, &hf_mms_ServiceSupportOptions_terminateDownloadSequence, -1, -1, "terminateDownloadSequence", NULL },
  { 29, &hf_mms_ServiceSupportOptions_initiateUploadSequence, -1, -1, "initiateUploadSequence", NULL },
  { 30, &hf_mms_ServiceSupportOptions_uploadSegment, -1, -1, "uploadSegment", NULL },
  { 31, &hf_mms_ServiceSupportOptions_terminateUploadSequence, -1, -1, "terminateUploadSequence", NULL },
  { 32, &hf_mms_ServiceSupportOptions_requestDomainDownload, -1, -1, "requestDomainDownload", NULL },
  { 33, &hf_mms_ServiceSupportOptions_requestDomainUpload, -1, -1, "requestDomainUpload", NULL },
  { 34, &hf_mms_ServiceSupportOptions_loadDomainContent, -1, -1, "loadDomainContent", NULL },
  { 35, &hf_mms_ServiceSupportOptions_storeDomainContent, -1, -1, "storeDomainContent", NULL },
  { 36, &hf_mms_ServiceSupportOptions_deleteDomain, -1, -1, "deleteDomain", NULL },
  { 37, &hf_mms_ServiceSupportOptions_getDomainAttributes, -1, -1, "getDomainAttributes", NULL },
  { 38, &hf_mms_ServiceSupportOptions_createProgramInvocation, -1, -1, "createProgramInvocation", NULL },
  { 39, &hf_mms_ServiceSupportOptions_deleteProgramInvocation, -1, -1, "deleteProgramInvocation", NULL },
  { 40, &hf_mms_ServiceSupportOptions_start, -1, -1, "start", NULL },
  { 41, &hf_mms_ServiceSupportOptions_stop, -1, -1, "stop", NULL },
  { 42, &hf_mms_ServiceSupportOptions_resume, -1, -1, "resume", NULL },
  { 43, &hf_mms_ServiceSupportOptions_reset, -1, -1, "reset", NULL },
  { 44, &hf_mms_ServiceSupportOptions_kill, -1, -1, "kill", NULL },
  { 45, &hf_mms_ServiceSupportOptions_getProgramInvocationAttributes, -1, -1, "getProgramInvocationAttributes", NULL },
  { 46, &hf_mms_ServiceSupportOptions_obtainFile, -1, -1, "obtainFile", NULL },
  { 47, &hf_mms_ServiceSupportOptions_defineEventCondition, -1, -1, "defineEventCondition", NULL },
  { 48, &hf_mms_ServiceSupportOptions_deleteEventCondition, -1, -1, "deleteEventCondition", NULL },
  { 49, &hf_mms_ServiceSupportOptions_getEventConditionAttributes, -1, -1, "getEventConditionAttributes", NULL },
  { 50, &hf_mms_ServiceSupportOptions_reportEventConditionStatus, -1, -1, "reportEventConditionStatus", NULL },
  { 51, &hf_mms_ServiceSupportOptions_alterEventConditionMonitoring, -1, -1, "alterEventConditionMonitoring", NULL },
  { 52, &hf_mms_ServiceSupportOptions_triggerEvent, -1, -1, "triggerEvent", NULL },
  { 53, &hf_mms_ServiceSupportOptions_defineEventAction, -1, -1, "defineEventAction", NULL },
  { 54, &hf_mms_ServiceSupportOptions_deleteEventAction, -1, -1, "deleteEventAction", NULL },
  { 55, &hf_mms_ServiceSupportOptions_getEventActionAttributes, -1, -1, "getEventActionAttributes", NULL },
  { 56, &hf_mms_ServiceSupportOptions_reportActionStatus, -1, -1, "reportActionStatus", NULL },
  { 57, &hf_mms_ServiceSupportOptions_defineEventEnrollment, -1, -1, "defineEventEnrollment", NULL },
  { 58, &hf_mms_ServiceSupportOptions_deleteEventEnrollment, -1, -1, "deleteEventEnrollment", NULL },
  { 59, &hf_mms_ServiceSupportOptions_alterEventEnrollment, -1, -1, "alterEventEnrollment", NULL },
  { 60, &hf_mms_ServiceSupportOptions_reportEventEnrollmentStatus, -1, -1, "reportEventEnrollmentStatus", NULL },
  { 61, &hf_mms_ServiceSupportOptions_getEventEnrollmentAttributes, -1, -1, "getEventEnrollmentAttributes", NULL },
  { 62, &hf_mms_ServiceSupportOptions_acknowledgeEventNotification, -1, -1, "acknowledgeEventNotification", NULL },
  { 63, &hf_mms_ServiceSupportOptions_getAlarmSummary, -1, -1, "getAlarmSummary", NULL },
  { 64, &hf_mms_ServiceSupportOptions_getAlarmEnrollmentSummary, -1, -1, "getAlarmEnrollmentSummary", NULL },
  { 65, &hf_mms_ServiceSupportOptions_readJournal, -1, -1, "readJournal", NULL },
  { 66, &hf_mms_ServiceSupportOptions_writeJournal, -1, -1, "writeJournal", NULL },
  { 67, &hf_mms_ServiceSupportOptions_initializeJournal, -1, -1, "initializeJournal", NULL },
  { 68, &hf_mms_ServiceSupportOptions_reportJournalStatus, -1, -1, "reportJournalStatus", NULL },
  { 69, &hf_mms_ServiceSupportOptions_createJournal, -1, -1, "createJournal", NULL },
  { 70, &hf_mms_ServiceSupportOptions_deleteJournal, -1, -1, "deleteJournal", NULL },
  { 71, &hf_mms_ServiceSupportOptions_getCapabilityList, -1, -1, "getCapabilityList", NULL },
  { 72, &hf_mms_ServiceSupportOptions_fileOpen, -1, -1, "fileOpen", NULL },
  { 73, &hf_mms_ServiceSupportOptions_fileRead, -1, -1, "fileRead", NULL },
  { 74, &hf_mms_ServiceSupportOptions_fileClose, -1, -1, "fileClose", NULL },
  { 75, &hf_mms_ServiceSupportOptions_fileRename, -1, -1, "fileRename", NULL },
  { 76, &hf_mms_ServiceSupportOptions_fileDelete, -1, -1, "fileDelete", NULL },
  { 77, &hf_mms_ServiceSupportOptions_fileDirectory, -1, -1, "fileDirectory", NULL },
  { 78, &hf_mms_ServiceSupportOptions_unsolicitedStatus, -1, -1, "unsolicitedStatus", NULL },
  { 79, &hf_mms_ServiceSupportOptions_informationReport, -1, -1, "informationReport", NULL },
  { 80, &hf_mms_ServiceSupportOptions_eventNotification, -1, -1, "eventNotification", NULL },
  { 81, &hf_mms_ServiceSupportOptions_attachToEventCondition, -1, -1, "attachToEventCondition", NULL },
  { 82, &hf_mms_ServiceSupportOptions_attachToSemaphore, -1, -1, "attachToSemaphore", NULL },
  { 83, &hf_mms_ServiceSupportOptions_conclude, -1, -1, "conclude", NULL },
  { 84, &hf_mms_ServiceSupportOptions_cancel, -1, -1, "cancel", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_mms_ServiceSupportOptions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    ServiceSupportOptions_bits, hf_index, ett_mms_ServiceSupportOptions,
                                    NULL);

  return offset;
}


static const ber_sequence_t InitRequestDetail_sequence[] = {
  { &hf_mms_proposedVersionNumber, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Integer16 },
  { &hf_mms_proposedParameterCBB, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_ParameterSupportOptions },
  { &hf_mms_servicesSupportedCalling, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_ServiceSupportOptions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_InitRequestDetail(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InitRequestDetail_sequence, hf_index, ett_mms_InitRequestDetail);

  return offset;
}


static const ber_sequence_t Initiate_RequestPDU_sequence[] = {
  { &hf_mms_localDetailCalling, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Integer32 },
  { &hf_mms_proposedMaxServOutstandingCalling, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_Integer16 },
  { &hf_mms_proposedMaxServOutstandingCalled, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_Integer16 },
  { &hf_mms_proposedDataStructureNestingLevel, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Integer8 },
  { &hf_mms_mmsInitRequestDetail, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_mms_InitRequestDetail },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_Initiate_RequestPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Initiate_RequestPDU_sequence, hf_index, ett_mms_Initiate_RequestPDU);

  return offset;
}


static const ber_sequence_t InitResponseDetail_sequence[] = {
  { &hf_mms_negociatedVersionNumber, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Integer16 },
  { &hf_mms_negociatedParameterCBB, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_ParameterSupportOptions },
  { &hf_mms_servicesSupportedCalled, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_ServiceSupportOptions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_InitResponseDetail(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InitResponseDetail_sequence, hf_index, ett_mms_InitResponseDetail);

  return offset;
}


static const ber_sequence_t Initiate_ResponsePDU_sequence[] = {
  { &hf_mms_localDetailCalled, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Integer32 },
  { &hf_mms_negociatedMaxServOutstandingCalling, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_Integer16 },
  { &hf_mms_negociatedMaxServOutstandingCalled, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_Integer16 },
  { &hf_mms_negociatedDataStructureNestingLevel, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Integer8 },
  { &hf_mms_mmsInitResponseDetail, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_mms_InitResponseDetail },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_Initiate_ResponsePDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Initiate_ResponsePDU_sequence, hf_index, ett_mms_Initiate_ResponsePDU);

  return offset;
}



static int
dissect_mms_Initiate_ErrorPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_ServiceError(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_mms_Conclude_RequestPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_Conclude_ResponsePDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_Conclude_ErrorPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_ServiceError(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


const value_string mms_MMSpdu_vals[] = {
  {   0, "confirmed-RequestPDU" },
  {   1, "confirmed-ResponsePDU" },
  {   2, "confirmed-ErrorPDU" },
  {   3, "unconfirmed-PDU" },
  {   4, "rejectPDU" },
  {   5, "cancel-RequestPDU" },
  {   6, "cancel-ResponsePDU" },
  {   7, "cancel-ErrorPDU" },
  {   8, "initiate-RequestPDU" },
  {   9, "initiate-ResponsePDU" },
  {  10, "initiate-ErrorPDU" },
  {  11, "conclude-RequestPDU" },
  {  12, "conclude-ResponsePDU" },
  {  13, "conclude-ErrorPDU" },
  { 0, NULL }
};

static const ber_choice_t MMSpdu_choice[] = {
  {   0, &hf_mms_confirmed_RequestPDU, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Confirmed_RequestPDU },
  {   1, &hf_mms_confirmed_ResponsePDU, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_Confirmed_ResponsePDU },
  {   2, &hf_mms_confirmed_ErrorPDU, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_Confirmed_ErrorPDU },
  {   3, &hf_mms_unconfirmed_PDU , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_mms_Unconfirmed_PDU },
  {   4, &hf_mms_rejectPDU       , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_mms_RejectPDU },
  {   5, &hf_mms_cancel_RequestPDU, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_mms_Cancel_RequestPDU },
  {   6, &hf_mms_cancel_ResponsePDU, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_mms_Cancel_ResponsePDU },
  {   7, &hf_mms_cancel_ErrorPDU , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_mms_Cancel_ErrorPDU },
  {   8, &hf_mms_initiate_RequestPDU, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_mms_Initiate_RequestPDU },
  {   9, &hf_mms_initiate_ResponsePDU, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_mms_Initiate_ResponsePDU },
  {  10, &hf_mms_initiate_ErrorPDU, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_mms_Initiate_ErrorPDU },
  {  11, &hf_mms_conclude_RequestPDU, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_mms_Conclude_RequestPDU },
  {  12, &hf_mms_conclude_ResponsePDU, BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_mms_Conclude_ResponsePDU },
  {  13, &hf_mms_conclude_ErrorPDU, BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_mms_Conclude_ErrorPDU },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_mms_MMSpdu(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 37 "../../asn1/mms/mms.cnf"
  gint branch_taken;

  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 MMSpdu_choice, hf_index, ett_mms_MMSpdu,
                                 &branch_taken);


  if( (branch_taken!=-1) && mms_MMSpdu_vals[branch_taken].strptr ){
    col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s ", mms_MMSpdu_vals[branch_taken].strptr);
  }





  return offset;
}


/*--- End of included file: packet-mms-fn.c ---*/
#line 56 "../../asn1/mms/packet-mms-template.c"

/*
* Dissect MMS PDUs inside a PPDU.
*/
static void
dissect_mms(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	int offset = 0;
	int old_offset;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_mms, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_mms);
	}
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "MMS");
  	col_clear(pinfo->cinfo, COL_INFO);

	while (tvb_reported_length_remaining(tvb, offset) > 0){
		old_offset=offset;
		offset=dissect_mms_MMSpdu(FALSE, tvb, offset, &asn1_ctx , tree, -1);
		if(offset == old_offset){
			proto_tree_add_text(tree, tvb, offset, -1,"Internal error, zero-byte MMS PDU");
			break;
		}
	}
}


/*--- proto_register_mms -------------------------------------------*/
void proto_register_mms(void) {

	/* List of fields */
  static hf_register_info hf[] =
  {

/*--- Included file: packet-mms-hfarr.c ---*/
#line 1 "../../asn1/mms/packet-mms-hfarr.c"
    { &hf_mms_confirmed_RequestPDU,
      { "confirmed-RequestPDU", "mms.confirmed_RequestPDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_confirmed_ResponsePDU,
      { "confirmed-ResponsePDU", "mms.confirmed_ResponsePDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_confirmed_ErrorPDU,
      { "confirmed-ErrorPDU", "mms.confirmed_ErrorPDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_unconfirmed_PDU,
      { "unconfirmed-PDU", "mms.unconfirmed_PDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_rejectPDU,
      { "rejectPDU", "mms.rejectPDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_cancel_RequestPDU,
      { "cancel-RequestPDU", "mms.cancel_RequestPDU",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_cancel_ResponsePDU,
      { "cancel-ResponsePDU", "mms.cancel_ResponsePDU",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_cancel_ErrorPDU,
      { "cancel-ErrorPDU", "mms.cancel_ErrorPDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_initiate_RequestPDU,
      { "initiate-RequestPDU", "mms.initiate_RequestPDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_initiate_ResponsePDU,
      { "initiate-ResponsePDU", "mms.initiate_ResponsePDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_initiate_ErrorPDU,
      { "initiate-ErrorPDU", "mms.initiate_ErrorPDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_conclude_RequestPDU,
      { "conclude-RequestPDU", "mms.conclude_RequestPDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_conclude_ResponsePDU,
      { "conclude-ResponsePDU", "mms.conclude_ResponsePDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_conclude_ErrorPDU,
      { "conclude-ErrorPDU", "mms.conclude_ErrorPDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_invokeID,
      { "invokeID", "mms.invokeID",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_mms_listOfModifier,
      { "listOfModifier", "mms.listOfModifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Modifier", HFILL }},
    { &hf_mms_listOfModifier_item,
      { "Modifier", "mms.Modifier",
        FT_UINT32, BASE_DEC, VALS(mms_Modifier_vals), 0,
        NULL, HFILL }},
    { &hf_mms_confirmedServiceRequest,
      { "confirmedServiceRequest", "mms.confirmedServiceRequest",
        FT_UINT32, BASE_DEC, VALS(mms_ConfirmedServiceRequest_vals), 0,
        NULL, HFILL }},
    { &hf_mms_cs_request_detail,
      { "cs-request-detail", "mms.cs_request_detail",
        FT_UINT32, BASE_DEC, VALS(mms_CS_Request_Detail_vals), 0,
        NULL, HFILL }},
    { &hf_mms_unconfirmedService,
      { "unconfirmedService", "mms.unconfirmedService",
        FT_UINT32, BASE_DEC, VALS(mms_UnconfirmedService_vals), 0,
        NULL, HFILL }},
    { &hf_mms_confirmedServiceResponse,
      { "confirmedServiceResponse", "mms.confirmedServiceResponse",
        FT_UINT32, BASE_DEC, VALS(mms_ConfirmedServiceResponse_vals), 0,
        NULL, HFILL }},
    { &hf_mms_modifierPosition,
      { "modifierPosition", "mms.modifierPosition",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_mms_serviceError,
      { "serviceError", "mms.serviceError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_informationReport,
      { "informationReport", "mms.informationReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_unsolicitedStatus,
      { "unsolicitedStatus", "mms.unsolicitedStatus_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_eventNotification,
      { "eventNotification", "mms.eventNotification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_attach_To_Event_Condition,
      { "attach-To-Event-Condition", "mms.attach_To_Event_Condition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttachToEventCondition", HFILL }},
    { &hf_mms_attach_To_Semaphore,
      { "attach-To-Semaphore", "mms.attach_To_Semaphore_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttachToSemaphore", HFILL }},
    { &hf_mms_status,
      { "status", "mms.status",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "Status_Request", HFILL }},
    { &hf_mms_getNameList,
      { "getNameList", "mms.getNameList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetNameList_Request", HFILL }},
    { &hf_mms_identify,
      { "identify", "mms.identify_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Identify_Request", HFILL }},
    { &hf_mms_rename,
      { "rename", "mms.rename_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Rename_Request", HFILL }},
    { &hf_mms_read,
      { "read", "mms.read_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Read_Request", HFILL }},
    { &hf_mms_write,
      { "write", "mms.write_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Write_Request", HFILL }},
    { &hf_mms_getVariableAccessAttributes,
      { "getVariableAccessAttributes", "mms.getVariableAccessAttributes",
        FT_UINT32, BASE_DEC, VALS(mms_GetVariableAccessAttributes_Request_vals), 0,
        "GetVariableAccessAttributes_Request", HFILL }},
    { &hf_mms_defineNamedVariable,
      { "defineNamedVariable", "mms.defineNamedVariable_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DefineNamedVariable_Request", HFILL }},
    { &hf_mms_defineScatteredAccess,
      { "defineScatteredAccess", "mms.defineScatteredAccess_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DefineScatteredAccess_Request", HFILL }},
    { &hf_mms_getScatteredAccessAttributes,
      { "getScatteredAccessAttributes", "mms.getScatteredAccessAttributes",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "GetScatteredAccessAttributes_Request", HFILL }},
    { &hf_mms_deleteVariableAccess,
      { "deleteVariableAccess", "mms.deleteVariableAccess_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeleteVariableAccess_Request", HFILL }},
    { &hf_mms_defineNamedVariableList,
      { "defineNamedVariableList", "mms.defineNamedVariableList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DefineNamedVariableList_Request", HFILL }},
    { &hf_mms_getNamedVariableListAttributes,
      { "getNamedVariableListAttributes", "mms.getNamedVariableListAttributes",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "GetNamedVariableListAttributes_Request", HFILL }},
    { &hf_mms_deleteNamedVariableList,
      { "deleteNamedVariableList", "mms.deleteNamedVariableList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeleteNamedVariableList_Request", HFILL }},
    { &hf_mms_defineNamedType,
      { "defineNamedType", "mms.defineNamedType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DefineNamedType_Request", HFILL }},
    { &hf_mms_getNamedTypeAttributes,
      { "getNamedTypeAttributes", "mms.getNamedTypeAttributes",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "GetNamedTypeAttributes_Request", HFILL }},
    { &hf_mms_deleteNamedType,
      { "deleteNamedType", "mms.deleteNamedType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeleteNamedType_Request", HFILL }},
    { &hf_mms_input,
      { "input", "mms.input_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Input_Request", HFILL }},
    { &hf_mms_output,
      { "output", "mms.output_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Output_Request", HFILL }},
    { &hf_mms_takeControl,
      { "takeControl", "mms.takeControl_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TakeControl_Request", HFILL }},
    { &hf_mms_relinquishControl,
      { "relinquishControl", "mms.relinquishControl_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RelinquishControl_Request", HFILL }},
    { &hf_mms_defineSemaphore,
      { "defineSemaphore", "mms.defineSemaphore_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DefineSemaphore_Request", HFILL }},
    { &hf_mms_deleteSemaphore,
      { "deleteSemaphore", "mms.deleteSemaphore",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "DeleteSemaphore_Request", HFILL }},
    { &hf_mms_reportSemaphoreStatus,
      { "reportSemaphoreStatus", "mms.reportSemaphoreStatus",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "ReportSemaphoreStatus_Request", HFILL }},
    { &hf_mms_reportPoolSemaphoreStatus,
      { "reportPoolSemaphoreStatus", "mms.reportPoolSemaphoreStatus_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportPoolSemaphoreStatus_Request", HFILL }},
    { &hf_mms_reportSemaphoreEntryStatus,
      { "reportSemaphoreEntryStatus", "mms.reportSemaphoreEntryStatus_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportSemaphoreEntryStatus_Request", HFILL }},
    { &hf_mms_initiateDownloadSequence,
      { "initiateDownloadSequence", "mms.initiateDownloadSequence_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InitiateDownloadSequence_Request", HFILL }},
    { &hf_mms_downloadSegment,
      { "downloadSegment", "mms.downloadSegment",
        FT_STRING, BASE_NONE, NULL, 0,
        "DownloadSegment_Request", HFILL }},
    { &hf_mms_terminateDownloadSequence,
      { "terminateDownloadSequence", "mms.terminateDownloadSequence_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminateDownloadSequence_Request", HFILL }},
    { &hf_mms_initiateUploadSequence,
      { "initiateUploadSequence", "mms.initiateUploadSequence",
        FT_STRING, BASE_NONE, NULL, 0,
        "InitiateUploadSequence_Request", HFILL }},
    { &hf_mms_uploadSegment,
      { "uploadSegment", "mms.uploadSegment",
        FT_INT32, BASE_DEC, NULL, 0,
        "UploadSegment_Request", HFILL }},
    { &hf_mms_terminateUploadSequence,
      { "terminateUploadSequence", "mms.terminateUploadSequence",
        FT_INT32, BASE_DEC, NULL, 0,
        "TerminateUploadSequence_Request", HFILL }},
    { &hf_mms_requestDomainDownload,
      { "requestDomainDownload", "mms.requestDomainDownload_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestDomainDownload_Request", HFILL }},
    { &hf_mms_requestDomainUpload,
      { "requestDomainUpload", "mms.requestDomainUpload_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestDomainUpload_Request", HFILL }},
    { &hf_mms_loadDomainContent,
      { "loadDomainContent", "mms.loadDomainContent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LoadDomainContent_Request", HFILL }},
    { &hf_mms_storeDomainContent,
      { "storeDomainContent", "mms.storeDomainContent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "StoreDomainContent_Request", HFILL }},
    { &hf_mms_deleteDomain,
      { "deleteDomain", "mms.deleteDomain",
        FT_STRING, BASE_NONE, NULL, 0,
        "DeleteDomain_Request", HFILL }},
    { &hf_mms_getDomainAttributes,
      { "getDomainAttributes", "mms.getDomainAttributes",
        FT_STRING, BASE_NONE, NULL, 0,
        "GetDomainAttributes_Request", HFILL }},
    { &hf_mms_createProgramInvocation,
      { "createProgramInvocation", "mms.createProgramInvocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CreateProgramInvocation_Request", HFILL }},
    { &hf_mms_deleteProgramInvocation,
      { "deleteProgramInvocation", "mms.deleteProgramInvocation",
        FT_STRING, BASE_NONE, NULL, 0,
        "DeleteProgramInvocation_Request", HFILL }},
    { &hf_mms_start,
      { "start", "mms.start_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Start_Request", HFILL }},
    { &hf_mms_stop,
      { "stop", "mms.stop_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Stop_Request", HFILL }},
    { &hf_mms_resume,
      { "resume", "mms.resume_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Resume_Request", HFILL }},
    { &hf_mms_reset,
      { "reset", "mms.reset_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Reset_Request", HFILL }},
    { &hf_mms_kill,
      { "kill", "mms.kill_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Kill_Request", HFILL }},
    { &hf_mms_getProgramInvocationAttributes,
      { "getProgramInvocationAttributes", "mms.getProgramInvocationAttributes",
        FT_STRING, BASE_NONE, NULL, 0,
        "GetProgramInvocationAttributes_Request", HFILL }},
    { &hf_mms_obtainFile,
      { "obtainFile", "mms.obtainFile_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ObtainFile_Request", HFILL }},
    { &hf_mms_defineEventCondition,
      { "defineEventCondition", "mms.defineEventCondition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DefineEventCondition_Request", HFILL }},
    { &hf_mms_deleteEventCondition,
      { "deleteEventCondition", "mms.deleteEventCondition",
        FT_UINT32, BASE_DEC, VALS(mms_DeleteEventCondition_Request_vals), 0,
        "DeleteEventCondition_Request", HFILL }},
    { &hf_mms_getEventConditionAttributes,
      { "getEventConditionAttributes", "mms.getEventConditionAttributes",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "GetEventConditionAttributes_Request", HFILL }},
    { &hf_mms_reportEventConditionStatus,
      { "reportEventConditionStatus", "mms.reportEventConditionStatus",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "ReportEventConditionStatus_Request", HFILL }},
    { &hf_mms_alterEventConditionMonitoring,
      { "alterEventConditionMonitoring", "mms.alterEventConditionMonitoring_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlterEventConditionMonitoring_Request", HFILL }},
    { &hf_mms_triggerEvent,
      { "triggerEvent", "mms.triggerEvent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TriggerEvent_Request", HFILL }},
    { &hf_mms_defineEventAction,
      { "defineEventAction", "mms.defineEventAction_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DefineEventAction_Request", HFILL }},
    { &hf_mms_deleteEventAction,
      { "deleteEventAction", "mms.deleteEventAction",
        FT_UINT32, BASE_DEC, VALS(mms_DeleteEventAction_Request_vals), 0,
        "DeleteEventAction_Request", HFILL }},
    { &hf_mms_getEventActionAttributes,
      { "getEventActionAttributes", "mms.getEventActionAttributes",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "GetEventActionAttributes_Request", HFILL }},
    { &hf_mms_reportEventActionStatus,
      { "reportEventActionStatus", "mms.reportEventActionStatus",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "ReportEventActionStatus_Request", HFILL }},
    { &hf_mms_defineEventEnrollment,
      { "defineEventEnrollment", "mms.defineEventEnrollment_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DefineEventEnrollment_Request", HFILL }},
    { &hf_mms_deleteEventEnrollment,
      { "deleteEventEnrollment", "mms.deleteEventEnrollment",
        FT_UINT32, BASE_DEC, VALS(mms_DeleteEventEnrollment_Request_vals), 0,
        "DeleteEventEnrollment_Request", HFILL }},
    { &hf_mms_alterEventEnrollment,
      { "alterEventEnrollment", "mms.alterEventEnrollment_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlterEventEnrollment_Request", HFILL }},
    { &hf_mms_reportEventEnrollmentStatus,
      { "reportEventEnrollmentStatus", "mms.reportEventEnrollmentStatus",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "ReportEventEnrollmentStatus_Request", HFILL }},
    { &hf_mms_getEventEnrollmentAttributes,
      { "getEventEnrollmentAttributes", "mms.getEventEnrollmentAttributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetEventEnrollmentAttributes_Request", HFILL }},
    { &hf_mms_acknowledgeEventNotification,
      { "acknowledgeEventNotification", "mms.acknowledgeEventNotification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AcknowledgeEventNotification_Request", HFILL }},
    { &hf_mms_getAlarmSummary,
      { "getAlarmSummary", "mms.getAlarmSummary_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetAlarmSummary_Request", HFILL }},
    { &hf_mms_getAlarmEnrollmentSummary,
      { "getAlarmEnrollmentSummary", "mms.getAlarmEnrollmentSummary_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetAlarmEnrollmentSummary_Request", HFILL }},
    { &hf_mms_readJournal,
      { "readJournal", "mms.readJournal_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReadJournal_Request", HFILL }},
    { &hf_mms_writeJournal,
      { "writeJournal", "mms.writeJournal_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "WriteJournal_Request", HFILL }},
    { &hf_mms_initializeJournal,
      { "initializeJournal", "mms.initializeJournal_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InitializeJournal_Request", HFILL }},
    { &hf_mms_reportJournalStatus,
      { "reportJournalStatus", "mms.reportJournalStatus",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "ReportJournalStatus_Request", HFILL }},
    { &hf_mms_createJournal,
      { "createJournal", "mms.createJournal_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CreateJournal_Request", HFILL }},
    { &hf_mms_deleteJournal,
      { "deleteJournal", "mms.deleteJournal_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeleteJournal_Request", HFILL }},
    { &hf_mms_getCapabilityList,
      { "getCapabilityList", "mms.getCapabilityList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetCapabilityList_Request", HFILL }},
    { &hf_mms_fileOpen,
      { "fileOpen", "mms.fileOpen_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FileOpen_Request", HFILL }},
    { &hf_mms_fileRead,
      { "fileRead", "mms.fileRead",
        FT_INT32, BASE_DEC, NULL, 0,
        "FileRead_Request", HFILL }},
    { &hf_mms_fileClose,
      { "fileClose", "mms.fileClose",
        FT_INT32, BASE_DEC, NULL, 0,
        "FileClose_Request", HFILL }},
    { &hf_mms_fileRename,
      { "fileRename", "mms.fileRename_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FileRename_Request", HFILL }},
    { &hf_mms_fileDelete,
      { "fileDelete", "mms.fileDelete",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FileDelete_Request", HFILL }},
    { &hf_mms_fileDirectory,
      { "fileDirectory", "mms.fileDirectory_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FileDirectory_Request", HFILL }},
    { &hf_mms_foo,
      { "foo", "mms.foo",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_mms_status_01,
      { "status", "mms.status_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Status_Response", HFILL }},
    { &hf_mms_getNameList_01,
      { "getNameList", "mms.getNameList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetNameList_Response", HFILL }},
    { &hf_mms_identify_01,
      { "identify", "mms.identify_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Identify_Response", HFILL }},
    { &hf_mms_rename_01,
      { "rename", "mms.rename_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Rename_Response", HFILL }},
    { &hf_mms_read_01,
      { "read", "mms.read_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Read_Response", HFILL }},
    { &hf_mms_write_01,
      { "write", "mms.write",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Write_Response", HFILL }},
    { &hf_mms_getVariableAccessAttributes_01,
      { "getVariableAccessAttributes", "mms.getVariableAccessAttributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetVariableAccessAttributes_Response", HFILL }},
    { &hf_mms_defineNamedVariable_01,
      { "defineNamedVariable", "mms.defineNamedVariable_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DefineNamedVariable_Response", HFILL }},
    { &hf_mms_defineScatteredAccess_01,
      { "defineScatteredAccess", "mms.defineScatteredAccess_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DefineScatteredAccess_Response", HFILL }},
    { &hf_mms_getScatteredAccessAttributes_01,
      { "getScatteredAccessAttributes", "mms.getScatteredAccessAttributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetScatteredAccessAttributes_Response", HFILL }},
    { &hf_mms_deleteVariableAccess_01,
      { "deleteVariableAccess", "mms.deleteVariableAccess_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeleteVariableAccess_Response", HFILL }},
    { &hf_mms_defineNamedVariableList_01,
      { "defineNamedVariableList", "mms.defineNamedVariableList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DefineNamedVariableList_Response", HFILL }},
    { &hf_mms_getNamedVariableListAttributes_01,
      { "getNamedVariableListAttributes", "mms.getNamedVariableListAttributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetNamedVariableListAttributes_Response", HFILL }},
    { &hf_mms_deleteNamedVariableList_01,
      { "deleteNamedVariableList", "mms.deleteNamedVariableList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeleteNamedVariableList_Response", HFILL }},
    { &hf_mms_defineNamedType_01,
      { "defineNamedType", "mms.defineNamedType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DefineNamedType_Response", HFILL }},
    { &hf_mms_getNamedTypeAttributes_01,
      { "getNamedTypeAttributes", "mms.getNamedTypeAttributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetNamedTypeAttributes_Response", HFILL }},
    { &hf_mms_deleteNamedType_01,
      { "deleteNamedType", "mms.deleteNamedType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeleteNamedType_Response", HFILL }},
    { &hf_mms_input_01,
      { "input", "mms.input",
        FT_STRING, BASE_NONE, NULL, 0,
        "Input_Response", HFILL }},
    { &hf_mms_output_01,
      { "output", "mms.output_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Output_Response", HFILL }},
    { &hf_mms_takeControl_01,
      { "takeControl", "mms.takeControl",
        FT_UINT32, BASE_DEC, VALS(mms_TakeControl_Response_vals), 0,
        "TakeControl_Response", HFILL }},
    { &hf_mms_relinquishControl_01,
      { "relinquishControl", "mms.relinquishControl_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RelinquishControl_Response", HFILL }},
    { &hf_mms_defineSemaphore_01,
      { "defineSemaphore", "mms.defineSemaphore_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DefineSemaphore_Response", HFILL }},
    { &hf_mms_deleteSemaphore_01,
      { "deleteSemaphore", "mms.deleteSemaphore_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeleteSemaphore_Response", HFILL }},
    { &hf_mms_reportSemaphoreStatus_01,
      { "reportSemaphoreStatus", "mms.reportSemaphoreStatus_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportSemaphoreStatus_Response", HFILL }},
    { &hf_mms_reportPoolSemaphoreStatus_01,
      { "reportPoolSemaphoreStatus", "mms.reportPoolSemaphoreStatus_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportPoolSemaphoreStatus_Response", HFILL }},
    { &hf_mms_reportSemaphoreEntryStatus_01,
      { "reportSemaphoreEntryStatus", "mms.reportSemaphoreEntryStatus_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportSemaphoreEntryStatus_Response", HFILL }},
    { &hf_mms_initiateDownloadSequence_01,
      { "initiateDownloadSequence", "mms.initiateDownloadSequence_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InitiateDownloadSequence_Response", HFILL }},
    { &hf_mms_downloadSegment_01,
      { "downloadSegment", "mms.downloadSegment_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DownloadSegment_Response", HFILL }},
    { &hf_mms_terminateDownloadSequence_01,
      { "terminateDownloadSequence", "mms.terminateDownloadSequence_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminateDownloadSequence_Response", HFILL }},
    { &hf_mms_initiateUploadSequence_01,
      { "initiateUploadSequence", "mms.initiateUploadSequence_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InitiateUploadSequence_Response", HFILL }},
    { &hf_mms_uploadSegment_01,
      { "uploadSegment", "mms.uploadSegment_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UploadSegment_Response", HFILL }},
    { &hf_mms_terminateUploadSequence_01,
      { "terminateUploadSequence", "mms.terminateUploadSequence_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TerminateUploadSequence_Response", HFILL }},
    { &hf_mms_requestDomainDownLoad,
      { "requestDomainDownLoad", "mms.requestDomainDownLoad_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestDomainDownload_Response", HFILL }},
    { &hf_mms_requestDomainUpload_01,
      { "requestDomainUpload", "mms.requestDomainUpload_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestDomainUpload_Response", HFILL }},
    { &hf_mms_loadDomainContent_01,
      { "loadDomainContent", "mms.loadDomainContent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LoadDomainContent_Response", HFILL }},
    { &hf_mms_storeDomainContent_01,
      { "storeDomainContent", "mms.storeDomainContent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "StoreDomainContent_Response", HFILL }},
    { &hf_mms_deleteDomain_01,
      { "deleteDomain", "mms.deleteDomain_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeleteDomain_Response", HFILL }},
    { &hf_mms_getDomainAttributes_01,
      { "getDomainAttributes", "mms.getDomainAttributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetDomainAttributes_Response", HFILL }},
    { &hf_mms_createProgramInvocation_01,
      { "createProgramInvocation", "mms.createProgramInvocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CreateProgramInvocation_Response", HFILL }},
    { &hf_mms_deleteProgramInvocation_01,
      { "deleteProgramInvocation", "mms.deleteProgramInvocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeleteProgramInvocation_Response", HFILL }},
    { &hf_mms_start_01,
      { "start", "mms.start_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Start_Response", HFILL }},
    { &hf_mms_stop_01,
      { "stop", "mms.stop_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Stop_Response", HFILL }},
    { &hf_mms_resume_01,
      { "resume", "mms.resume_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Resume_Response", HFILL }},
    { &hf_mms_reset_01,
      { "reset", "mms.reset_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Reset_Response", HFILL }},
    { &hf_mms_kill_01,
      { "kill", "mms.kill_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Kill_Response", HFILL }},
    { &hf_mms_getProgramInvocationAttributes_01,
      { "getProgramInvocationAttributes", "mms.getProgramInvocationAttributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetProgramInvocationAttributes_Response", HFILL }},
    { &hf_mms_obtainFile_01,
      { "obtainFile", "mms.obtainFile_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ObtainFile_Response", HFILL }},
    { &hf_mms_fileOpen_01,
      { "fileOpen", "mms.fileOpen_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FileOpen_Response", HFILL }},
    { &hf_mms_defineEventCondition_01,
      { "defineEventCondition", "mms.defineEventCondition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DefineEventCondition_Response", HFILL }},
    { &hf_mms_deleteEventCondition_01,
      { "deleteEventCondition", "mms.deleteEventCondition",
        FT_INT32, BASE_DEC, NULL, 0,
        "DeleteEventCondition_Response", HFILL }},
    { &hf_mms_getEventConditionAttributes_01,
      { "getEventConditionAttributes", "mms.getEventConditionAttributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetEventConditionAttributes_Response", HFILL }},
    { &hf_mms_reportEventConditionStatus_01,
      { "reportEventConditionStatus", "mms.reportEventConditionStatus_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportEventConditionStatus_Response", HFILL }},
    { &hf_mms_alterEventConditionMonitoring_01,
      { "alterEventConditionMonitoring", "mms.alterEventConditionMonitoring_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlterEventConditionMonitoring_Response", HFILL }},
    { &hf_mms_triggerEvent_01,
      { "triggerEvent", "mms.triggerEvent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TriggerEvent_Response", HFILL }},
    { &hf_mms_defineEventAction_01,
      { "defineEventAction", "mms.defineEventAction_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DefineEventAction_Response", HFILL }},
    { &hf_mms_deleteEventAction_01,
      { "deleteEventAction", "mms.deleteEventAction",
        FT_INT32, BASE_DEC, NULL, 0,
        "DeleteEventAction_Response", HFILL }},
    { &hf_mms_getEventActionAttributes_01,
      { "getEventActionAttributes", "mms.getEventActionAttributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetEventActionAttributes_Response", HFILL }},
    { &hf_mms_reportActionStatus,
      { "reportActionStatus", "mms.reportActionStatus",
        FT_INT32, BASE_DEC, NULL, 0,
        "ReportEventActionStatus_Response", HFILL }},
    { &hf_mms_defineEventEnrollment_01,
      { "defineEventEnrollment", "mms.defineEventEnrollment_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DefineEventEnrollment_Response", HFILL }},
    { &hf_mms_deleteEventEnrollment_01,
      { "deleteEventEnrollment", "mms.deleteEventEnrollment",
        FT_INT32, BASE_DEC, NULL, 0,
        "DeleteEventEnrollment_Response", HFILL }},
    { &hf_mms_alterEventEnrollment_01,
      { "alterEventEnrollment", "mms.alterEventEnrollment_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlterEventEnrollment_Response", HFILL }},
    { &hf_mms_reportEventEnrollmentStatus_01,
      { "reportEventEnrollmentStatus", "mms.reportEventEnrollmentStatus_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportEventEnrollmentStatus_Response", HFILL }},
    { &hf_mms_getEventEnrollmentAttributes_01,
      { "getEventEnrollmentAttributes", "mms.getEventEnrollmentAttributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetEventEnrollmentAttributes_Response", HFILL }},
    { &hf_mms_acknowledgeEventNotification_01,
      { "acknowledgeEventNotification", "mms.acknowledgeEventNotification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AcknowledgeEventNotification_Response", HFILL }},
    { &hf_mms_getAlarmSummary_01,
      { "getAlarmSummary", "mms.getAlarmSummary_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetAlarmSummary_Response", HFILL }},
    { &hf_mms_getAlarmEnrollmentSummary_01,
      { "getAlarmEnrollmentSummary", "mms.getAlarmEnrollmentSummary_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetAlarmEnrollmentSummary_Response", HFILL }},
    { &hf_mms_readJournal_01,
      { "readJournal", "mms.readJournal_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReadJournal_Response", HFILL }},
    { &hf_mms_writeJournal_01,
      { "writeJournal", "mms.writeJournal_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "WriteJournal_Response", HFILL }},
    { &hf_mms_initializeJournal_01,
      { "initializeJournal", "mms.initializeJournal",
        FT_INT32, BASE_DEC, NULL, 0,
        "InitializeJournal_Response", HFILL }},
    { &hf_mms_reportJournalStatus_01,
      { "reportJournalStatus", "mms.reportJournalStatus_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportJournalStatus_Response", HFILL }},
    { &hf_mms_createJournal_01,
      { "createJournal", "mms.createJournal_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CreateJournal_Response", HFILL }},
    { &hf_mms_deleteJournal_01,
      { "deleteJournal", "mms.deleteJournal_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeleteJournal_Response", HFILL }},
    { &hf_mms_getCapabilityList_01,
      { "getCapabilityList", "mms.getCapabilityList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetCapabilityList_Response", HFILL }},
    { &hf_mms_fileRead_01,
      { "fileRead", "mms.fileRead_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FileRead_Response", HFILL }},
    { &hf_mms_fileClose_01,
      { "fileClose", "mms.fileClose_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FileClose_Response", HFILL }},
    { &hf_mms_fileRename_01,
      { "fileRename", "mms.fileRename_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FileRename_Response", HFILL }},
    { &hf_mms_fileDelete_01,
      { "fileDelete", "mms.fileDelete_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FileDelete_Response", HFILL }},
    { &hf_mms_fileDirectory_01,
      { "fileDirectory", "mms.fileDirectory_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FileDirectory_Response", HFILL }},
    { &hf_mms_FileName_item,
      { "FileName item", "mms.FileName_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "GraphicString", HFILL }},
    { &hf_mms_vmd_specific,
      { "vmd-specific", "mms.vmd_specific",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_mms_domain_specific,
      { "domain-specific", "mms.domain_specific_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_domainId,
      { "domainId", "mms.domainId",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_mms_itemId,
      { "itemId", "mms.itemId",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_mms_aa_specific,
      { "aa-specific", "mms.aa_specific",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_mms_ap_title,
      { "ap-title", "mms.ap_title",
        FT_UINT32, BASE_DEC, VALS(acse_AP_title_vals), 0,
        NULL, HFILL }},
    { &hf_mms_ap_invocation_id,
      { "ap-invocation-id", "mms.ap_invocation_id",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_ae_qualifier,
      { "ae-qualifier", "mms.ae_qualifier",
        FT_UINT32, BASE_DEC, VALS(acse_ASO_qualifier_vals), 0,
        NULL, HFILL }},
    { &hf_mms_ae_invocation_id,
      { "ae-invocation-id", "mms.ae_invocation_id",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_localDetailCalling,
      { "localDetailCalling", "mms.localDetailCalling",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer32", HFILL }},
    { &hf_mms_proposedMaxServOutstandingCalling,
      { "proposedMaxServOutstandingCalling", "mms.proposedMaxServOutstandingCalling",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer16", HFILL }},
    { &hf_mms_proposedMaxServOutstandingCalled,
      { "proposedMaxServOutstandingCalled", "mms.proposedMaxServOutstandingCalled",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer16", HFILL }},
    { &hf_mms_proposedDataStructureNestingLevel,
      { "proposedDataStructureNestingLevel", "mms.proposedDataStructureNestingLevel",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer8", HFILL }},
    { &hf_mms_mmsInitRequestDetail,
      { "mmsInitRequestDetail", "mms.mmsInitRequestDetail_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InitRequestDetail", HFILL }},
    { &hf_mms_proposedVersionNumber,
      { "proposedVersionNumber", "mms.proposedVersionNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer16", HFILL }},
    { &hf_mms_proposedParameterCBB,
      { "proposedParameterCBB", "mms.proposedParameterCBB",
        FT_BYTES, BASE_NONE, NULL, 0,
        "ParameterSupportOptions", HFILL }},
    { &hf_mms_servicesSupportedCalling,
      { "servicesSupportedCalling", "mms.servicesSupportedCalling",
        FT_BYTES, BASE_NONE, NULL, 0,
        "ServiceSupportOptions", HFILL }},
    { &hf_mms_localDetailCalled,
      { "localDetailCalled", "mms.localDetailCalled",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer32", HFILL }},
    { &hf_mms_negociatedMaxServOutstandingCalling,
      { "negociatedMaxServOutstandingCalling", "mms.negociatedMaxServOutstandingCalling",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer16", HFILL }},
    { &hf_mms_negociatedMaxServOutstandingCalled,
      { "negociatedMaxServOutstandingCalled", "mms.negociatedMaxServOutstandingCalled",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer16", HFILL }},
    { &hf_mms_negociatedDataStructureNestingLevel,
      { "negociatedDataStructureNestingLevel", "mms.negociatedDataStructureNestingLevel",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer8", HFILL }},
    { &hf_mms_mmsInitResponseDetail,
      { "mmsInitResponseDetail", "mms.mmsInitResponseDetail_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InitResponseDetail", HFILL }},
    { &hf_mms_negociatedVersionNumber,
      { "negociatedVersionNumber", "mms.negociatedVersionNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer16", HFILL }},
    { &hf_mms_negociatedParameterCBB,
      { "negociatedParameterCBB", "mms.negociatedParameterCBB",
        FT_BYTES, BASE_NONE, NULL, 0,
        "ParameterSupportOptions", HFILL }},
    { &hf_mms_servicesSupportedCalled,
      { "servicesSupportedCalled", "mms.servicesSupportedCalled",
        FT_BYTES, BASE_NONE, NULL, 0,
        "ServiceSupportOptions", HFILL }},
    { &hf_mms_originalInvokeID,
      { "originalInvokeID", "mms.originalInvokeID",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_mms_errorClass,
      { "errorClass", "mms.errorClass",
        FT_UINT32, BASE_DEC, VALS(mms_T_errorClass_vals), 0,
        NULL, HFILL }},
    { &hf_mms_vmd_state,
      { "vmd-state", "mms.vmd_state",
        FT_INT32, BASE_DEC, VALS(mms_T_vmd_state_vals), 0,
        NULL, HFILL }},
    { &hf_mms_application_reference,
      { "application-reference", "mms.application_reference",
        FT_INT32, BASE_DEC, VALS(mms_T_application_reference_vals), 0,
        NULL, HFILL }},
    { &hf_mms_definition,
      { "definition", "mms.definition",
        FT_INT32, BASE_DEC, VALS(mms_T_definition_vals), 0,
        NULL, HFILL }},
    { &hf_mms_resource,
      { "resource", "mms.resource",
        FT_INT32, BASE_DEC, VALS(mms_T_resource_vals), 0,
        NULL, HFILL }},
    { &hf_mms_service,
      { "service", "mms.service",
        FT_INT32, BASE_DEC, VALS(mms_T_service_vals), 0,
        NULL, HFILL }},
    { &hf_mms_service_preempt,
      { "service-preempt", "mms.service_preempt",
        FT_INT32, BASE_DEC, VALS(mms_T_service_preempt_vals), 0,
        NULL, HFILL }},
    { &hf_mms_time_resolution,
      { "time-resolution", "mms.time_resolution",
        FT_INT32, BASE_DEC, VALS(mms_T_time_resolution_vals), 0,
        NULL, HFILL }},
    { &hf_mms_access,
      { "access", "mms.access",
        FT_INT32, BASE_DEC, VALS(mms_T_access_vals), 0,
        NULL, HFILL }},
    { &hf_mms_initiate,
      { "initiate", "mms.initiate",
        FT_INT32, BASE_DEC, VALS(mms_T_initiate_vals), 0,
        NULL, HFILL }},
    { &hf_mms_conclude,
      { "conclude", "mms.conclude",
        FT_INT32, BASE_DEC, VALS(mms_T_conclude_vals), 0,
        NULL, HFILL }},
    { &hf_mms_cancel,
      { "cancel", "mms.cancel",
        FT_INT32, BASE_DEC, VALS(mms_T_cancel_vals), 0,
        NULL, HFILL }},
    { &hf_mms_file,
      { "file", "mms.file",
        FT_INT32, BASE_DEC, VALS(mms_T_file_vals), 0,
        NULL, HFILL }},
    { &hf_mms_others,
      { "others", "mms.others",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_mms_additionalCode,
      { "additionalCode", "mms.additionalCode",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_mms_additionalDescription,
      { "additionalDescription", "mms.additionalDescription",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_mms_serviceSpecificInformation,
      { "serviceSpecificInformation", "mms.serviceSpecificInformation",
        FT_UINT32, BASE_DEC, VALS(mms_T_serviceSpecificInformation_vals), 0,
        NULL, HFILL }},
    { &hf_mms_obtainFile_02,
      { "obtainFile", "mms.obtainFile",
        FT_INT32, BASE_DEC, VALS(mms_ObtainFile_Error_vals), 0,
        "ObtainFile_Error", HFILL }},
    { &hf_mms_start_02,
      { "start", "mms.start",
        FT_INT32, BASE_DEC, VALS(mms_ProgramInvocationState_vals), 0,
        "Start_Error", HFILL }},
    { &hf_mms_stop_02,
      { "stop", "mms.stop",
        FT_INT32, BASE_DEC, VALS(mms_ProgramInvocationState_vals), 0,
        "Stop_Error", HFILL }},
    { &hf_mms_resume_02,
      { "resume", "mms.resume",
        FT_INT32, BASE_DEC, VALS(mms_ProgramInvocationState_vals), 0,
        "Resume_Error", HFILL }},
    { &hf_mms_reset_02,
      { "reset", "mms.reset",
        FT_INT32, BASE_DEC, VALS(mms_ProgramInvocationState_vals), 0,
        "Reset_Error", HFILL }},
    { &hf_mms_deleteVariableAccess_02,
      { "deleteVariableAccess", "mms.deleteVariableAccess",
        FT_INT32, BASE_DEC, NULL, 0,
        "DeleteVariableAccess_Error", HFILL }},
    { &hf_mms_deleteNamedVariableList_02,
      { "deleteNamedVariableList", "mms.deleteNamedVariableList",
        FT_INT32, BASE_DEC, NULL, 0,
        "DeleteNamedVariableList_Error", HFILL }},
    { &hf_mms_deleteNamedType_02,
      { "deleteNamedType", "mms.deleteNamedType",
        FT_INT32, BASE_DEC, NULL, 0,
        "DeleteNamedType_Error", HFILL }},
    { &hf_mms_defineEventEnrollment_Error,
      { "defineEventEnrollment-Error", "mms.defineEventEnrollment_Error",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        NULL, HFILL }},
    { &hf_mms_fileRename_02,
      { "fileRename", "mms.fileRename",
        FT_INT32, BASE_DEC, VALS(mms_FileRename_Error_vals), 0,
        "FileRename_Error", HFILL }},
    { &hf_mms_rejectReason,
      { "rejectReason", "mms.rejectReason",
        FT_UINT32, BASE_DEC, VALS(mms_T_rejectReason_vals), 0,
        NULL, HFILL }},
    { &hf_mms_confirmed_requestPDU,
      { "confirmed-requestPDU", "mms.confirmed_requestPDU",
        FT_INT32, BASE_DEC, VALS(mms_T_confirmed_requestPDU_vals), 0,
        NULL, HFILL }},
    { &hf_mms_confirmed_responsePDU,
      { "confirmed-responsePDU", "mms.confirmed_responsePDU",
        FT_INT32, BASE_DEC, VALS(mms_T_confirmed_responsePDU_vals), 0,
        NULL, HFILL }},
    { &hf_mms_confirmed_errorPDU,
      { "confirmed-errorPDU", "mms.confirmed_errorPDU",
        FT_INT32, BASE_DEC, VALS(mms_T_confirmed_errorPDU_vals), 0,
        NULL, HFILL }},
    { &hf_mms_unconfirmedPDU,
      { "unconfirmedPDU", "mms.unconfirmedPDU",
        FT_INT32, BASE_DEC, VALS(mms_T_unconfirmedPDU_vals), 0,
        NULL, HFILL }},
    { &hf_mms_pdu_error,
      { "pdu-error", "mms.pdu_error",
        FT_INT32, BASE_DEC, VALS(mms_T_pdu_error_vals), 0,
        NULL, HFILL }},
    { &hf_mms_cancel_requestPDU,
      { "cancel-requestPDU", "mms.cancel_requestPDU",
        FT_INT32, BASE_DEC, VALS(mms_T_cancel_requestPDU_vals), 0,
        NULL, HFILL }},
    { &hf_mms_cancel_responsePDU,
      { "cancel-responsePDU", "mms.cancel_responsePDU",
        FT_INT32, BASE_DEC, VALS(mms_T_cancel_responsePDU_vals), 0,
        NULL, HFILL }},
    { &hf_mms_cancel_errorPDU,
      { "cancel-errorPDU", "mms.cancel_errorPDU",
        FT_INT32, BASE_DEC, VALS(mms_T_cancel_errorPDU_vals), 0,
        NULL, HFILL }},
    { &hf_mms_conclude_requestPDU,
      { "conclude-requestPDU", "mms.conclude_requestPDU",
        FT_INT32, BASE_DEC, VALS(mms_T_conclude_requestPDU_vals), 0,
        NULL, HFILL }},
    { &hf_mms_conclude_responsePDU,
      { "conclude-responsePDU", "mms.conclude_responsePDU",
        FT_INT32, BASE_DEC, VALS(mms_T_conclude_responsePDU_vals), 0,
        NULL, HFILL }},
    { &hf_mms_conclude_errorPDU,
      { "conclude-errorPDU", "mms.conclude_errorPDU",
        FT_INT32, BASE_DEC, VALS(mms_T_conclude_errorPDU_vals), 0,
        NULL, HFILL }},
    { &hf_mms_vmdLogicalStatus,
      { "vmdLogicalStatus", "mms.vmdLogicalStatus",
        FT_INT32, BASE_DEC, VALS(mms_T_vmdLogicalStatus_vals), 0,
        NULL, HFILL }},
    { &hf_mms_vmdPhysicalStatus,
      { "vmdPhysicalStatus", "mms.vmdPhysicalStatus",
        FT_INT32, BASE_DEC, VALS(mms_T_vmdPhysicalStatus_vals), 0,
        NULL, HFILL }},
    { &hf_mms_localDetail,
      { "localDetail", "mms.localDetail",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_0_128", HFILL }},
    { &hf_mms_extendedObjectClass,
      { "extendedObjectClass", "mms.extendedObjectClass",
        FT_UINT32, BASE_DEC, VALS(mms_T_extendedObjectClass_vals), 0,
        NULL, HFILL }},
    { &hf_mms_objectClass,
      { "objectClass", "mms.objectClass",
        FT_INT32, BASE_DEC, VALS(mms_T_objectClass_vals), 0,
        NULL, HFILL }},
    { &hf_mms_objectScope,
      { "objectScope", "mms.objectScope",
        FT_UINT32, BASE_DEC, VALS(mms_T_objectScope_vals), 0,
        NULL, HFILL }},
    { &hf_mms_vmdSpecific,
      { "vmdSpecific", "mms.vmdSpecific_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_domainSpecific,
      { "domainSpecific", "mms.domainSpecific",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_mms_aaSpecific,
      { "aaSpecific", "mms.aaSpecific_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_continueAfter,
      { "continueAfter", "mms.continueAfter",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_mms_listOfIdentifier,
      { "listOfIdentifier", "mms.listOfIdentifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Identifier", HFILL }},
    { &hf_mms_listOfIdentifier_item,
      { "Identifier", "mms.Identifier",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_moreFollows,
      { "moreFollows", "mms.moreFollows",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mms_vendorName,
      { "vendorName", "mms.vendorName",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_mms_modelName,
      { "modelName", "mms.modelName",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_mms_revision,
      { "revision", "mms.revision",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_mms_listOfAbstractSyntaxes,
      { "listOfAbstractSyntaxes", "mms.listOfAbstractSyntaxes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_listOfAbstractSyntaxes_item,
      { "listOfAbstractSyntaxes item", "mms.listOfAbstractSyntaxes_item",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_mms_extendedObjectClass_01,
      { "extendedObjectClass", "mms.extendedObjectClass",
        FT_UINT32, BASE_DEC, VALS(mms_T_extendedObjectClass_01_vals), 0,
        "T_extendedObjectClass_01", HFILL }},
    { &hf_mms_objectClass_01,
      { "objectClass", "mms.objectClass",
        FT_INT32, BASE_DEC, VALS(mms_T_objectClass_01_vals), 0,
        "T_objectClass_01", HFILL }},
    { &hf_mms_currentName,
      { "currentName", "mms.currentName",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_mms_newIdentifier,
      { "newIdentifier", "mms.newIdentifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_mms_continueAfter_01,
      { "continueAfter", "mms.continueAfter",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_mms_listOfCapabilities,
      { "listOfCapabilities", "mms.listOfCapabilities",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_listOfCapabilities_item,
      { "listOfCapabilities item", "mms.listOfCapabilities_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_mms_domainName,
      { "domainName", "mms.domainName",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_mms_listOfCapabilities_01,
      { "listOfCapabilities", "mms.listOfCapabilities",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_listOfCapabilities_01", HFILL }},
    { &hf_mms_sharable,
      { "sharable", "mms.sharable",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mms_loadData,
      { "loadData", "mms.loadData",
        FT_UINT32, BASE_DEC, VALS(mms_T_loadData_vals), 0,
        NULL, HFILL }},
    { &hf_mms_non_coded,
      { "non-coded", "mms.non_coded",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_mms_coded,
      { "coded", "mms.coded_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNALt", HFILL }},
    { &hf_mms_discard,
      { "discard", "mms.discard_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServiceError", HFILL }},
    { &hf_mms_ulsmID,
      { "ulsmID", "mms.ulsmID",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer32", HFILL }},
    { &hf_mms_listOfCapabilities_02,
      { "listOfCapabilities", "mms.listOfCapabilities",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_listOfCapabilities_02", HFILL }},
    { &hf_mms_loadData_01,
      { "loadData", "mms.loadData",
        FT_UINT32, BASE_DEC, VALS(mms_T_loadData_01_vals), 0,
        "T_loadData_01", HFILL }},
    { &hf_mms_listOfCapabilities_03,
      { "listOfCapabilities", "mms.listOfCapabilities",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_listOfCapabilities_03", HFILL }},
    { &hf_mms_fileName,
      { "fileName", "mms.fileName",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_listOfCapabilities_04,
      { "listOfCapabilities", "mms.listOfCapabilities",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_listOfCapabilities_04", HFILL }},
    { &hf_mms_thirdParty,
      { "thirdParty", "mms.thirdParty_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ApplicationReference", HFILL }},
    { &hf_mms_filenName,
      { "filenName", "mms.filenName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FileName", HFILL }},
    { &hf_mms_listOfCapabilities_05,
      { "listOfCapabilities", "mms.listOfCapabilities",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_listOfCapabilities_05", HFILL }},
    { &hf_mms_state,
      { "state", "mms.state",
        FT_INT32, BASE_DEC, VALS(mms_DomainState_vals), 0,
        "DomainState", HFILL }},
    { &hf_mms_mmsDeletable,
      { "mmsDeletable", "mms.mmsDeletable",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mms_listOfProgramInvocations,
      { "listOfProgramInvocations", "mms.listOfProgramInvocations",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Identifier", HFILL }},
    { &hf_mms_listOfProgramInvocations_item,
      { "Identifier", "mms.Identifier",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_uploadInProgress,
      { "uploadInProgress", "mms.uploadInProgress",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer8", HFILL }},
    { &hf_mms_programInvocationName,
      { "programInvocationName", "mms.programInvocationName",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_mms_listOfDomainName,
      { "listOfDomainName", "mms.listOfDomainName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Identifier", HFILL }},
    { &hf_mms_listOfDomainName_item,
      { "Identifier", "mms.Identifier",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_reusable,
      { "reusable", "mms.reusable",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mms_monitorType,
      { "monitorType", "mms.monitorType",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mms_executionArgument,
      { "executionArgument", "mms.executionArgument",
        FT_UINT32, BASE_DEC, VALS(mms_T_executionArgument_vals), 0,
        NULL, HFILL }},
    { &hf_mms_simpleString,
      { "simpleString", "mms.simpleString",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_mms_encodedString,
      { "encodedString", "mms.encodedString_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNALt", HFILL }},
    { &hf_mms_executionArgument_01,
      { "executionArgument", "mms.executionArgument",
        FT_UINT32, BASE_DEC, VALS(mms_T_executionArgument_01_vals), 0,
        "T_executionArgument_01", HFILL }},
    { &hf_mms_state_01,
      { "state", "mms.state",
        FT_INT32, BASE_DEC, VALS(mms_ProgramInvocationState_vals), 0,
        "ProgramInvocationState", HFILL }},
    { &hf_mms_listOfDomainNames,
      { "listOfDomainNames", "mms.listOfDomainNames",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Identifier", HFILL }},
    { &hf_mms_listOfDomainNames_item,
      { "Identifier", "mms.Identifier",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_monitor,
      { "monitor", "mms.monitor",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mms_startArgument,
      { "startArgument", "mms.startArgument",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_mms_executionArgument_02,
      { "executionArgument", "mms.executionArgument",
        FT_UINT32, BASE_DEC, VALS(mms_T_executionArgument_02_vals), 0,
        "T_executionArgument_02", HFILL }},
    { &hf_mms_typeName,
      { "typeName", "mms.typeName",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_mms_array,
      { "array", "mms.array_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_packed,
      { "packed", "mms.packed",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mms_numberOfElements,
      { "numberOfElements", "mms.numberOfElements",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_mms_elementType,
      { "elementType", "mms.elementType",
        FT_UINT32, BASE_DEC, VALS(mms_TypeSpecification_vals), 0,
        "TypeSpecification", HFILL }},
    { &hf_mms_structure,
      { "structure", "mms.structure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_components,
      { "components", "mms.components",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_components_item,
      { "components item", "mms.components_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_componentName,
      { "componentName", "mms.componentName",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_mms_componentType,
      { "componentType", "mms.componentType",
        FT_UINT32, BASE_DEC, VALS(mms_TypeSpecification_vals), 0,
        "TypeSpecification", HFILL }},
    { &hf_mms_boolean,
      { "boolean", "mms.boolean_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_bit_string,
      { "bit-string", "mms.bit_string",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer32", HFILL }},
    { &hf_mms_integer,
      { "integer", "mms.integer",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned8", HFILL }},
    { &hf_mms_unsigned,
      { "unsigned", "mms.unsigned",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned8", HFILL }},
    { &hf_mms_octet_string,
      { "octet-string", "mms.octet_string",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer32", HFILL }},
    { &hf_mms_visible_string,
      { "visible-string", "mms.visible_string",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer32", HFILL }},
    { &hf_mms_generalized_time,
      { "generalized-time", "mms.generalized_time_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_binary_time,
      { "binary-time", "mms.binary_time",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mms_bcd,
      { "bcd", "mms.bcd",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned8", HFILL }},
    { &hf_mms_objId,
      { "objId", "mms.objId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_AlternateAccess_item,
      { "AlternateAccess item", "mms.AlternateAccess_item",
        FT_UINT32, BASE_DEC, VALS(mms_AlternateAccess_item_vals), 0,
        NULL, HFILL }},
    { &hf_mms_unnamed,
      { "unnamed", "mms.unnamed",
        FT_UINT32, BASE_DEC, VALS(mms_AlternateAccessSelection_vals), 0,
        "AlternateAccessSelection", HFILL }},
    { &hf_mms_named,
      { "named", "mms.named_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_accesst,
      { "accesst", "mms.accesst",
        FT_UINT32, BASE_DEC, VALS(mms_AlternateAccessSelection_vals), 0,
        "AlternateAccessSelection", HFILL }},
    { &hf_mms_selectAlternateAccess,
      { "selectAlternateAccess", "mms.selectAlternateAccess_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_accessSelection,
      { "accessSelection", "mms.accessSelection",
        FT_UINT32, BASE_DEC, VALS(mms_T_accessSelection_vals), 0,
        NULL, HFILL }},
    { &hf_mms_component,
      { "component", "mms.component",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_mms_index,
      { "index", "mms.index",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_mms_indexRange,
      { "indexRange", "mms.indexRange_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_lowIndex,
      { "lowIndex", "mms.lowIndex",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_mms_allElements,
      { "allElements", "mms.allElements_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_alternateAccess,
      { "alternateAccess", "mms.alternateAccess",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_selectAccess,
      { "selectAccess", "mms.selectAccess",
        FT_UINT32, BASE_DEC, VALS(mms_T_selectAccess_vals), 0,
        NULL, HFILL }},
    { &hf_mms_indexRange_01,
      { "indexRange", "mms.indexRange_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_indexRange_01", HFILL }},
    { &hf_mms_nmberOfElements,
      { "nmberOfElements", "mms.nmberOfElements",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_mms_specificationWithResult,
      { "specificationWithResult", "mms.specificationWithResult",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mms_variableAccessSpecificatn,
      { "variableAccessSpecificatn", "mms.variableAccessSpecificatn",
        FT_UINT32, BASE_DEC, VALS(mms_VariableAccessSpecification_vals), 0,
        "VariableAccessSpecification", HFILL }},
    { &hf_mms_listOfAccessResult,
      { "listOfAccessResult", "mms.listOfAccessResult",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_AccessResult", HFILL }},
    { &hf_mms_listOfAccessResult_item,
      { "AccessResult", "mms.AccessResult",
        FT_UINT32, BASE_DEC, VALS(mms_AccessResult_vals), 0,
        NULL, HFILL }},
    { &hf_mms_listOfData,
      { "listOfData", "mms.listOfData",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Data", HFILL }},
    { &hf_mms_listOfData_item,
      { "Data", "mms.Data",
        FT_UINT32, BASE_DEC, VALS(mms_Data_vals), 0,
        NULL, HFILL }},
    { &hf_mms_Write_Response_item,
      { "Write-Response item", "mms.Write_Response_item",
        FT_UINT32, BASE_DEC, VALS(mms_Write_Response_item_vals), 0,
        NULL, HFILL }},
    { &hf_mms_failure,
      { "failure", "mms.failure",
        FT_INT32, BASE_DEC, VALS(mms_DataAccessError_vals), 0,
        "DataAccessError", HFILL }},
    { &hf_mms_success,
      { "success", "mms.success_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_variableAccessSpecification,
      { "variableAccessSpecification", "mms.variableAccessSpecification",
        FT_UINT32, BASE_DEC, VALS(mms_VariableAccessSpecification_vals), 0,
        NULL, HFILL }},
    { &hf_mms_name,
      { "name", "mms.name",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_mms_address,
      { "address", "mms.address",
        FT_UINT32, BASE_DEC, VALS(mms_Address_vals), 0,
        NULL, HFILL }},
    { &hf_mms_typeSpecification,
      { "typeSpecification", "mms.typeSpecification",
        FT_UINT32, BASE_DEC, VALS(mms_TypeSpecification_vals), 0,
        NULL, HFILL }},
    { &hf_mms_variableName,
      { "variableName", "mms.variableName",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_mms_scatteredAccessName,
      { "scatteredAccessName", "mms.scatteredAccessName",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_mms_scatteredAccessDescription,
      { "scatteredAccessDescription", "mms.scatteredAccessDescription",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_scopeOfDelete,
      { "scopeOfDelete", "mms.scopeOfDelete",
        FT_INT32, BASE_DEC, VALS(mms_T_scopeOfDelete_vals), 0,
        NULL, HFILL }},
    { &hf_mms_listOfName,
      { "listOfName", "mms.listOfName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ObjectName", HFILL }},
    { &hf_mms_listOfName_item,
      { "ObjectName", "mms.ObjectName",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        NULL, HFILL }},
    { &hf_mms_numberMatched,
      { "numberMatched", "mms.numberMatched",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_mms_numberDeleted,
      { "numberDeleted", "mms.numberDeleted",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_mms_variableListName,
      { "variableListName", "mms.variableListName",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_mms_listOfVariable,
      { "listOfVariable", "mms.listOfVariable",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_listOfVariable_item,
      { "listOfVariable item", "mms.listOfVariable_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_variableSpecification,
      { "variableSpecification", "mms.variableSpecification",
        FT_UINT32, BASE_DEC, VALS(mms_VariableSpecification_vals), 0,
        NULL, HFILL }},
    { &hf_mms_listOfVariable_01,
      { "listOfVariable", "mms.listOfVariable",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_listOfVariable_01", HFILL }},
    { &hf_mms_listOfVariable_item_01,
      { "listOfVariable item", "mms.listOfVariable_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_listOfVariable_item_01", HFILL }},
    { &hf_mms_scopeOfDelete_01,
      { "scopeOfDelete", "mms.scopeOfDelete",
        FT_INT32, BASE_DEC, VALS(mms_T_scopeOfDelete_01_vals), 0,
        "T_scopeOfDelete_01", HFILL }},
    { &hf_mms_listOfVariableListName,
      { "listOfVariableListName", "mms.listOfVariableListName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ObjectName", HFILL }},
    { &hf_mms_listOfVariableListName_item,
      { "ObjectName", "mms.ObjectName",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        NULL, HFILL }},
    { &hf_mms_scopeOfDelete_02,
      { "scopeOfDelete", "mms.scopeOfDelete",
        FT_INT32, BASE_DEC, VALS(mms_T_scopeOfDelete_02_vals), 0,
        "T_scopeOfDelete_02", HFILL }},
    { &hf_mms_listOfTypeName,
      { "listOfTypeName", "mms.listOfTypeName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ObjectName", HFILL }},
    { &hf_mms_listOfTypeName_item,
      { "ObjectName", "mms.ObjectName",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        NULL, HFILL }},
    { &hf_mms_success_01,
      { "success", "mms.success",
        FT_UINT32, BASE_DEC, VALS(mms_Data_vals), 0,
        "Data", HFILL }},
    { &hf_mms_array_01,
      { "array", "mms.array",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Data", HFILL }},
    { &hf_mms_array_item,
      { "Data", "mms.Data",
        FT_UINT32, BASE_DEC, VALS(mms_Data_vals), 0,
        NULL, HFILL }},
    { &hf_mms_structure_01,
      { "structure", "mms.structure",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Data", HFILL }},
    { &hf_mms_structure_item,
      { "Data", "mms.Data",
        FT_UINT32, BASE_DEC, VALS(mms_Data_vals), 0,
        NULL, HFILL }},
    { &hf_mms_boolean_01,
      { "boolean", "mms.boolean",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_bit_string_01,
      { "bit-string", "mms.bit_string",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_integer_01,
      { "integer", "mms.integer",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_unsigned_01,
      { "unsigned", "mms.unsigned",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_mms_floating_point,
      { "floating-point", "mms.floating_point",
        FT_BYTES, BASE_NONE, NULL, 0,
        "FloatingPoint", HFILL }},
    { &hf_mms_octet_string_01,
      { "octet-string", "mms.octet_string",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_visible_string_01,
      { "visible-string", "mms.visible_string",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_mms_binary_time_01,
      { "binary-time", "mms.binary_time",
        FT_STRING, BASE_NONE, NULL, 0,
        "TimeOfDay", HFILL }},
    { &hf_mms_bcd_01,
      { "bcd", "mms.bcd",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_mms_booleanArray,
      { "booleanArray", "mms.booleanArray",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_mms_objId_01,
      { "objId", "mms.objId",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_mms_mMSString,
      { "mMSString", "mms.mMSString",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_utc_time,
      { "utc-time", "mms.utc_time",
        FT_STRING, BASE_NONE, NULL, 0,
        "UtcTime", HFILL }},
    { &hf_mms_listOfVariable_02,
      { "listOfVariable", "mms.listOfVariable",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_listOfVariable_02", HFILL }},
    { &hf_mms_listOfVariable_item_02,
      { "listOfVariable item", "mms.listOfVariable_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_listOfVariable_item_02", HFILL }},
    { &hf_mms_ScatteredAccessDescription_item,
      { "ScatteredAccessDescription item", "mms.ScatteredAccessDescription_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_variableDescription,
      { "variableDescription", "mms.variableDescription_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_invalidated,
      { "invalidated", "mms.invalidated_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_numericAddress,
      { "numericAddress", "mms.numericAddress",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_mms_symbolicAddress,
      { "symbolicAddress", "mms.symbolicAddress",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_mms_unconstrainedAddress,
      { "unconstrainedAddress", "mms.unconstrainedAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_mms_semaphoreName,
      { "semaphoreName", "mms.semaphoreName",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_mms_namedToken,
      { "namedToken", "mms.namedToken",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_mms_priority,
      { "priority", "mms.priority",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_acceptableDelay,
      { "acceptableDelay", "mms.acceptableDelay",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_mms_controlTimeOut,
      { "controlTimeOut", "mms.controlTimeOut",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_mms_abortOnTimeOut,
      { "abortOnTimeOut", "mms.abortOnTimeOut",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mms_relinquishIfConnectionLost,
      { "relinquishIfConnectionLost", "mms.relinquishIfConnectionLost",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mms_applicationToPreempt,
      { "applicationToPreempt", "mms.applicationToPreempt_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ApplicationReference", HFILL }},
    { &hf_mms_noResult,
      { "noResult", "mms.noResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_numbersOfTokens,
      { "numbersOfTokens", "mms.numbersOfTokens",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned16", HFILL }},
    { &hf_mms_class,
      { "class", "mms.class",
        FT_INT32, BASE_DEC, VALS(mms_T_class_vals), 0,
        NULL, HFILL }},
    { &hf_mms_numberOfTokens,
      { "numberOfTokens", "mms.numberOfTokens",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned16", HFILL }},
    { &hf_mms_numberOfOwnedTokens,
      { "numberOfOwnedTokens", "mms.numberOfOwnedTokens",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned16", HFILL }},
    { &hf_mms_numberOfHungTokens,
      { "numberOfHungTokens", "mms.numberOfHungTokens",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned16", HFILL }},
    { &hf_mms_nameToStartAfter,
      { "nameToStartAfter", "mms.nameToStartAfter",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_mms_listOfNamedTokens,
      { "listOfNamedTokens", "mms.listOfNamedTokens",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_listOfNamedTokens_item,
      { "listOfNamedTokens item", "mms.listOfNamedTokens_item",
        FT_UINT32, BASE_DEC, VALS(mms_T_listOfNamedTokens_item_vals), 0,
        NULL, HFILL }},
    { &hf_mms_freeNamedToken,
      { "freeNamedToken", "mms.freeNamedToken",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_mms_ownedNamedToken,
      { "ownedNamedToken", "mms.ownedNamedToken",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_mms_hungNamedToken,
      { "hungNamedToken", "mms.hungNamedToken",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_mms_state_02,
      { "state", "mms.state",
        FT_INT32, BASE_DEC, VALS(mms_T_state_vals), 0,
        NULL, HFILL }},
    { &hf_mms_entryIdToStartAfter,
      { "entryIdToStartAfter", "mms.entryIdToStartAfter",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_mms_listOfSemaphoreEntry,
      { "listOfSemaphoreEntry", "mms.listOfSemaphoreEntry",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_SemaphoreEntry", HFILL }},
    { &hf_mms_listOfSemaphoreEntry_item,
      { "SemaphoreEntry", "mms.SemaphoreEntry_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_entryId,
      { "entryId", "mms.entryId",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_mms_entryClass,
      { "entryClass", "mms.entryClass",
        FT_INT32, BASE_DEC, VALS(mms_T_entryClass_vals), 0,
        NULL, HFILL }},
    { &hf_mms_applicationReference,
      { "applicationReference", "mms.applicationReference_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_remainingTimeOut,
      { "remainingTimeOut", "mms.remainingTimeOut",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_mms_operatorStationName,
      { "operatorStationName", "mms.operatorStationName",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_mms_echo,
      { "echo", "mms.echo",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mms_listOfPromptData,
      { "listOfPromptData", "mms.listOfPromptData",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_listOfPromptData_item,
      { "listOfPromptData item", "mms.listOfPromptData_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_mms_inputTimeOut,
      { "inputTimeOut", "mms.inputTimeOut",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_mms_listOfOutputData,
      { "listOfOutputData", "mms.listOfOutputData",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_listOfOutputData_item,
      { "listOfOutputData item", "mms.listOfOutputData_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_mms_eventConditionName,
      { "eventConditionName", "mms.eventConditionName",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_mms_class_01,
      { "class", "mms.class",
        FT_INT32, BASE_DEC, VALS(mms_EC_Class_vals), 0,
        "EC_Class", HFILL }},
    { &hf_mms_prio_rity,
      { "prio-rity", "mms.prio_rity",
        FT_INT32, BASE_DEC, NULL, 0,
        "Priority", HFILL }},
    { &hf_mms_severity,
      { "severity", "mms.severity",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned8", HFILL }},
    { &hf_mms_alarmSummaryReports,
      { "alarmSummaryReports", "mms.alarmSummaryReports",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mms_monitoredVariable,
      { "monitoredVariable", "mms.monitoredVariable",
        FT_UINT32, BASE_DEC, VALS(mms_VariableSpecification_vals), 0,
        "VariableSpecification", HFILL }},
    { &hf_mms_evaluationInterval,
      { "evaluationInterval", "mms.evaluationInterval",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_mms_specific,
      { "specific", "mms.specific",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ObjectName", HFILL }},
    { &hf_mms_specific_item,
      { "ObjectName", "mms.ObjectName",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        NULL, HFILL }},
    { &hf_mms_aa_specific_01,
      { "aa-specific", "mms.aa_specific_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_domain,
      { "domain", "mms.domain",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_mms_vmd,
      { "vmd", "mms.vmd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_monitoredVariable_01,
      { "monitoredVariable", "mms.monitoredVariable",
        FT_UINT32, BASE_DEC, VALS(mms_T_monitoredVariable_vals), 0,
        NULL, HFILL }},
    { &hf_mms_variableReference,
      { "variableReference", "mms.variableReference",
        FT_UINT32, BASE_DEC, VALS(mms_VariableSpecification_vals), 0,
        "VariableSpecification", HFILL }},
    { &hf_mms_undefined,
      { "undefined", "mms.undefined_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_currentState,
      { "currentState", "mms.currentState",
        FT_INT32, BASE_DEC, VALS(mms_EC_State_vals), 0,
        "EC_State", HFILL }},
    { &hf_mms_numberOfEventEnrollments,
      { "numberOfEventEnrollments", "mms.numberOfEventEnrollments",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_mms_enabled,
      { "enabled", "mms.enabled",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mms_timeOfLastTransitionToActive,
      { "timeOfLastTransitionToActive", "mms.timeOfLastTransitionToActive",
        FT_UINT32, BASE_DEC, VALS(mms_EventTime_vals), 0,
        "EventTime", HFILL }},
    { &hf_mms_timeOfLastTransitionToIdle,
      { "timeOfLastTransitionToIdle", "mms.timeOfLastTransitionToIdle",
        FT_UINT32, BASE_DEC, VALS(mms_EventTime_vals), 0,
        "EventTime", HFILL }},
    { &hf_mms_eventActionName,
      { "eventActionName", "mms.eventActionName",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_mms_eventEnrollmentName,
      { "eventEnrollmentName", "mms.eventEnrollmentName",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_mms_eventConditionTransition,
      { "eventConditionTransition", "mms.eventConditionTransition",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Transitions", HFILL }},
    { &hf_mms_alarmAcknowledgementRule,
      { "alarmAcknowledgementRule", "mms.alarmAcknowledgementRule",
        FT_INT32, BASE_DEC, VALS(mms_AlarmAckRule_vals), 0,
        "AlarmAckRule", HFILL }},
    { &hf_mms_clientApplication,
      { "clientApplication", "mms.clientApplication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ApplicationReference", HFILL }},
    { &hf_mms_ec,
      { "ec", "mms.ec",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_mms_ea,
      { "ea", "mms.ea",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_mms_scopeOfRequest,
      { "scopeOfRequest", "mms.scopeOfRequest",
        FT_INT32, BASE_DEC, VALS(mms_T_scopeOfRequest_vals), 0,
        NULL, HFILL }},
    { &hf_mms_eventEnrollmentNames,
      { "eventEnrollmentNames", "mms.eventEnrollmentNames",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ObjectName", HFILL }},
    { &hf_mms_eventEnrollmentNames_item,
      { "ObjectName", "mms.ObjectName",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        NULL, HFILL }},
    { &hf_mms_continueAfter_02,
      { "continueAfter", "mms.continueAfter",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_mms_eventConditionName_01,
      { "eventConditionName", "mms.eventConditionName",
        FT_UINT32, BASE_DEC, VALS(mms_T_eventConditionName_vals), 0,
        NULL, HFILL }},
    { &hf_mms_eventCondition,
      { "eventCondition", "mms.eventCondition",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_mms_eventActionName_01,
      { "eventActionName", "mms.eventActionName",
        FT_UINT32, BASE_DEC, VALS(mms_T_eventActionName_vals), 0,
        NULL, HFILL }},
    { &hf_mms_eventAction,
      { "eventAction", "mms.eventAction",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_mms_enrollmentClass,
      { "enrollmentClass", "mms.enrollmentClass",
        FT_INT32, BASE_DEC, VALS(mms_EE_Class_vals), 0,
        "EE_Class", HFILL }},
    { &hf_mms_duration,
      { "duration", "mms.duration",
        FT_INT32, BASE_DEC, VALS(mms_EE_Duration_vals), 0,
        "EE_Duration", HFILL }},
    { &hf_mms_remainingAcceptableDelay,
      { "remainingAcceptableDelay", "mms.remainingAcceptableDelay",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_mms_listOfEventEnrollment,
      { "listOfEventEnrollment", "mms.listOfEventEnrollment",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_EventEnrollment", HFILL }},
    { &hf_mms_listOfEventEnrollment_item,
      { "EventEnrollment", "mms.EventEnrollment_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_eventConditionTransitions,
      { "eventConditionTransitions", "mms.eventConditionTransitions",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Transitions", HFILL }},
    { &hf_mms_notificationLost,
      { "notificationLost", "mms.notificationLost",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mms_alarmAcknowledgmentRule,
      { "alarmAcknowledgmentRule", "mms.alarmAcknowledgmentRule",
        FT_INT32, BASE_DEC, VALS(mms_AlarmAckRule_vals), 0,
        "AlarmAckRule", HFILL }},
    { &hf_mms_currentState_01,
      { "currentState", "mms.currentState",
        FT_INT32, BASE_DEC, VALS(mms_EE_State_vals), 0,
        "EE_State", HFILL }},
    { &hf_mms_currentState_02,
      { "currentState", "mms.currentState",
        FT_UINT32, BASE_DEC, VALS(mms_T_currentState_vals), 0,
        NULL, HFILL }},
    { &hf_mms_state_03,
      { "state", "mms.state",
        FT_INT32, BASE_DEC, VALS(mms_EE_State_vals), 0,
        "EE_State", HFILL }},
    { &hf_mms_transitionTime,
      { "transitionTime", "mms.transitionTime",
        FT_UINT32, BASE_DEC, VALS(mms_EventTime_vals), 0,
        "EventTime", HFILL }},
    { &hf_mms_acknowledgedState,
      { "acknowledgedState", "mms.acknowledgedState",
        FT_INT32, BASE_DEC, VALS(mms_EC_State_vals), 0,
        "EC_State", HFILL }},
    { &hf_mms_timeOfAcknowledgedTransition,
      { "timeOfAcknowledgedTransition", "mms.timeOfAcknowledgedTransition",
        FT_UINT32, BASE_DEC, VALS(mms_EventTime_vals), 0,
        "EventTime", HFILL }},
    { &hf_mms_enrollmentsOnly,
      { "enrollmentsOnly", "mms.enrollmentsOnly",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mms_activeAlarmsOnly,
      { "activeAlarmsOnly", "mms.activeAlarmsOnly",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_mms_acknowledgmentFilter,
      { "acknowledgmentFilter", "mms.acknowledgmentFilter",
        FT_INT32, BASE_DEC, VALS(mms_T_acknowledgmentFilter_vals), 0,
        NULL, HFILL }},
    { &hf_mms_severityFilter,
      { "severityFilter", "mms.severityFilter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_mostSevere,
      { "mostSevere", "mms.mostSevere",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned8", HFILL }},
    { &hf_mms_leastSevere,
      { "leastSevere", "mms.leastSevere",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned8", HFILL }},
    { &hf_mms_listOfAlarmSummary,
      { "listOfAlarmSummary", "mms.listOfAlarmSummary",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_AlarmSummary", HFILL }},
    { &hf_mms_listOfAlarmSummary_item,
      { "AlarmSummary", "mms.AlarmSummary_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_unacknowledgedState,
      { "unacknowledgedState", "mms.unacknowledgedState",
        FT_INT32, BASE_DEC, VALS(mms_T_unacknowledgedState_vals), 0,
        NULL, HFILL }},
    { &hf_mms_acknowledgmentFilter_01,
      { "acknowledgmentFilter", "mms.acknowledgmentFilter",
        FT_INT32, BASE_DEC, VALS(mms_T_acknowledgmentFilter_01_vals), 0,
        "T_acknowledgmentFilter_01", HFILL }},
    { &hf_mms_severityFilter_01,
      { "severityFilter", "mms.severityFilter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_severityFilter_01", HFILL }},
    { &hf_mms_listOfAlarmEnrollmentSummary,
      { "listOfAlarmEnrollmentSummary", "mms.listOfAlarmEnrollmentSummary",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_AlarmEnrollmentSummary", HFILL }},
    { &hf_mms_listOfAlarmEnrollmentSummary_item,
      { "AlarmEnrollmentSummary", "mms.AlarmEnrollmentSummary_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_enrollementState,
      { "enrollementState", "mms.enrollementState",
        FT_INT32, BASE_DEC, VALS(mms_EE_State_vals), 0,
        "EE_State", HFILL }},
    { &hf_mms_timeActiveAcknowledged,
      { "timeActiveAcknowledged", "mms.timeActiveAcknowledged",
        FT_UINT32, BASE_DEC, VALS(mms_EventTime_vals), 0,
        "EventTime", HFILL }},
    { &hf_mms_timeIdleAcknowledged,
      { "timeIdleAcknowledged", "mms.timeIdleAcknowledged",
        FT_UINT32, BASE_DEC, VALS(mms_EventTime_vals), 0,
        "EventTime", HFILL }},
    { &hf_mms_eventConditionName_02,
      { "eventConditionName", "mms.eventConditionName",
        FT_UINT32, BASE_DEC, VALS(mms_T_eventConditionName_01_vals), 0,
        "T_eventConditionName_01", HFILL }},
    { &hf_mms_actionResult,
      { "actionResult", "mms.actionResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_eventActioName,
      { "eventActioName", "mms.eventActioName",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_mms_eventActionResult,
      { "eventActionResult", "mms.eventActionResult",
        FT_UINT32, BASE_DEC, VALS(mms_T_eventActionResult_vals), 0,
        NULL, HFILL }},
    { &hf_mms_success_02,
      { "success", "mms.success",
        FT_UINT32, BASE_DEC, VALS(mms_ConfirmedServiceResponse_vals), 0,
        "ConfirmedServiceResponse", HFILL }},
    { &hf_mms_failure_01,
      { "failure", "mms.failure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServiceError", HFILL }},
    { &hf_mms_causingTransitions,
      { "causingTransitions", "mms.causingTransitions",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Transitions", HFILL }},
    { &hf_mms_timeOfDayT,
      { "timeOfDayT", "mms.timeOfDayT",
        FT_STRING, BASE_NONE, NULL, 0,
        "TimeOfDay", HFILL }},
    { &hf_mms_timeSequenceIdentifier,
      { "timeSequenceIdentifier", "mms.timeSequenceIdentifier",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_mms_journalName,
      { "journalName", "mms.journalName",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_mms_rangeStartSpecification,
      { "rangeStartSpecification", "mms.rangeStartSpecification",
        FT_UINT32, BASE_DEC, VALS(mms_T_rangeStartSpecification_vals), 0,
        NULL, HFILL }},
    { &hf_mms_startingTime,
      { "startingTime", "mms.startingTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "TimeOfDay", HFILL }},
    { &hf_mms_startingEntry,
      { "startingEntry", "mms.startingEntry",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_mms_rangeStopSpecification,
      { "rangeStopSpecification", "mms.rangeStopSpecification",
        FT_UINT32, BASE_DEC, VALS(mms_T_rangeStopSpecification_vals), 0,
        NULL, HFILL }},
    { &hf_mms_endingTime,
      { "endingTime", "mms.endingTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "TimeOfDay", HFILL }},
    { &hf_mms_numberOfEntries,
      { "numberOfEntries", "mms.numberOfEntries",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer32", HFILL }},
    { &hf_mms_listOfVariables,
      { "listOfVariables", "mms.listOfVariables",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_listOfVariables_item,
      { "listOfVariables item", "mms.listOfVariables_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_mms_entryToStartAfter,
      { "entryToStartAfter", "mms.entryToStartAfter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_timeSpecification,
      { "timeSpecification", "mms.timeSpecification",
        FT_STRING, BASE_NONE, NULL, 0,
        "TimeOfDay", HFILL }},
    { &hf_mms_entrySpecification,
      { "entrySpecification", "mms.entrySpecification",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_mms_listOfJournalEntry,
      { "listOfJournalEntry", "mms.listOfJournalEntry",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_JournalEntry", HFILL }},
    { &hf_mms_listOfJournalEntry_item,
      { "JournalEntry", "mms.JournalEntry_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_entryIdentifier,
      { "entryIdentifier", "mms.entryIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_mms_originatingApplication,
      { "originatingApplication", "mms.originatingApplication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ApplicationReference", HFILL }},
    { &hf_mms_entryContent,
      { "entryContent", "mms.entryContent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_listOfJournalEntry_01,
      { "listOfJournalEntry", "mms.listOfJournalEntry",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_EntryContent", HFILL }},
    { &hf_mms_listOfJournalEntry_item_01,
      { "EntryContent", "mms.EntryContent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_limitSpecification,
      { "limitSpecification", "mms.limitSpecification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_limitingTime,
      { "limitingTime", "mms.limitingTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "TimeOfDay", HFILL }},
    { &hf_mms_limitingEntry,
      { "limitingEntry", "mms.limitingEntry",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_mms_currentEntries,
      { "currentEntries", "mms.currentEntries",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_mms_occurenceTime,
      { "occurenceTime", "mms.occurenceTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "TimeOfDay", HFILL }},
    { &hf_mms_additionalDetail,
      { "additionalDetail", "mms.additionalDetail_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "JOU_Additional_Detail", HFILL }},
    { &hf_mms_entryForm,
      { "entryForm", "mms.entryForm",
        FT_UINT32, BASE_DEC, VALS(mms_T_entryForm_vals), 0,
        NULL, HFILL }},
    { &hf_mms_data,
      { "data", "mms.data_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_event,
      { "event", "mms.event_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_listOfVariables_01,
      { "listOfVariables", "mms.listOfVariables",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_listOfVariables_01", HFILL }},
    { &hf_mms_listOfVariables_item_01,
      { "listOfVariables item", "mms.listOfVariables_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_variableTag,
      { "variableTag", "mms.variableTag",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_mms_valueSpecification,
      { "valueSpecification", "mms.valueSpecification",
        FT_UINT32, BASE_DEC, VALS(mms_Data_vals), 0,
        "Data", HFILL }},
    { &hf_mms_annotation,
      { "annotation", "mms.annotation",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_mms_sourceFileServer,
      { "sourceFileServer", "mms.sourceFileServer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ApplicationReference", HFILL }},
    { &hf_mms_sourceFile,
      { "sourceFile", "mms.sourceFile",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FileName", HFILL }},
    { &hf_mms_destinationFile,
      { "destinationFile", "mms.destinationFile",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FileName", HFILL }},
    { &hf_mms_initialPosition,
      { "initialPosition", "mms.initialPosition",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_mms_frsmID,
      { "frsmID", "mms.frsmID",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer32", HFILL }},
    { &hf_mms_fileAttributes,
      { "fileAttributes", "mms.fileAttributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_fileData,
      { "fileData", "mms.fileData",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_mms_currentFileName,
      { "currentFileName", "mms.currentFileName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FileName", HFILL }},
    { &hf_mms_newFileName,
      { "newFileName", "mms.newFileName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FileName", HFILL }},
    { &hf_mms_fileSpecification,
      { "fileSpecification", "mms.fileSpecification",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FileName", HFILL }},
    { &hf_mms_continueAfter_03,
      { "continueAfter", "mms.continueAfter",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FileName", HFILL }},
    { &hf_mms_listOfDirectoryEntry,
      { "listOfDirectoryEntry", "mms.listOfDirectoryEntry",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_DirectoryEntry", HFILL }},
    { &hf_mms_listOfDirectoryEntry_item,
      { "DirectoryEntry", "mms.DirectoryEntry_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_filename,
      { "filename", "mms.filename",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_sizeOfFile,
      { "sizeOfFile", "mms.sizeOfFile",
        FT_INT32, BASE_DEC, NULL, 0,
        "Unsigned32", HFILL }},
    { &hf_mms_lastModified,
      { "lastModified", "mms.lastModified",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_mms_ParameterSupportOptions_str1,
      { "str1", "mms.str1",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_mms_ParameterSupportOptions_str2,
      { "str2", "mms.str2",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_mms_ParameterSupportOptions_vnam,
      { "vnam", "mms.vnam",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_mms_ParameterSupportOptions_valt,
      { "valt", "mms.valt",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_mms_ParameterSupportOptions_vadr,
      { "vadr", "mms.vadr",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_mms_ParameterSupportOptions_vsca,
      { "vsca", "mms.vsca",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_mms_ParameterSupportOptions_tpy,
      { "tpy", "mms.tpy",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_mms_ParameterSupportOptions_vlis,
      { "vlis", "mms.vlis",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_mms_ParameterSupportOptions_real,
      { "real", "mms.real",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_mms_ParameterSupportOptions_cei,
      { "cei", "mms.cei",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_status,
      { "status", "mms.status",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_getNameList,
      { "getNameList", "mms.getNameList",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_identify,
      { "identify", "mms.identify",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_rename,
      { "rename", "mms.rename",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_read,
      { "read", "mms.read",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_write,
      { "write", "mms.write",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_getVariableAccessAttributes,
      { "getVariableAccessAttributes", "mms.getVariableAccessAttributes",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_defineNamedVariable,
      { "defineNamedVariable", "mms.defineNamedVariable",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_defineScatteredAccess,
      { "defineScatteredAccess", "mms.defineScatteredAccess",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_getScatteredAccessAttributes,
      { "getScatteredAccessAttributes", "mms.getScatteredAccessAttributes",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_deleteVariableAccess,
      { "deleteVariableAccess", "mms.deleteVariableAccess",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_defineNamedVariableList,
      { "defineNamedVariableList", "mms.defineNamedVariableList",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_getNamedVariableListAttributes,
      { "getNamedVariableListAttributes", "mms.getNamedVariableListAttributes",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_deleteNamedVariableList,
      { "deleteNamedVariableList", "mms.deleteNamedVariableList",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_defineNamedType,
      { "defineNamedType", "mms.defineNamedType",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_getNamedTypeAttributes,
      { "getNamedTypeAttributes", "mms.getNamedTypeAttributes",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_deleteNamedType,
      { "deleteNamedType", "mms.deleteNamedType",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_input,
      { "input", "mms.input",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_output,
      { "output", "mms.output",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_takeControl,
      { "takeControl", "mms.takeControl",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_relinquishControl,
      { "relinquishControl", "mms.relinquishControl",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_defineSemaphore,
      { "defineSemaphore", "mms.defineSemaphore",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_deleteSemaphore,
      { "deleteSemaphore", "mms.deleteSemaphore",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_reportSemaphoreStatus,
      { "reportSemaphoreStatus", "mms.reportSemaphoreStatus",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_reportPoolSemaphoreStatus,
      { "reportPoolSemaphoreStatus", "mms.reportPoolSemaphoreStatus",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_reportSemaphoreEntryStatus,
      { "reportSemaphoreEntryStatus", "mms.reportSemaphoreEntryStatus",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_initiateDownloadSequence,
      { "initiateDownloadSequence", "mms.initiateDownloadSequence",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_downloadSegment,
      { "downloadSegment", "mms.downloadSegment",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_terminateDownloadSequence,
      { "terminateDownloadSequence", "mms.terminateDownloadSequence",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_initiateUploadSequence,
      { "initiateUploadSequence", "mms.initiateUploadSequence",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_uploadSegment,
      { "uploadSegment", "mms.uploadSegment",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_terminateUploadSequence,
      { "terminateUploadSequence", "mms.terminateUploadSequence",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_requestDomainDownload,
      { "requestDomainDownload", "mms.requestDomainDownload",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_requestDomainUpload,
      { "requestDomainUpload", "mms.requestDomainUpload",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_loadDomainContent,
      { "loadDomainContent", "mms.loadDomainContent",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_storeDomainContent,
      { "storeDomainContent", "mms.storeDomainContent",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_deleteDomain,
      { "deleteDomain", "mms.deleteDomain",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_getDomainAttributes,
      { "getDomainAttributes", "mms.getDomainAttributes",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_createProgramInvocation,
      { "createProgramInvocation", "mms.createProgramInvocation",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_deleteProgramInvocation,
      { "deleteProgramInvocation", "mms.deleteProgramInvocation",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_start,
      { "start", "mms.start",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_stop,
      { "stop", "mms.stop",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_resume,
      { "resume", "mms.resume",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_reset,
      { "reset", "mms.reset",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_kill,
      { "kill", "mms.kill",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_getProgramInvocationAttributes,
      { "getProgramInvocationAttributes", "mms.getProgramInvocationAttributes",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_obtainFile,
      { "obtainFile", "mms.obtainFile",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_defineEventCondition,
      { "defineEventCondition", "mms.defineEventCondition",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_deleteEventCondition,
      { "deleteEventCondition", "mms.deleteEventCondition",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_getEventConditionAttributes,
      { "getEventConditionAttributes", "mms.getEventConditionAttributes",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_reportEventConditionStatus,
      { "reportEventConditionStatus", "mms.reportEventConditionStatus",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_alterEventConditionMonitoring,
      { "alterEventConditionMonitoring", "mms.alterEventConditionMonitoring",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_triggerEvent,
      { "triggerEvent", "mms.triggerEvent",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_defineEventAction,
      { "defineEventAction", "mms.defineEventAction",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_deleteEventAction,
      { "deleteEventAction", "mms.deleteEventAction",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_getEventActionAttributes,
      { "getEventActionAttributes", "mms.getEventActionAttributes",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_reportActionStatus,
      { "reportActionStatus", "mms.reportActionStatus",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_defineEventEnrollment,
      { "defineEventEnrollment", "mms.defineEventEnrollment",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_deleteEventEnrollment,
      { "deleteEventEnrollment", "mms.deleteEventEnrollment",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_alterEventEnrollment,
      { "alterEventEnrollment", "mms.alterEventEnrollment",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_reportEventEnrollmentStatus,
      { "reportEventEnrollmentStatus", "mms.reportEventEnrollmentStatus",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_getEventEnrollmentAttributes,
      { "getEventEnrollmentAttributes", "mms.getEventEnrollmentAttributes",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_acknowledgeEventNotification,
      { "acknowledgeEventNotification", "mms.acknowledgeEventNotification",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_getAlarmSummary,
      { "getAlarmSummary", "mms.getAlarmSummary",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_getAlarmEnrollmentSummary,
      { "getAlarmEnrollmentSummary", "mms.getAlarmEnrollmentSummary",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_readJournal,
      { "readJournal", "mms.readJournal",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_writeJournal,
      { "writeJournal", "mms.writeJournal",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_initializeJournal,
      { "initializeJournal", "mms.initializeJournal",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_reportJournalStatus,
      { "reportJournalStatus", "mms.reportJournalStatus",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_createJournal,
      { "createJournal", "mms.createJournal",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_deleteJournal,
      { "deleteJournal", "mms.deleteJournal",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_getCapabilityList,
      { "getCapabilityList", "mms.getCapabilityList",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_fileOpen,
      { "fileOpen", "mms.fileOpen",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_fileRead,
      { "fileRead", "mms.fileRead",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_fileClose,
      { "fileClose", "mms.fileClose",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_fileRename,
      { "fileRename", "mms.fileRename",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_fileDelete,
      { "fileDelete", "mms.fileDelete",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_fileDirectory,
      { "fileDirectory", "mms.fileDirectory",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_unsolicitedStatus,
      { "unsolicitedStatus", "mms.unsolicitedStatus",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_informationReport,
      { "informationReport", "mms.informationReport",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_eventNotification,
      { "eventNotification", "mms.eventNotification",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_attachToEventCondition,
      { "attachToEventCondition", "mms.attachToEventCondition",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_attachToSemaphore,
      { "attachToSemaphore", "mms.attachToSemaphore",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_conclude,
      { "conclude", "mms.conclude",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_cancel,
      { "cancel", "mms.cancel",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_mms_Transitions_idle_to_disabled,
      { "idle-to-disabled", "mms.idle-to-disabled",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_mms_Transitions_active_to_disabled,
      { "active-to-disabled", "mms.active-to-disabled",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_mms_Transitions_disabled_to_idle,
      { "disabled-to-idle", "mms.disabled-to-idle",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_mms_Transitions_active_to_idle,
      { "active-to-idle", "mms.active-to-idle",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_mms_Transitions_disabled_to_active,
      { "disabled-to-active", "mms.disabled-to-active",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_mms_Transitions_idle_to_active,
      { "idle-to-active", "mms.idle-to-active",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_mms_Transitions_any_to_deleted,
      { "any-to-deleted", "mms.any-to-deleted",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},

/*--- End of included file: packet-mms-hfarr.c ---*/
#line 95 "../../asn1/mms/packet-mms-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_mms,

/*--- Included file: packet-mms-ettarr.c ---*/
#line 1 "../../asn1/mms/packet-mms-ettarr.c"
    &ett_mms_MMSpdu,
    &ett_mms_Confirmed_RequestPDU,
    &ett_mms_SEQUENCE_OF_Modifier,
    &ett_mms_Unconfirmed_PDU,
    &ett_mms_Confirmed_ResponsePDU,
    &ett_mms_Confirmed_ErrorPDU,
    &ett_mms_UnconfirmedService,
    &ett_mms_Modifier,
    &ett_mms_ConfirmedServiceRequest,
    &ett_mms_CS_Request_Detail,
    &ett_mms_ConfirmedServiceResponse,
    &ett_mms_FileName,
    &ett_mms_ObjectName,
    &ett_mms_T_domain_specific,
    &ett_mms_ApplicationReference,
    &ett_mms_Initiate_RequestPDU,
    &ett_mms_InitRequestDetail,
    &ett_mms_Initiate_ResponsePDU,
    &ett_mms_InitResponseDetail,
    &ett_mms_ParameterSupportOptions,
    &ett_mms_ServiceSupportOptions,
    &ett_mms_Cancel_ErrorPDU,
    &ett_mms_ServiceError,
    &ett_mms_T_errorClass,
    &ett_mms_T_serviceSpecificInformation,
    &ett_mms_RejectPDU,
    &ett_mms_T_rejectReason,
    &ett_mms_Status_Response,
    &ett_mms_GetNameList_Request,
    &ett_mms_T_extendedObjectClass,
    &ett_mms_T_objectScope,
    &ett_mms_GetNameList_Response,
    &ett_mms_SEQUENCE_OF_Identifier,
    &ett_mms_Identify_Response,
    &ett_mms_T_listOfAbstractSyntaxes,
    &ett_mms_Rename_Request,
    &ett_mms_T_extendedObjectClass_01,
    &ett_mms_GetCapabilityList_Request,
    &ett_mms_GetCapabilityList_Response,
    &ett_mms_T_listOfCapabilities,
    &ett_mms_InitiateDownloadSequence_Request,
    &ett_mms_T_listOfCapabilities_01,
    &ett_mms_DownloadSegment_Response,
    &ett_mms_T_loadData,
    &ett_mms_TerminateDownloadSequence_Request,
    &ett_mms_InitiateUploadSequence_Response,
    &ett_mms_T_listOfCapabilities_02,
    &ett_mms_UploadSegment_Response,
    &ett_mms_T_loadData_01,
    &ett_mms_RequestDomainDownload_Request,
    &ett_mms_T_listOfCapabilities_03,
    &ett_mms_RequestDomainUpload_Request,
    &ett_mms_LoadDomainContent_Request,
    &ett_mms_T_listOfCapabilities_04,
    &ett_mms_StoreDomainContent_Request,
    &ett_mms_GetDomainAttributes_Response,
    &ett_mms_T_listOfCapabilities_05,
    &ett_mms_CreateProgramInvocation_Request,
    &ett_mms_Start_Request,
    &ett_mms_T_executionArgument,
    &ett_mms_Stop_Request,
    &ett_mms_Resume_Request,
    &ett_mms_T_executionArgument_01,
    &ett_mms_Reset_Request,
    &ett_mms_Kill_Request,
    &ett_mms_GetProgramInvocationAttributes_Response,
    &ett_mms_T_executionArgument_02,
    &ett_mms_TypeSpecification,
    &ett_mms_T_array,
    &ett_mms_T_structure,
    &ett_mms_T_components,
    &ett_mms_T_components_item,
    &ett_mms_AlternateAccess,
    &ett_mms_AlternateAccess_item,
    &ett_mms_T_named,
    &ett_mms_AlternateAccessSelection,
    &ett_mms_T_selectAlternateAccess,
    &ett_mms_T_accessSelection,
    &ett_mms_T_indexRange,
    &ett_mms_T_selectAccess,
    &ett_mms_T_indexRange_01,
    &ett_mms_Read_Request,
    &ett_mms_Read_Response,
    &ett_mms_SEQUENCE_OF_AccessResult,
    &ett_mms_Write_Request,
    &ett_mms_SEQUENCE_OF_Data,
    &ett_mms_Write_Response,
    &ett_mms_Write_Response_item,
    &ett_mms_InformationReport,
    &ett_mms_GetVariableAccessAttributes_Request,
    &ett_mms_GetVariableAccessAttributes_Response,
    &ett_mms_DefineNamedVariable_Request,
    &ett_mms_DefineScatteredAccess_Request,
    &ett_mms_GetScatteredAccessAttributes_Response,
    &ett_mms_DeleteVariableAccess_Request,
    &ett_mms_SEQUENCE_OF_ObjectName,
    &ett_mms_DeleteVariableAccess_Response,
    &ett_mms_DefineNamedVariableList_Request,
    &ett_mms_T_listOfVariable,
    &ett_mms_T_listOfVariable_item,
    &ett_mms_GetNamedVariableListAttributes_Response,
    &ett_mms_T_listOfVariable_01,
    &ett_mms_T_listOfVariable_item_01,
    &ett_mms_DeleteNamedVariableList_Request,
    &ett_mms_DeleteNamedVariableList_Response,
    &ett_mms_DefineNamedType_Request,
    &ett_mms_GetNamedTypeAttributes_Response,
    &ett_mms_DeleteNamedType_Request,
    &ett_mms_DeleteNamedType_Response,
    &ett_mms_AccessResult,
    &ett_mms_Data,
    &ett_mms_VariableAccessSpecification,
    &ett_mms_T_listOfVariable_02,
    &ett_mms_T_listOfVariable_item_02,
    &ett_mms_ScatteredAccessDescription,
    &ett_mms_ScatteredAccessDescription_item,
    &ett_mms_VariableSpecification,
    &ett_mms_T_variableDescription,
    &ett_mms_Address,
    &ett_mms_TakeControl_Request,
    &ett_mms_TakeControl_Response,
    &ett_mms_RelinquishControl_Request,
    &ett_mms_DefineSemaphore_Request,
    &ett_mms_ReportSemaphoreStatus_Response,
    &ett_mms_ReportPoolSemaphoreStatus_Request,
    &ett_mms_ReportPoolSemaphoreStatus_Response,
    &ett_mms_T_listOfNamedTokens,
    &ett_mms_T_listOfNamedTokens_item,
    &ett_mms_ReportSemaphoreEntryStatus_Request,
    &ett_mms_ReportSemaphoreEntryStatus_Response,
    &ett_mms_SEQUENCE_OF_SemaphoreEntry,
    &ett_mms_AttachToSemaphore,
    &ett_mms_SemaphoreEntry,
    &ett_mms_Input_Request,
    &ett_mms_T_listOfPromptData,
    &ett_mms_Output_Request,
    &ett_mms_T_listOfOutputData,
    &ett_mms_DefineEventCondition_Request,
    &ett_mms_DeleteEventCondition_Request,
    &ett_mms_GetEventConditionAttributes_Response,
    &ett_mms_T_monitoredVariable,
    &ett_mms_ReportEventConditionStatus_Response,
    &ett_mms_AlterEventConditionMonitoring_Request,
    &ett_mms_TriggerEvent_Request,
    &ett_mms_DefineEventAction_Request,
    &ett_mms_DeleteEventAction_Request,
    &ett_mms_GetEventActionAttributes_Response,
    &ett_mms_DefineEventEnrollment_Request,
    &ett_mms_DeleteEventEnrollment_Request,
    &ett_mms_GetEventEnrollmentAttributes_Request,
    &ett_mms_EventEnrollment,
    &ett_mms_T_eventConditionName,
    &ett_mms_T_eventActionName,
    &ett_mms_GetEventEnrollmentAttributes_Response,
    &ett_mms_SEQUENCE_OF_EventEnrollment,
    &ett_mms_ReportEventEnrollmentStatus_Response,
    &ett_mms_AlterEventEnrollment_Request,
    &ett_mms_AlterEventEnrollment_Response,
    &ett_mms_T_currentState,
    &ett_mms_AcknowledgeEventNotification_Request,
    &ett_mms_GetAlarmSummary_Request,
    &ett_mms_T_severityFilter,
    &ett_mms_GetAlarmSummary_Response,
    &ett_mms_SEQUENCE_OF_AlarmSummary,
    &ett_mms_AlarmSummary,
    &ett_mms_GetAlarmEnrollmentSummary_Request,
    &ett_mms_T_severityFilter_01,
    &ett_mms_GetAlarmEnrollmentSummary_Response,
    &ett_mms_SEQUENCE_OF_AlarmEnrollmentSummary,
    &ett_mms_AlarmEnrollmentSummary,
    &ett_mms_EventNotification,
    &ett_mms_T_eventConditionName_01,
    &ett_mms_T_actionResult,
    &ett_mms_T_eventActionResult,
    &ett_mms_AttachToEventCondition,
    &ett_mms_EventTime,
    &ett_mms_Transitions,
    &ett_mms_ReadJournal_Request,
    &ett_mms_T_rangeStartSpecification,
    &ett_mms_T_rangeStopSpecification,
    &ett_mms_T_listOfVariables,
    &ett_mms_T_entryToStartAfter,
    &ett_mms_ReadJournal_Response,
    &ett_mms_SEQUENCE_OF_JournalEntry,
    &ett_mms_JournalEntry,
    &ett_mms_WriteJournal_Request,
    &ett_mms_SEQUENCE_OF_EntryContent,
    &ett_mms_InitializeJournal_Request,
    &ett_mms_T_limitSpecification,
    &ett_mms_ReportJournalStatus_Response,
    &ett_mms_CreateJournal_Request,
    &ett_mms_DeleteJournal_Request,
    &ett_mms_EntryContent,
    &ett_mms_T_entryForm,
    &ett_mms_T_data,
    &ett_mms_T_event,
    &ett_mms_T_listOfVariables_01,
    &ett_mms_T_listOfVariables_item,
    &ett_mms_ObtainFile_Request,
    &ett_mms_FileOpen_Request,
    &ett_mms_FileOpen_Response,
    &ett_mms_FileRead_Response,
    &ett_mms_FileRename_Request,
    &ett_mms_FileDirectory_Request,
    &ett_mms_FileDirectory_Response,
    &ett_mms_SEQUENCE_OF_DirectoryEntry,
    &ett_mms_DirectoryEntry,
    &ett_mms_FileAttributes,

/*--- End of included file: packet-mms-ettarr.c ---*/
#line 101 "../../asn1/mms/packet-mms-template.c"
  };

  static ei_register_info ei[] = {
     { &ei_mms_mal_timeofday_encoding, { "mms.malformed.timeofday_encoding", PI_MALFORMED, PI_WARN, "BER Error: malformed TimeOfDay encoding", EXPFILL }},
     { &ei_mms_mal_utctime_encoding, { "mms.malformed.utctime", PI_MALFORMED, PI_WARN, "BER Error: malformed IEC61850 UTCTime encoding", EXPFILL }},
  };

  expert_module_t* expert_mms;

  /* Register protocol */
  proto_mms = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("mms", dissect_mms, proto_mms);
  /* Register fields and subtrees */
  proto_register_field_array(proto_mms, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_mms = expert_register_protocol(proto_mms);
  expert_register_field_array(expert_mms, ei, array_length(ei));

}


static gboolean
dissect_mms_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
	/* must check that this really is an mms packet */
	int offset = 0;
	guint32 length = 0 ;
	guint32 oct;
	gint idx = 0 ;

	gint8 tmp_class;
	gboolean tmp_pc;
	gint32 tmp_tag;

		/* first, check do we have at least 2 bytes (pdu) */
	if (!tvb_bytes_exist(tvb, 0, 2))
		return FALSE;	/* no */

	/* can we recognize MMS PDU ? Return FALSE if  not */
	/*   get MMS PDU type */
	offset = get_ber_identifier(tvb, offset, &tmp_class, &tmp_pc, &tmp_tag);

	/* check MMS type */

	/* Class should be constructed */
	if (tmp_class!=BER_CLASS_CON)
		return FALSE;

	/* see if the tag is a valid MMS PDU */
	try_val_to_str_idx(tmp_tag, mms_MMSpdu_vals, &idx);
	if  (idx == -1) {
	 	return FALSE;  /* no, it isn't an MMS PDU */
	}

	/* check MMS length  */
	oct = tvb_get_guint8(tvb, offset)& 0x7F;
	if (oct==0)
		/* MMS requires length after tag so not MMS if indefinite length*/
		return FALSE;

	offset = get_ber_length(tvb, offset, &length, NULL);
	/* do we have enough bytes? */
	if (!tvb_bytes_exist(tvb, offset, length))
		return FALSE;

	dissect_mms(tvb, pinfo, parent_tree);
	return TRUE;
}

/*--- proto_reg_handoff_mms --- */
void proto_reg_handoff_mms(void) {
	register_ber_oid_dissector("1.0.9506.2.3", dissect_mms, proto_mms,"MMS");
	register_ber_oid_dissector("1.0.9506.2.1", dissect_mms, proto_mms,"mms-abstract-syntax-version1(1)");
	heur_dissector_add("cotp", dissect_mms_heur, proto_mms);
	heur_dissector_add("cotp_is", dissect_mms_heur, proto_mms);
}

