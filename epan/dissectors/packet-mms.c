/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* ./packet-mms.c                                                             */
/* ../../tools/asn2wrs.py -b -e -p mms -c mms.cnf -s packet-mms-template mms.asn */

/* Input file: packet-mms-template.c */

#line 1 "packet-mms-template.c"
/* packet-mms_asn1.c
 *
 * Ronnie Sahlberg 2005
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-acse.h"
#include "packet-mms.h"

#define PNAME  "MMS"
#define PSNAME "MMS"
#define PFNAME "mms"

/* Initialize the protocol and registered fields */
int proto_mms = -1;


/*--- Included file: packet-mms-hf.c ---*/
#line 1 "packet-mms-hf.c"
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
static int hf_mms_status1 = -1;                   /* Status_Response */
static int hf_mms_getNameList1 = -1;              /* GetNameList_Response */
static int hf_mms_identify1 = -1;                 /* Identify_Response */
static int hf_mms_rename1 = -1;                   /* Rename_Response */
static int hf_mms_read1 = -1;                     /* Read_Response */
static int hf_mms_write1 = -1;                    /* Write_Response */
static int hf_mms_getVariableAccessAttributes1 = -1;  /* GetVariableAccessAttributes_Response */
static int hf_mms_defineNamedVariable1 = -1;      /* DefineNamedVariable_Response */
static int hf_mms_defineScatteredAccess1 = -1;    /* DefineScatteredAccess_Response */
static int hf_mms_getScatteredAccessAttributes1 = -1;  /* GetScatteredAccessAttributes_Response */
static int hf_mms_deleteVariableAccess1 = -1;     /* DeleteVariableAccess_Response */
static int hf_mms_defineNamedVariableList1 = -1;  /* DefineNamedVariableList_Response */
static int hf_mms_getNamedVariableListAttributes1 = -1;  /* GetNamedVariableListAttributes_Response */
static int hf_mms_deleteNamedVariableList1 = -1;  /* DeleteNamedVariableList_Response */
static int hf_mms_defineNamedType1 = -1;          /* DefineNamedType_Response */
static int hf_mms_getNamedTypeAttributes1 = -1;   /* GetNamedTypeAttributes_Response */
static int hf_mms_deleteNamedType1 = -1;          /* DeleteNamedType_Response */
static int hf_mms_input1 = -1;                    /* Input_Response */
static int hf_mms_output1 = -1;                   /* Output_Response */
static int hf_mms_takeControl1 = -1;              /* TakeControl_Response */
static int hf_mms_relinquishControl1 = -1;        /* RelinquishControl_Response */
static int hf_mms_defineSemaphore1 = -1;          /* DefineSemaphore_Response */
static int hf_mms_deleteSemaphore1 = -1;          /* DeleteSemaphore_Response */
static int hf_mms_reportSemaphoreStatus1 = -1;    /* ReportSemaphoreStatus_Response */
static int hf_mms_reportPoolSemaphoreStatus1 = -1;  /* ReportPoolSemaphoreStatus_Response */
static int hf_mms_reportSemaphoreEntryStatus1 = -1;  /* ReportSemaphoreEntryStatus_Response */
static int hf_mms_initiateDownloadSequence1 = -1;  /* InitiateDownloadSequence_Response */
static int hf_mms_downloadSegment1 = -1;          /* DownloadSegment_Response */
static int hf_mms_terminateDownloadSequence1 = -1;  /* TerminateDownloadSequence_Response */
static int hf_mms_initiateUploadSequence1 = -1;   /* InitiateUploadSequence_Response */
static int hf_mms_uploadSegment1 = -1;            /* UploadSegment_Response */
static int hf_mms_terminateUploadSequence1 = -1;  /* TerminateUploadSequence_Response */
static int hf_mms_requestDomainDownLoad = -1;     /* RequestDomainDownload_Response */
static int hf_mms_requestDomainUpload1 = -1;      /* RequestDomainUpload_Response */
static int hf_mms_loadDomainContent1 = -1;        /* LoadDomainContent_Response */
static int hf_mms_storeDomainContent1 = -1;       /* StoreDomainContent_Response */
static int hf_mms_deleteDomain1 = -1;             /* DeleteDomain_Response */
static int hf_mms_getDomainAttributes1 = -1;      /* GetDomainAttributes_Response */
static int hf_mms_createProgramInvocation1 = -1;  /* CreateProgramInvocation_Response */
static int hf_mms_deleteProgramInvocation1 = -1;  /* DeleteProgramInvocation_Response */
static int hf_mms_start1 = -1;                    /* Start_Response */
static int hf_mms_stop1 = -1;                     /* Stop_Response */
static int hf_mms_resume1 = -1;                   /* Resume_Response */
static int hf_mms_reset1 = -1;                    /* Reset_Response */
static int hf_mms_kill1 = -1;                     /* Kill_Response */
static int hf_mms_getProgramInvocationAttributes1 = -1;  /* GetProgramInvocationAttributes_Response */
static int hf_mms_obtainFile1 = -1;               /* ObtainFile_Response */
static int hf_mms_fileOpen1 = -1;                 /* FileOpen_Response */
static int hf_mms_defineEventCondition1 = -1;     /* DefineEventCondition_Response */
static int hf_mms_deleteEventCondition1 = -1;     /* DeleteEventCondition_Response */
static int hf_mms_getEventConditionAttributes1 = -1;  /* GetEventConditionAttributes_Response */
static int hf_mms_reportEventConditionStatus1 = -1;  /* ReportEventConditionStatus_Response */
static int hf_mms_alterEventConditionMonitoring1 = -1;  /* AlterEventConditionMonitoring_Response */
static int hf_mms_triggerEvent1 = -1;             /* TriggerEvent_Response */
static int hf_mms_defineEventAction1 = -1;        /* DefineEventAction_Response */
static int hf_mms_deleteEventAction1 = -1;        /* DeleteEventAction_Response */
static int hf_mms_getEventActionAttributes1 = -1;  /* GetEventActionAttributes_Response */
static int hf_mms_reportActionStatus = -1;        /* ReportEventActionStatus_Response */
static int hf_mms_defineEventEnrollment1 = -1;    /* DefineEventEnrollment_Response */
static int hf_mms_deleteEventEnrollment1 = -1;    /* DeleteEventEnrollment_Response */
static int hf_mms_alterEventEnrollment1 = -1;     /* AlterEventEnrollment_Response */
static int hf_mms_reportEventEnrollmentStatus1 = -1;  /* ReportEventEnrollmentStatus_Response */
static int hf_mms_getEventEnrollmentAttributes1 = -1;  /* GetEventEnrollmentAttributes_Response */
static int hf_mms_acknowledgeEventNotification1 = -1;  /* AcknowledgeEventNotification_Response */
static int hf_mms_getAlarmSummary1 = -1;          /* GetAlarmSummary_Response */
static int hf_mms_getAlarmEnrollmentSummary1 = -1;  /* GetAlarmEnrollmentSummary_Response */
static int hf_mms_readJournal1 = -1;              /* ReadJournal_Response */
static int hf_mms_writeJournal1 = -1;             /* WriteJournal_Response */
static int hf_mms_initializeJournal1 = -1;        /* InitializeJournal_Response */
static int hf_mms_reportJournalStatus1 = -1;      /* ReportJournalStatus_Response */
static int hf_mms_createJournal1 = -1;            /* CreateJournal_Response */
static int hf_mms_deleteJournal1 = -1;            /* DeleteJournal_Response */
static int hf_mms_getCapabilityList1 = -1;        /* GetCapabilityList_Response */
static int hf_mms_fileRead1 = -1;                 /* FileRead_Response */
static int hf_mms_fileClose1 = -1;                /* FileClose_Response */
static int hf_mms_fileRename1 = -1;               /* FileRename_Response */
static int hf_mms_fileDelete1 = -1;               /* FileDelete_Response */
static int hf_mms_fileDirectory1 = -1;            /* FileDirectory_Response */
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
static int hf_mms_obtainFile2 = -1;               /* ObtainFile_Error */
static int hf_mms_start2 = -1;                    /* Start_Error */
static int hf_mms_stop2 = -1;                     /* Stop_Error */
static int hf_mms_resume2 = -1;                   /* Resume_Error */
static int hf_mms_reset2 = -1;                    /* Reset_Error */
static int hf_mms_deleteVariableAccess2 = -1;     /* DeleteVariableAccess_Error */
static int hf_mms_deleteNamedVariableList2 = -1;  /* DeleteNamedVariableList_Error */
static int hf_mms_deleteNamedType2 = -1;          /* DeleteNamedType_Error */
static int hf_mms_defineEventEnrollment_Error = -1;  /* DefineEventEnrollment_Error */
static int hf_mms_fileRename2 = -1;               /* FileRename_Error */
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
static int hf_mms_extendedObjectClass1 = -1;      /* T_extendedObjectClass1 */
static int hf_mms_objectClass1 = -1;              /* T_objectClass1 */
static int hf_mms_currentName = -1;               /* ObjectName */
static int hf_mms_newIdentifier = -1;             /* Identifier */
static int hf_mms_continueAfter1 = -1;            /* VisibleString */
static int hf_mms_listOfCapabilities = -1;        /* T_listOfCapabilities */
static int hf_mms_listOfCapabilities_item = -1;   /* VisibleString */
static int hf_mms_domainName = -1;                /* Identifier */
static int hf_mms_listOfCapabilities1 = -1;       /* T_listOfCapabilities1 */
static int hf_mms_sharable = -1;                  /* BOOLEAN */
static int hf_mms_loadData = -1;                  /* T_loadData */
static int hf_mms_non_coded = -1;                 /* OCTET_STRING */
static int hf_mms_coded = -1;                     /* EXTERNAL */
static int hf_mms_discard = -1;                   /* ServiceError */
static int hf_mms_ulsmID = -1;                    /* Integer32 */
static int hf_mms_listOfCapabilities2 = -1;       /* T_listOfCapabilities2 */
static int hf_mms_loadData1 = -1;                 /* T_loadData1 */
static int hf_mms_listOfCapabilities3 = -1;       /* T_listOfCapabilities3 */
static int hf_mms_fileName = -1;                  /* FileName */
static int hf_mms_listOfCapabilities4 = -1;       /* T_listOfCapabilities4 */
static int hf_mms_thirdParty = -1;                /* ApplicationReference */
static int hf_mms_filenName = -1;                 /* FileName */
static int hf_mms_listOfCapabilities5 = -1;       /* T_listOfCapabilities5 */
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
static int hf_mms_encodedString = -1;             /* EXTERNAL */
static int hf_mms_executionArgument1 = -1;        /* T_executionArgument1 */
static int hf_mms_state1 = -1;                    /* ProgramInvocationState */
static int hf_mms_listOfDomainNames = -1;         /* SEQUENCE_OF_Identifier */
static int hf_mms_listOfDomainNames_item = -1;    /* Identifier */
static int hf_mms_monitor = -1;                   /* BOOLEAN */
static int hf_mms_startArgument = -1;             /* VisibleString */
static int hf_mms_executionArgument2 = -1;        /* T_executionArgument2 */
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
static int hf_mms_selectAccess = -1;              /* T_selectAccess */
static int hf_mms_component = -1;                 /* Identifier */
static int hf_mms_index = -1;                     /* Unsigned32 */
static int hf_mms_indexRange = -1;                /* T_indexRange */
static int hf_mms_lowIndex = -1;                  /* Unsigned32 */
static int hf_mms_allElements = -1;               /* NULL */
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
static int hf_mms_alternateAccess = -1;           /* AlternateAccess */
static int hf_mms_listOfVariable1 = -1;           /* T_listOfVariable1 */
static int hf_mms_listOfVariable_item1 = -1;      /* T_listOfVariable_item1 */
static int hf_mms_scopeOfDelete1 = -1;            /* T_scopeOfDelete1 */
static int hf_mms_listOfVariableListName = -1;    /* SEQUENCE_OF_ObjectName */
static int hf_mms_listOfVariableListName_item = -1;  /* ObjectName */
static int hf_mms_scopeOfDelete2 = -1;            /* T_scopeOfDelete2 */
static int hf_mms_listOfTypeName = -1;            /* SEQUENCE_OF_ObjectName */
static int hf_mms_listOfTypeName_item = -1;       /* ObjectName */
static int hf_mms_success1 = -1;                  /* Data */
static int hf_mms_array1 = -1;                    /* SEQUENCE_OF_Data */
static int hf_mms_array_item = -1;                /* Data */
static int hf_mms_structure1 = -1;                /* SEQUENCE_OF_Data */
static int hf_mms_structure_item = -1;            /* Data */
static int hf_mms_boolean1 = -1;                  /* BOOLEAN */
static int hf_mms_bit_string1 = -1;               /* BIT_STRING */
static int hf_mms_integer1 = -1;                  /* INTEGER */
static int hf_mms_unsigned1 = -1;                 /* INTEGER */
static int hf_mms_floating_point = -1;            /* FloatingPoint */
static int hf_mms_octet_string1 = -1;             /* OCTET_STRING */
static int hf_mms_visible_string1 = -1;           /* VisibleString */
static int hf_mms_binary_time1 = -1;              /* TimeOfDay */
static int hf_mms_bcd1 = -1;                      /* INTEGER */
static int hf_mms_booleanArray = -1;              /* BIT_STRING */
static int hf_mms_listOfVariable2 = -1;           /* T_listOfVariable2 */
static int hf_mms_listOfVariable_item2 = -1;      /* T_listOfVariable_item2 */
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
static int hf_mms_state2 = -1;                    /* T_state */
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
static int hf_mms_class1 = -1;                    /* EC_Class */
static int hf_mms_prio_rity = -1;                 /* Priority */
static int hf_mms_severity = -1;                  /* Unsigned8 */
static int hf_mms_alarmSummaryReports = -1;       /* BOOLEAN */
static int hf_mms_monitoredVariable = -1;         /* VariableSpecification */
static int hf_mms_evaluationInterval = -1;        /* Unsigned32 */
static int hf_mms_specific = -1;                  /* SEQUENCE_OF_ObjectName */
static int hf_mms_specific_item = -1;             /* ObjectName */
static int hf_mms_aa_specific1 = -1;              /* NULL */
static int hf_mms_domain = -1;                    /* Identifier */
static int hf_mms_vmd = -1;                       /* NULL */
static int hf_mms_monitoredVariable1 = -1;        /* T_monitoredVariable */
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
static int hf_mms_continueAfter2 = -1;            /* ObjectName */
static int hf_mms_eventConditionName1 = -1;       /* T_eventConditionName */
static int hf_mms_eventCondition = -1;            /* ObjectName */
static int hf_mms_eventActionName1 = -1;          /* T_eventActionName */
static int hf_mms_eventAction = -1;               /* ObjectName */
static int hf_mms_enrollmentClass = -1;           /* EE_Class */
static int hf_mms_duration = -1;                  /* EE_Duration */
static int hf_mms_remainingAcceptableDelay = -1;  /* Unsigned32 */
static int hf_mms_listOfEventEnrollment = -1;     /* SEQUENCE_OF_EventEnrollment */
static int hf_mms_listOfEventEnrollment_item = -1;  /* EventEnrollment */
static int hf_mms_eventConditionTransitions = -1;  /* Transitions */
static int hf_mms_notificationLost = -1;          /* BOOLEAN */
static int hf_mms_alarmAcknowledgmentRule = -1;   /* AlarmAckRule */
static int hf_mms_currentState1 = -1;             /* EE_State */
static int hf_mms_currentState2 = -1;             /* T_currentState */
static int hf_mms_state3 = -1;                    /* EE_State */
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
static int hf_mms_acknowledgmentFilter1 = -1;     /* T_acknowledgmentFilter1 */
static int hf_mms_severityFilter1 = -1;           /* T_severityFilter1 */
static int hf_mms_listOfAlarmEnrollmentSummary = -1;  /* SEQUENCE_OF_AlarmEnrollmentSummary */
static int hf_mms_listOfAlarmEnrollmentSummary_item = -1;  /* AlarmEnrollmentSummary */
static int hf_mms_enrollementState = -1;          /* EE_State */
static int hf_mms_timeActiveAcknowledged = -1;    /* EventTime */
static int hf_mms_timeIdleAcknowledged = -1;      /* EventTime */
static int hf_mms_eventConditionName2 = -1;       /* T_eventConditionName1 */
static int hf_mms_actionResult = -1;              /* T_actionResult */
static int hf_mms_eventActioName = -1;            /* ObjectName */
static int hf_mms_eventActionResult = -1;         /* T_eventActionResult */
static int hf_mms_success2 = -1;                  /* ConfirmedServiceResponse */
static int hf_mms_failure1 = -1;                  /* ServiceError */
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
static int hf_mms_listOfJournalEntry1 = -1;       /* SEQUENCE_OF_EntryContent */
static int hf_mms_listOfJournalEntry_item1 = -1;  /* EntryContent */
static int hf_mms_limitSpecification = -1;        /* T_limitSpecification */
static int hf_mms_limitingTime = -1;              /* TimeOfDay */
static int hf_mms_limitingEntry = -1;             /* OCTET_STRING */
static int hf_mms_currentEntries = -1;            /* Unsigned32 */
static int hf_mms_occurenceTime = -1;             /* TimeOfDay */
static int hf_mms_additionalDetail = -1;          /* JOU_Additional_Detail */
static int hf_mms_entryForm = -1;                 /* T_entryForm */
static int hf_mms_data = -1;                      /* T_data */
static int hf_mms_event = -1;                     /* T_event */
static int hf_mms_listOfVariables1 = -1;          /* T_listOfVariables1 */
static int hf_mms_listOfVariables_item1 = -1;     /* T_listOfVariables_item */
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
static int hf_mms_continueAfter3 = -1;            /* FileName */
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
#line 49 "packet-mms-template.c"

/* Initialize the subtree pointers */
static gint ett_mms = -1;

/*--- Included file: packet-mms-ett.c ---*/
#line 1 "packet-mms-ett.c"
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
static gint ett_mms_T_extendedObjectClass1 = -1;
static gint ett_mms_GetCapabilityList_Request = -1;
static gint ett_mms_GetCapabilityList_Response = -1;
static gint ett_mms_T_listOfCapabilities = -1;
static gint ett_mms_InitiateDownloadSequence_Request = -1;
static gint ett_mms_T_listOfCapabilities1 = -1;
static gint ett_mms_DownloadSegment_Response = -1;
static gint ett_mms_T_loadData = -1;
static gint ett_mms_TerminateDownloadSequence_Request = -1;
static gint ett_mms_InitiateUploadSequence_Response = -1;
static gint ett_mms_T_listOfCapabilities2 = -1;
static gint ett_mms_UploadSegment_Response = -1;
static gint ett_mms_T_loadData1 = -1;
static gint ett_mms_RequestDomainDownload_Request = -1;
static gint ett_mms_T_listOfCapabilities3 = -1;
static gint ett_mms_RequestDomainUpload_Request = -1;
static gint ett_mms_LoadDomainContent_Request = -1;
static gint ett_mms_T_listOfCapabilities4 = -1;
static gint ett_mms_StoreDomainContent_Request = -1;
static gint ett_mms_GetDomainAttributes_Response = -1;
static gint ett_mms_T_listOfCapabilities5 = -1;
static gint ett_mms_CreateProgramInvocation_Request = -1;
static gint ett_mms_Start_Request = -1;
static gint ett_mms_T_executionArgument = -1;
static gint ett_mms_Stop_Request = -1;
static gint ett_mms_Resume_Request = -1;
static gint ett_mms_T_executionArgument1 = -1;
static gint ett_mms_Reset_Request = -1;
static gint ett_mms_Kill_Request = -1;
static gint ett_mms_GetProgramInvocationAttributes_Response = -1;
static gint ett_mms_T_executionArgument2 = -1;
static gint ett_mms_TypeSpecification = -1;
static gint ett_mms_T_array = -1;
static gint ett_mms_T_structure = -1;
static gint ett_mms_T_components = -1;
static gint ett_mms_T_components_item = -1;
static gint ett_mms_AlternateAccess = -1;
static gint ett_mms_AlternateAccess_item = -1;
static gint ett_mms_T_named = -1;
static gint ett_mms_AlternateAccessSelection = -1;
static gint ett_mms_T_selectAccess = -1;
static gint ett_mms_T_indexRange = -1;
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
static gint ett_mms_T_listOfVariable1 = -1;
static gint ett_mms_T_listOfVariable_item1 = -1;
static gint ett_mms_DeleteNamedVariableList_Request = -1;
static gint ett_mms_DeleteNamedVariableList_Response = -1;
static gint ett_mms_DefineNamedType_Request = -1;
static gint ett_mms_GetNamedTypeAttributes_Response = -1;
static gint ett_mms_DeleteNamedType_Request = -1;
static gint ett_mms_DeleteNamedType_Response = -1;
static gint ett_mms_AccessResult = -1;
static gint ett_mms_Data = -1;
static gint ett_mms_VariableAccessSpecification = -1;
static gint ett_mms_T_listOfVariable2 = -1;
static gint ett_mms_T_listOfVariable_item2 = -1;
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
static gint ett_mms_T_severityFilter1 = -1;
static gint ett_mms_GetAlarmEnrollmentSummary_Response = -1;
static gint ett_mms_SEQUENCE_OF_AlarmEnrollmentSummary = -1;
static gint ett_mms_AlarmEnrollmentSummary = -1;
static gint ett_mms_EventNotification = -1;
static gint ett_mms_T_eventConditionName1 = -1;
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
static gint ett_mms_T_listOfVariables1 = -1;
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
#line 53 "packet-mms-template.c"


/*--- Included file: packet-mms-fn.c ---*/
#line 1 "packet-mms-fn.c"
/*--- Cyclic dependencies ---*/

/* TypeSpecification -> TypeSpecification/array -> TypeSpecification */
/* TypeSpecification -> TypeSpecification/structure -> TypeSpecification/structure/components -> TypeSpecification/structure/components/_item -> TypeSpecification */
static int dissect_mms_TypeSpecification(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);

static int dissect_elementType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_TypeSpecification(FALSE, tvb, offset, pinfo, tree, hf_mms_elementType);
}
static int dissect_componentType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_TypeSpecification(FALSE, tvb, offset, pinfo, tree, hf_mms_componentType);
}
static int dissect_typeSpecification(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_TypeSpecification(FALSE, tvb, offset, pinfo, tree, hf_mms_typeSpecification);
}

/* VariableSpecification -> ScatteredAccessDescription -> ScatteredAccessDescription/_item -> VariableSpecification */
static int dissect_mms_VariableSpecification(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);

static int dissect_variableSpecification(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_VariableSpecification(FALSE, tvb, offset, pinfo, tree, hf_mms_variableSpecification);
}
static int dissect_monitoredVariable(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_VariableSpecification(FALSE, tvb, offset, pinfo, tree, hf_mms_monitoredVariable);
}
static int dissect_variableReference(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_VariableSpecification(FALSE, tvb, offset, pinfo, tree, hf_mms_variableReference);
}

/* Data -> Data/array -> Data */
static int dissect_mms_Data(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);

static int dissect_listOfData_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Data(FALSE, tvb, offset, pinfo, tree, hf_mms_listOfData_item);
}
static int dissect_success1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Data(FALSE, tvb, offset, pinfo, tree, hf_mms_success1);
}
static int dissect_array_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Data(FALSE, tvb, offset, pinfo, tree, hf_mms_array_item);
}
static int dissect_structure_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Data(FALSE, tvb, offset, pinfo, tree, hf_mms_structure_item);
}
static int dissect_valueSpecification(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Data(FALSE, tvb, offset, pinfo, tree, hf_mms_valueSpecification);
}


/*--- Fields for imported types ---*/

static int dissect_coded(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acse_EXTERNAL(FALSE, tvb, offset, pinfo, tree, hf_mms_coded);
}
static int dissect_encodedString(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acse_EXTERNAL(FALSE, tvb, offset, pinfo, tree, hf_mms_encodedString);
}



static int
dissect_mms_Unsigned32(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_invokeID(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Unsigned32(FALSE, tvb, offset, pinfo, tree, hf_mms_invokeID);
}
static int dissect_invokeID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Unsigned32(TRUE, tvb, offset, pinfo, tree, hf_mms_invokeID);
}
static int dissect_modifierPosition_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Unsigned32(TRUE, tvb, offset, pinfo, tree, hf_mms_modifierPosition);
}
static int dissect_originalInvokeID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Unsigned32(TRUE, tvb, offset, pinfo, tree, hf_mms_originalInvokeID);
}
static int dissect_numberOfElements_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Unsigned32(TRUE, tvb, offset, pinfo, tree, hf_mms_numberOfElements);
}
static int dissect_index_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Unsigned32(TRUE, tvb, offset, pinfo, tree, hf_mms_index);
}
static int dissect_lowIndex_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Unsigned32(TRUE, tvb, offset, pinfo, tree, hf_mms_lowIndex);
}
static int dissect_numberMatched_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Unsigned32(TRUE, tvb, offset, pinfo, tree, hf_mms_numberMatched);
}
static int dissect_numberDeleted_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Unsigned32(TRUE, tvb, offset, pinfo, tree, hf_mms_numberDeleted);
}
static int dissect_numericAddress_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Unsigned32(TRUE, tvb, offset, pinfo, tree, hf_mms_numericAddress);
}
static int dissect_acceptableDelay_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Unsigned32(TRUE, tvb, offset, pinfo, tree, hf_mms_acceptableDelay);
}
static int dissect_controlTimeOut_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Unsigned32(TRUE, tvb, offset, pinfo, tree, hf_mms_controlTimeOut);
}
static int dissect_remainingTimeOut_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Unsigned32(TRUE, tvb, offset, pinfo, tree, hf_mms_remainingTimeOut);
}
static int dissect_inputTimeOut_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Unsigned32(TRUE, tvb, offset, pinfo, tree, hf_mms_inputTimeOut);
}
static int dissect_evaluationInterval_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Unsigned32(TRUE, tvb, offset, pinfo, tree, hf_mms_evaluationInterval);
}
static int dissect_numberOfEventEnrollments_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Unsigned32(TRUE, tvb, offset, pinfo, tree, hf_mms_numberOfEventEnrollments);
}
static int dissect_remainingAcceptableDelay_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Unsigned32(TRUE, tvb, offset, pinfo, tree, hf_mms_remainingAcceptableDelay);
}
static int dissect_timeSequenceIdentifier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Unsigned32(TRUE, tvb, offset, pinfo, tree, hf_mms_timeSequenceIdentifier);
}
static int dissect_currentEntries_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Unsigned32(TRUE, tvb, offset, pinfo, tree, hf_mms_currentEntries);
}
static int dissect_initialPosition_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Unsigned32(TRUE, tvb, offset, pinfo, tree, hf_mms_initialPosition);
}
static int dissect_sizeOfFile_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Unsigned32(TRUE, tvb, offset, pinfo, tree, hf_mms_sizeOfFile);
}



static int
dissect_mms_Identifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_VisibleString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_vmd_specific_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Identifier(TRUE, tvb, offset, pinfo, tree, hf_mms_vmd_specific);
}
static int dissect_domainId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Identifier(FALSE, tvb, offset, pinfo, tree, hf_mms_domainId);
}
static int dissect_itemId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Identifier(FALSE, tvb, offset, pinfo, tree, hf_mms_itemId);
}
static int dissect_aa_specific_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Identifier(TRUE, tvb, offset, pinfo, tree, hf_mms_aa_specific);
}
static int dissect_domainSpecific_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Identifier(TRUE, tvb, offset, pinfo, tree, hf_mms_domainSpecific);
}
static int dissect_continueAfter_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Identifier(TRUE, tvb, offset, pinfo, tree, hf_mms_continueAfter);
}
static int dissect_listOfIdentifier_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Identifier(FALSE, tvb, offset, pinfo, tree, hf_mms_listOfIdentifier_item);
}
static int dissect_newIdentifier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Identifier(TRUE, tvb, offset, pinfo, tree, hf_mms_newIdentifier);
}
static int dissect_domainName_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Identifier(TRUE, tvb, offset, pinfo, tree, hf_mms_domainName);
}
static int dissect_listOfProgramInvocations_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Identifier(FALSE, tvb, offset, pinfo, tree, hf_mms_listOfProgramInvocations_item);
}
static int dissect_programInvocationName_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Identifier(TRUE, tvb, offset, pinfo, tree, hf_mms_programInvocationName);
}
static int dissect_listOfDomainName_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Identifier(FALSE, tvb, offset, pinfo, tree, hf_mms_listOfDomainName_item);
}
static int dissect_listOfDomainNames_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Identifier(FALSE, tvb, offset, pinfo, tree, hf_mms_listOfDomainNames_item);
}
static int dissect_componentName_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Identifier(TRUE, tvb, offset, pinfo, tree, hf_mms_componentName);
}
static int dissect_component_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Identifier(TRUE, tvb, offset, pinfo, tree, hf_mms_component);
}
static int dissect_namedToken_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Identifier(TRUE, tvb, offset, pinfo, tree, hf_mms_namedToken);
}
static int dissect_nameToStartAfter_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Identifier(TRUE, tvb, offset, pinfo, tree, hf_mms_nameToStartAfter);
}
static int dissect_freeNamedToken_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Identifier(TRUE, tvb, offset, pinfo, tree, hf_mms_freeNamedToken);
}
static int dissect_ownedNamedToken_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Identifier(TRUE, tvb, offset, pinfo, tree, hf_mms_ownedNamedToken);
}
static int dissect_hungNamedToken_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Identifier(TRUE, tvb, offset, pinfo, tree, hf_mms_hungNamedToken);
}
static int dissect_operatorStationName_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Identifier(TRUE, tvb, offset, pinfo, tree, hf_mms_operatorStationName);
}
static int dissect_domain_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Identifier(TRUE, tvb, offset, pinfo, tree, hf_mms_domain);
}


static const ber_sequence_t T_domain_specific_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_domainId },
  { BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_itemId },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_T_domain_specific(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_domain_specific_sequence, hf_index, ett_mms_T_domain_specific);

  return offset;
}
static int dissect_domain_specific_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_domain_specific(TRUE, tvb, offset, pinfo, tree, hf_mms_domain_specific);
}


static const value_string mms_ObjectName_vals[] = {
  {   0, "vmd-specific" },
  {   1, "domain-specific" },
  {   2, "aa-specific" },
  { 0, NULL }
};

static const ber_choice_t ObjectName_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_vmd_specific_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_domain_specific_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_aa_specific_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_ObjectName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ObjectName_choice, hf_index, ett_mms_ObjectName,
                                 NULL);

  return offset;
}
static int dissect_currentName(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ObjectName(FALSE, tvb, offset, pinfo, tree, hf_mms_currentName);
}
static int dissect_typeName(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ObjectName(FALSE, tvb, offset, pinfo, tree, hf_mms_typeName);
}
static int dissect_name(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ObjectName(FALSE, tvb, offset, pinfo, tree, hf_mms_name);
}
static int dissect_variableName(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ObjectName(FALSE, tvb, offset, pinfo, tree, hf_mms_variableName);
}
static int dissect_scatteredAccessName(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ObjectName(FALSE, tvb, offset, pinfo, tree, hf_mms_scatteredAccessName);
}
static int dissect_listOfName_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ObjectName(FALSE, tvb, offset, pinfo, tree, hf_mms_listOfName_item);
}
static int dissect_variableListName(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ObjectName(FALSE, tvb, offset, pinfo, tree, hf_mms_variableListName);
}
static int dissect_listOfVariableListName_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ObjectName(FALSE, tvb, offset, pinfo, tree, hf_mms_listOfVariableListName_item);
}
static int dissect_listOfTypeName_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ObjectName(FALSE, tvb, offset, pinfo, tree, hf_mms_listOfTypeName_item);
}
static int dissect_semaphoreName(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ObjectName(FALSE, tvb, offset, pinfo, tree, hf_mms_semaphoreName);
}
static int dissect_eventConditionName(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ObjectName(FALSE, tvb, offset, pinfo, tree, hf_mms_eventConditionName);
}
static int dissect_specific_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ObjectName(FALSE, tvb, offset, pinfo, tree, hf_mms_specific_item);
}
static int dissect_eventActionName(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ObjectName(FALSE, tvb, offset, pinfo, tree, hf_mms_eventActionName);
}
static int dissect_eventEnrollmentName(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ObjectName(FALSE, tvb, offset, pinfo, tree, hf_mms_eventEnrollmentName);
}
static int dissect_ec(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ObjectName(FALSE, tvb, offset, pinfo, tree, hf_mms_ec);
}
static int dissect_ea(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ObjectName(FALSE, tvb, offset, pinfo, tree, hf_mms_ea);
}
static int dissect_eventEnrollmentNames_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ObjectName(FALSE, tvb, offset, pinfo, tree, hf_mms_eventEnrollmentNames_item);
}
static int dissect_continueAfter2(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ObjectName(FALSE, tvb, offset, pinfo, tree, hf_mms_continueAfter2);
}
static int dissect_eventCondition(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ObjectName(FALSE, tvb, offset, pinfo, tree, hf_mms_eventCondition);
}
static int dissect_eventAction(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ObjectName(FALSE, tvb, offset, pinfo, tree, hf_mms_eventAction);
}
static int dissect_eventActioName(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ObjectName(FALSE, tvb, offset, pinfo, tree, hf_mms_eventActioName);
}
static int dissect_journalName(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ObjectName(FALSE, tvb, offset, pinfo, tree, hf_mms_journalName);
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
dissect_mms_Transitions(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    Transitions_bits, hf_index, ett_mms_Transitions,
                                    NULL);

  return offset;
}
static int dissect_eventConditionTransition_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Transitions(TRUE, tvb, offset, pinfo, tree, hf_mms_eventConditionTransition);
}
static int dissect_eventConditionTransitions_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Transitions(TRUE, tvb, offset, pinfo, tree, hf_mms_eventConditionTransitions);
}
static int dissect_causingTransitions_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Transitions(TRUE, tvb, offset, pinfo, tree, hf_mms_causingTransitions);
}


static const ber_sequence_t AttachToEventCondition_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_eventEnrollmentName },
  { BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_eventConditionName },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_causingTransitions_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acceptableDelay_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_AttachToEventCondition(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AttachToEventCondition_sequence, hf_index, ett_mms_AttachToEventCondition);

  return offset;
}
static int dissect_attach_To_Event_Condition_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_AttachToEventCondition(TRUE, tvb, offset, pinfo, tree, hf_mms_attach_To_Event_Condition);
}



static int
dissect_mms_Unsigned8(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_integer_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Unsigned8(TRUE, tvb, offset, pinfo, tree, hf_mms_integer);
}
static int dissect_unsigned_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Unsigned8(TRUE, tvb, offset, pinfo, tree, hf_mms_unsigned);
}
static int dissect_bcd_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Unsigned8(TRUE, tvb, offset, pinfo, tree, hf_mms_bcd);
}
static int dissect_severity_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Unsigned8(TRUE, tvb, offset, pinfo, tree, hf_mms_severity);
}
static int dissect_mostSevere_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Unsigned8(TRUE, tvb, offset, pinfo, tree, hf_mms_mostSevere);
}
static int dissect_leastSevere_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Unsigned8(TRUE, tvb, offset, pinfo, tree, hf_mms_leastSevere);
}



static int
dissect_mms_Priority(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_Unsigned8(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_priority_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Priority(TRUE, tvb, offset, pinfo, tree, hf_mms_priority);
}
static int dissect_prio_rity_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Priority(TRUE, tvb, offset, pinfo, tree, hf_mms_prio_rity);
}



static int
dissect_mms_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_moreFollows_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_BOOLEAN(TRUE, tvb, offset, pinfo, tree, hf_mms_moreFollows);
}
static int dissect_sharable_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_BOOLEAN(TRUE, tvb, offset, pinfo, tree, hf_mms_sharable);
}
static int dissect_mmsDeletable_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_BOOLEAN(TRUE, tvb, offset, pinfo, tree, hf_mms_mmsDeletable);
}
static int dissect_reusable_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_BOOLEAN(TRUE, tvb, offset, pinfo, tree, hf_mms_reusable);
}
static int dissect_monitorType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_BOOLEAN(TRUE, tvb, offset, pinfo, tree, hf_mms_monitorType);
}
static int dissect_monitor_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_BOOLEAN(TRUE, tvb, offset, pinfo, tree, hf_mms_monitor);
}
static int dissect_packed_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_BOOLEAN(TRUE, tvb, offset, pinfo, tree, hf_mms_packed);
}
static int dissect_binary_time_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_BOOLEAN(TRUE, tvb, offset, pinfo, tree, hf_mms_binary_time);
}
static int dissect_specificationWithResult_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_BOOLEAN(TRUE, tvb, offset, pinfo, tree, hf_mms_specificationWithResult);
}
static int dissect_boolean1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_BOOLEAN(TRUE, tvb, offset, pinfo, tree, hf_mms_boolean1);
}
static int dissect_abortOnTimeOut_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_BOOLEAN(TRUE, tvb, offset, pinfo, tree, hf_mms_abortOnTimeOut);
}
static int dissect_relinquishIfConnectionLost_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_BOOLEAN(TRUE, tvb, offset, pinfo, tree, hf_mms_relinquishIfConnectionLost);
}
static int dissect_echo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_BOOLEAN(TRUE, tvb, offset, pinfo, tree, hf_mms_echo);
}
static int dissect_alarmSummaryReports_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_BOOLEAN(TRUE, tvb, offset, pinfo, tree, hf_mms_alarmSummaryReports);
}
static int dissect_enabled_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_BOOLEAN(TRUE, tvb, offset, pinfo, tree, hf_mms_enabled);
}
static int dissect_notificationLost_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_BOOLEAN(TRUE, tvb, offset, pinfo, tree, hf_mms_notificationLost);
}
static int dissect_enrollmentsOnly_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_BOOLEAN(TRUE, tvb, offset, pinfo, tree, hf_mms_enrollmentsOnly);
}
static int dissect_activeAlarmsOnly_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_BOOLEAN(TRUE, tvb, offset, pinfo, tree, hf_mms_activeAlarmsOnly);
}


static const ber_sequence_t AttachToSemaphore_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_semaphoreName },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_namedToken_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_priority_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acceptableDelay_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_controlTimeOut_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_abortOnTimeOut_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_relinquishIfConnectionLost_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_AttachToSemaphore(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AttachToSemaphore_sequence, hf_index, ett_mms_AttachToSemaphore);

  return offset;
}
static int dissect_attach_To_Semaphore_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_AttachToSemaphore(TRUE, tvb, offset, pinfo, tree, hf_mms_attach_To_Semaphore);
}


static const value_string mms_Modifier_vals[] = {
  {   0, "attach-To-Event-Condition" },
  {   1, "attach-To-Semaphore" },
  { 0, NULL }
};

static const ber_choice_t Modifier_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_attach_To_Event_Condition_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_attach_To_Semaphore_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_Modifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Modifier_choice, hf_index, ett_mms_Modifier,
                                 NULL);

  return offset;
}
static int dissect_listOfModifier_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Modifier(FALSE, tvb, offset, pinfo, tree, hf_mms_listOfModifier_item);
}


static const ber_sequence_t SEQUENCE_OF_Modifier_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_listOfModifier_item },
};

static int
dissect_mms_SEQUENCE_OF_Modifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_Modifier_sequence_of, hf_index, ett_mms_SEQUENCE_OF_Modifier);

  return offset;
}
static int dissect_listOfModifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_SEQUENCE_OF_Modifier(FALSE, tvb, offset, pinfo, tree, hf_mms_listOfModifier);
}
static int dissect_listOfModifier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_SEQUENCE_OF_Modifier(TRUE, tvb, offset, pinfo, tree, hf_mms_listOfModifier);
}



static int
dissect_mms_Status_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_status_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Status_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_status);
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
dissect_mms_T_objectClass(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_objectClass_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_objectClass(TRUE, tvb, offset, pinfo, tree, hf_mms_objectClass);
}


static const value_string mms_T_extendedObjectClass_vals[] = {
  {   0, "objectClass" },
  { 0, NULL }
};

static const ber_choice_t T_extendedObjectClass_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_objectClass_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_T_extendedObjectClass(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_extendedObjectClass_choice, hf_index, ett_mms_T_extendedObjectClass,
                                 NULL);

  return offset;
}
static int dissect_extendedObjectClass(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_extendedObjectClass(FALSE, tvb, offset, pinfo, tree, hf_mms_extendedObjectClass);
}



static int
dissect_mms_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_vmdSpecific_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_NULL(TRUE, tvb, offset, pinfo, tree, hf_mms_vmdSpecific);
}
static int dissect_aaSpecific_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_NULL(TRUE, tvb, offset, pinfo, tree, hf_mms_aaSpecific);
}
static int dissect_boolean_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_NULL(TRUE, tvb, offset, pinfo, tree, hf_mms_boolean);
}
static int dissect_generalized_time_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_NULL(TRUE, tvb, offset, pinfo, tree, hf_mms_generalized_time);
}
static int dissect_objId_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_NULL(TRUE, tvb, offset, pinfo, tree, hf_mms_objId);
}
static int dissect_allElements_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_NULL(TRUE, tvb, offset, pinfo, tree, hf_mms_allElements);
}
static int dissect_success_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_NULL(TRUE, tvb, offset, pinfo, tree, hf_mms_success);
}
static int dissect_invalidated_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_NULL(TRUE, tvb, offset, pinfo, tree, hf_mms_invalidated);
}
static int dissect_noResult_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_NULL(TRUE, tvb, offset, pinfo, tree, hf_mms_noResult);
}
static int dissect_aa_specific1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_NULL(TRUE, tvb, offset, pinfo, tree, hf_mms_aa_specific1);
}
static int dissect_vmd_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_NULL(TRUE, tvb, offset, pinfo, tree, hf_mms_vmd);
}
static int dissect_undefined_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_NULL(TRUE, tvb, offset, pinfo, tree, hf_mms_undefined);
}


static const value_string mms_T_objectScope_vals[] = {
  {   0, "vmdSpecific" },
  {   1, "domainSpecific" },
  {   2, "aaSpecific" },
  { 0, NULL }
};

static const ber_choice_t T_objectScope_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_vmdSpecific_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_domainSpecific_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_aaSpecific_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_T_objectScope(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_objectScope_choice, hf_index, ett_mms_T_objectScope,
                                 NULL);

  return offset;
}
static int dissect_objectScope(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_objectScope(FALSE, tvb, offset, pinfo, tree, hf_mms_objectScope);
}


static const ber_sequence_t GetNameList_Request_sequence[] = {
  { BER_CLASS_CON, 0, 0, dissect_extendedObjectClass },
  { BER_CLASS_CON, 1, 0, dissect_objectScope },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_continueAfter_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_GetNameList_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   GetNameList_Request_sequence, hf_index, ett_mms_GetNameList_Request);

  return offset;
}
static int dissect_getNameList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_GetNameList_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_getNameList);
}



static int
dissect_mms_Identify_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_identify_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Identify_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_identify);
}


static const value_string mms_T_objectClass1_vals[] = {
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
dissect_mms_T_objectClass1(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_objectClass1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_objectClass1(TRUE, tvb, offset, pinfo, tree, hf_mms_objectClass1);
}


static const value_string mms_T_extendedObjectClass1_vals[] = {
  {   0, "objectClass" },
  { 0, NULL }
};

static const ber_choice_t T_extendedObjectClass1_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_objectClass1_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_T_extendedObjectClass1(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_extendedObjectClass1_choice, hf_index, ett_mms_T_extendedObjectClass1,
                                 NULL);

  return offset;
}
static int dissect_extendedObjectClass1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_extendedObjectClass1(FALSE, tvb, offset, pinfo, tree, hf_mms_extendedObjectClass1);
}


static const ber_sequence_t Rename_Request_sequence[] = {
  { BER_CLASS_CON, 0, 0, dissect_extendedObjectClass1 },
  { BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_currentName },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_newIdentifier_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_Rename_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Rename_Request_sequence, hf_index, ett_mms_Rename_Request);

  return offset;
}
static int dissect_rename_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Rename_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_rename);
}



static int
dissect_mms_VisibleString(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_VisibleString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_additionalDescription_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_VisibleString(TRUE, tvb, offset, pinfo, tree, hf_mms_additionalDescription);
}
static int dissect_vendorName_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_VisibleString(TRUE, tvb, offset, pinfo, tree, hf_mms_vendorName);
}
static int dissect_modelName_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_VisibleString(TRUE, tvb, offset, pinfo, tree, hf_mms_modelName);
}
static int dissect_revision_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_VisibleString(TRUE, tvb, offset, pinfo, tree, hf_mms_revision);
}
static int dissect_continueAfter1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_VisibleString(FALSE, tvb, offset, pinfo, tree, hf_mms_continueAfter1);
}
static int dissect_listOfCapabilities_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_VisibleString(FALSE, tvb, offset, pinfo, tree, hf_mms_listOfCapabilities_item);
}
static int dissect_simpleString_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_VisibleString(TRUE, tvb, offset, pinfo, tree, hf_mms_simpleString);
}
static int dissect_startArgument_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_VisibleString(TRUE, tvb, offset, pinfo, tree, hf_mms_startArgument);
}
static int dissect_visible_string1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_VisibleString(TRUE, tvb, offset, pinfo, tree, hf_mms_visible_string1);
}
static int dissect_symbolicAddress_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_VisibleString(TRUE, tvb, offset, pinfo, tree, hf_mms_symbolicAddress);
}
static int dissect_listOfPromptData_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_VisibleString(FALSE, tvb, offset, pinfo, tree, hf_mms_listOfPromptData_item);
}
static int dissect_listOfOutputData_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_VisibleString(FALSE, tvb, offset, pinfo, tree, hf_mms_listOfOutputData_item);
}
static int dissect_listOfVariables_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_VisibleString(FALSE, tvb, offset, pinfo, tree, hf_mms_listOfVariables_item);
}
static int dissect_variableTag_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_VisibleString(TRUE, tvb, offset, pinfo, tree, hf_mms_variableTag);
}
static int dissect_annotation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_VisibleString(TRUE, tvb, offset, pinfo, tree, hf_mms_annotation);
}



static int
dissect_mms_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_non_coded_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_mms_non_coded);
}
static int dissect_octet_string1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_mms_octet_string1);
}
static int dissect_unconstrainedAddress_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_mms_unconstrainedAddress);
}
static int dissect_entryIdToStartAfter_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_mms_entryIdToStartAfter);
}
static int dissect_entryId_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_mms_entryId);
}
static int dissect_startingEntry_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_mms_startingEntry);
}
static int dissect_entrySpecification_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_mms_entrySpecification);
}
static int dissect_entryIdentifier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_mms_entryIdentifier);
}
static int dissect_limitingEntry_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_mms_limitingEntry);
}
static int dissect_fileData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_mms_fileData);
}


static const value_string mms_Address_vals[] = {
  {   0, "numericAddress" },
  {   1, "symbolicAddress" },
  {   2, "unconstrainedAddress" },
  { 0, NULL }
};

static const ber_choice_t Address_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_numericAddress_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_symbolicAddress_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_unconstrainedAddress_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_Address(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Address_choice, hf_index, ett_mms_Address,
                                 NULL);

  return offset;
}
static int dissect_address(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Address(FALSE, tvb, offset, pinfo, tree, hf_mms_address);
}


static const ber_sequence_t T_array_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_packed_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_numberOfElements_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_NOTCHKTAG, dissect_elementType },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_T_array(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_array_sequence, hf_index, ett_mms_T_array);

  return offset;
}
static int dissect_array_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_array(TRUE, tvb, offset, pinfo, tree, hf_mms_array);
}


static const ber_sequence_t T_components_item_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_componentName_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_componentType },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_T_components_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_components_item_sequence, hf_index, ett_mms_T_components_item);

  return offset;
}
static int dissect_components_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_components_item(FALSE, tvb, offset, pinfo, tree, hf_mms_components_item);
}


static const ber_sequence_t T_components_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_components_item },
};

static int
dissect_mms_T_components(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      T_components_sequence_of, hf_index, ett_mms_T_components);

  return offset;
}
static int dissect_components_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_components(TRUE, tvb, offset, pinfo, tree, hf_mms_components);
}


static const ber_sequence_t T_structure_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_packed_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_components_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_T_structure(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_structure_sequence, hf_index, ett_mms_T_structure);

  return offset;
}
static int dissect_structure_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_structure(TRUE, tvb, offset, pinfo, tree, hf_mms_structure);
}



static int
dissect_mms_Integer32(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_localDetailCalling_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Integer32(TRUE, tvb, offset, pinfo, tree, hf_mms_localDetailCalling);
}
static int dissect_localDetailCalled_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Integer32(TRUE, tvb, offset, pinfo, tree, hf_mms_localDetailCalled);
}
static int dissect_ulsmID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Integer32(TRUE, tvb, offset, pinfo, tree, hf_mms_ulsmID);
}
static int dissect_bit_string_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Integer32(TRUE, tvb, offset, pinfo, tree, hf_mms_bit_string);
}
static int dissect_octet_string_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Integer32(TRUE, tvb, offset, pinfo, tree, hf_mms_octet_string);
}
static int dissect_visible_string_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Integer32(TRUE, tvb, offset, pinfo, tree, hf_mms_visible_string);
}
static int dissect_numberOfEntries_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Integer32(TRUE, tvb, offset, pinfo, tree, hf_mms_numberOfEntries);
}
static int dissect_frsmID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Integer32(TRUE, tvb, offset, pinfo, tree, hf_mms_frsmID);
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
  {   0, BER_CLASS_CON, 0, 0, dissect_typeName },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_array_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_structure_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_boolean_impl },
  {   4, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_bit_string_impl },
  {   5, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_integer_impl },
  {   6, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_unsigned_impl },
  {   9, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_octet_string_impl },
  {  10, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_visible_string_impl },
  {  11, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_generalized_time_impl },
  {  12, BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_binary_time_impl },
  {  13, BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_bcd_impl },
  {  15, BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_objId_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_TypeSpecification(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 TypeSpecification_choice, hf_index, ett_mms_TypeSpecification,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_variableDescription_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_address },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_typeSpecification },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_T_variableDescription(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_variableDescription_sequence, hf_index, ett_mms_T_variableDescription);

  return offset;
}
static int dissect_variableDescription_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_variableDescription(TRUE, tvb, offset, pinfo, tree, hf_mms_variableDescription);
}


static const ber_sequence_t T_indexRange_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_lowIndex_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_numberOfElements_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_T_indexRange(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_indexRange_sequence, hf_index, ett_mms_T_indexRange);

  return offset;
}
static int dissect_indexRange_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_indexRange(TRUE, tvb, offset, pinfo, tree, hf_mms_indexRange);
}


static const value_string mms_T_selectAccess_vals[] = {
  {   1, "component" },
  {   2, "index" },
  {   3, "indexRange" },
  {   4, "allElements" },
  { 0, NULL }
};

static const ber_choice_t T_selectAccess_choice[] = {
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_component_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_index_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_indexRange_impl },
  {   4, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_allElements_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_T_selectAccess(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_selectAccess_choice, hf_index, ett_mms_T_selectAccess,
                                 NULL);

  return offset;
}
static int dissect_selectAccess(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_selectAccess(FALSE, tvb, offset, pinfo, tree, hf_mms_selectAccess);
}


static const value_string mms_AlternateAccessSelection_vals[] = {
  { -1/*choice*/, "selectAccess" },
  { 0, NULL }
};

static const ber_choice_t AlternateAccessSelection_choice[] = {
  { -1/*choice*/, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_selectAccess },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_AlternateAccessSelection(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 AlternateAccessSelection_choice, hf_index, ett_mms_AlternateAccessSelection,
                                 NULL);

  return offset;
}
static int dissect_unnamed(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_AlternateAccessSelection(FALSE, tvb, offset, pinfo, tree, hf_mms_unnamed);
}
static int dissect_accesst(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_AlternateAccessSelection(FALSE, tvb, offset, pinfo, tree, hf_mms_accesst);
}


static const ber_sequence_t T_named_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_componentName_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_accesst },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_T_named(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_named_sequence, hf_index, ett_mms_T_named);

  return offset;
}
static int dissect_named_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_named(TRUE, tvb, offset, pinfo, tree, hf_mms_named);
}


static const value_string mms_AlternateAccess_item_vals[] = {
  {   0, "unnamed" },
  {   1, "named" },
  { 0, NULL }
};

static const ber_choice_t AlternateAccess_item_choice[] = {
  {   0, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_unnamed },
  {   1, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_named_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_AlternateAccess_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 AlternateAccess_item_choice, hf_index, ett_mms_AlternateAccess_item,
                                 NULL);

  return offset;
}
static int dissect_AlternateAccess_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_AlternateAccess_item(FALSE, tvb, offset, pinfo, tree, hf_mms_AlternateAccess_item);
}


static const ber_sequence_t AlternateAccess_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_AlternateAccess_item },
};

static int
dissect_mms_AlternateAccess(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      AlternateAccess_sequence_of, hf_index, ett_mms_AlternateAccess);

  return offset;
}
static int dissect_alternateAccess_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_AlternateAccess(TRUE, tvb, offset, pinfo, tree, hf_mms_alternateAccess);
}


static const ber_sequence_t ScatteredAccessDescription_item_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_componentName_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_variableSpecification },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_alternateAccess_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_ScatteredAccessDescription_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ScatteredAccessDescription_item_sequence, hf_index, ett_mms_ScatteredAccessDescription_item);

  return offset;
}
static int dissect_ScatteredAccessDescription_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ScatteredAccessDescription_item(FALSE, tvb, offset, pinfo, tree, hf_mms_ScatteredAccessDescription_item);
}


static const ber_sequence_t ScatteredAccessDescription_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ScatteredAccessDescription_item },
};

static int
dissect_mms_ScatteredAccessDescription(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      ScatteredAccessDescription_sequence_of, hf_index, ett_mms_ScatteredAccessDescription);

  return offset;
}
static int dissect_scatteredAccessDescription_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ScatteredAccessDescription(TRUE, tvb, offset, pinfo, tree, hf_mms_scatteredAccessDescription);
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
  {   0, BER_CLASS_CON, 0, 0, dissect_name },
  {   1, BER_CLASS_CON, 1, 0, dissect_address },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_variableDescription_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_scatteredAccessDescription_impl },
  {   4, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_invalidated_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_VariableSpecification(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 VariableSpecification_choice, hf_index, ett_mms_VariableSpecification,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_listOfVariable_item2_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_variableSpecification },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_alternateAccess_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_T_listOfVariable_item2(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_listOfVariable_item2_sequence, hf_index, ett_mms_T_listOfVariable_item2);

  return offset;
}
static int dissect_listOfVariable_item2(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_listOfVariable_item2(FALSE, tvb, offset, pinfo, tree, hf_mms_listOfVariable_item2);
}


static const ber_sequence_t T_listOfVariable2_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_listOfVariable_item2 },
};

static int
dissect_mms_T_listOfVariable2(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      T_listOfVariable2_sequence_of, hf_index, ett_mms_T_listOfVariable2);

  return offset;
}
static int dissect_listOfVariable2_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_listOfVariable2(TRUE, tvb, offset, pinfo, tree, hf_mms_listOfVariable2);
}


static const value_string mms_VariableAccessSpecification_vals[] = {
  {   0, "listOfVariable" },
  {   1, "variableListName" },
  { 0, NULL }
};

static const ber_choice_t VariableAccessSpecification_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_listOfVariable2_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_variableListName },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_VariableAccessSpecification(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 VariableAccessSpecification_choice, hf_index, ett_mms_VariableAccessSpecification,
                                 NULL);

  return offset;
}
static int dissect_variableAccessSpecificatn(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_VariableAccessSpecification(FALSE, tvb, offset, pinfo, tree, hf_mms_variableAccessSpecificatn);
}
static int dissect_variableAccessSpecification(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_VariableAccessSpecification(FALSE, tvb, offset, pinfo, tree, hf_mms_variableAccessSpecification);
}


static const ber_sequence_t Read_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_specificationWithResult_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_variableAccessSpecificatn },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_Read_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Read_Request_sequence, hf_index, ett_mms_Read_Request);

  return offset;
}
static int dissect_read_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Read_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_read);
}


static const ber_sequence_t SEQUENCE_OF_Data_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_listOfData_item },
};

static int
dissect_mms_SEQUENCE_OF_Data(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_Data_sequence_of, hf_index, ett_mms_SEQUENCE_OF_Data);

  return offset;
}
static int dissect_listOfData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_SEQUENCE_OF_Data(TRUE, tvb, offset, pinfo, tree, hf_mms_listOfData);
}
static int dissect_array1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_SEQUENCE_OF_Data(TRUE, tvb, offset, pinfo, tree, hf_mms_array1);
}
static int dissect_structure1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_SEQUENCE_OF_Data(TRUE, tvb, offset, pinfo, tree, hf_mms_structure1);
}



static int
dissect_mms_BIT_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}
static int dissect_bit_string1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_BIT_STRING(TRUE, tvb, offset, pinfo, tree, hf_mms_bit_string1);
}
static int dissect_booleanArray_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_BIT_STRING(TRUE, tvb, offset, pinfo, tree, hf_mms_booleanArray);
}



static int
dissect_mms_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_foo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_mms_foo);
}
static int dissect_others_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_INTEGER(TRUE, tvb, offset, pinfo, tree, hf_mms_others);
}
static int dissect_additionalCode_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_INTEGER(TRUE, tvb, offset, pinfo, tree, hf_mms_additionalCode);
}
static int dissect_integer1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_INTEGER(TRUE, tvb, offset, pinfo, tree, hf_mms_integer1);
}
static int dissect_unsigned1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_INTEGER(TRUE, tvb, offset, pinfo, tree, hf_mms_unsigned1);
}
static int dissect_bcd1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_INTEGER(TRUE, tvb, offset, pinfo, tree, hf_mms_bcd1);
}



static int
dissect_mms_FloatingPoint(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_floating_point_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_FloatingPoint(TRUE, tvb, offset, pinfo, tree, hf_mms_floating_point);
}



static int
dissect_mms_TimeOfDay(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_binary_time1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_TimeOfDay(TRUE, tvb, offset, pinfo, tree, hf_mms_binary_time1);
}
static int dissect_timeOfDayT_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_TimeOfDay(TRUE, tvb, offset, pinfo, tree, hf_mms_timeOfDayT);
}
static int dissect_startingTime_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_TimeOfDay(TRUE, tvb, offset, pinfo, tree, hf_mms_startingTime);
}
static int dissect_endingTime_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_TimeOfDay(TRUE, tvb, offset, pinfo, tree, hf_mms_endingTime);
}
static int dissect_timeSpecification_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_TimeOfDay(TRUE, tvb, offset, pinfo, tree, hf_mms_timeSpecification);
}
static int dissect_limitingTime_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_TimeOfDay(TRUE, tvb, offset, pinfo, tree, hf_mms_limitingTime);
}
static int dissect_occurenceTime_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_TimeOfDay(TRUE, tvb, offset, pinfo, tree, hf_mms_occurenceTime);
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
  { 0, NULL }
};

static const ber_choice_t Data_choice[] = {
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_array1_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_structure1_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_boolean1_impl },
  {   4, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_bit_string1_impl },
  {   5, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_integer1_impl },
  {   6, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_unsigned1_impl },
  {   7, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_floating_point_impl },
  {   9, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_octet_string1_impl },
  {  10, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_visible_string1_impl },
  {  12, BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_binary_time1_impl },
  {  13, BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_bcd1_impl },
  {  14, BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_booleanArray_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_Data(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Data_choice, hf_index, ett_mms_Data,
                                 NULL);

  return offset;
}


static const ber_sequence_t Write_Request_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_variableAccessSpecificatn },
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_listOfData_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_Write_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Write_Request_sequence, hf_index, ett_mms_Write_Request);

  return offset;
}
static int dissect_write_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Write_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_write);
}


static const value_string mms_GetVariableAccessAttributes_Request_vals[] = {
  {   0, "name" },
  {   1, "address" },
  { 0, NULL }
};

static const ber_choice_t GetVariableAccessAttributes_Request_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_name },
  {   1, BER_CLASS_CON, 1, 0, dissect_address },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_GetVariableAccessAttributes_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 GetVariableAccessAttributes_Request_choice, hf_index, ett_mms_GetVariableAccessAttributes_Request,
                                 NULL);

  return offset;
}
static int dissect_getVariableAccessAttributes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_GetVariableAccessAttributes_Request(FALSE, tvb, offset, pinfo, tree, hf_mms_getVariableAccessAttributes);
}


static const ber_sequence_t DefineNamedVariable_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_variableName },
  { BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_address },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_typeSpecification },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_DefineNamedVariable_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DefineNamedVariable_Request_sequence, hf_index, ett_mms_DefineNamedVariable_Request);

  return offset;
}
static int dissect_defineNamedVariable_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DefineNamedVariable_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_defineNamedVariable);
}


static const ber_sequence_t DefineScatteredAccess_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_scatteredAccessName },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_scatteredAccessDescription_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_DefineScatteredAccess_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DefineScatteredAccess_Request_sequence, hf_index, ett_mms_DefineScatteredAccess_Request);

  return offset;
}
static int dissect_defineScatteredAccess_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DefineScatteredAccess_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_defineScatteredAccess);
}



static int
dissect_mms_GetScatteredAccessAttributes_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_ObjectName(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_getScatteredAccessAttributes_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_GetScatteredAccessAttributes_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_getScatteredAccessAttributes);
}


static const value_string mms_T_scopeOfDelete_vals[] = {
  {   0, "specific" },
  {   1, "aa-specific" },
  {   2, "domain" },
  {   3, "vmd" },
  { 0, NULL }
};


static int
dissect_mms_T_scopeOfDelete(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_scopeOfDelete_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_scopeOfDelete(TRUE, tvb, offset, pinfo, tree, hf_mms_scopeOfDelete);
}


static const ber_sequence_t SEQUENCE_OF_ObjectName_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_listOfName_item },
};

static int
dissect_mms_SEQUENCE_OF_ObjectName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_ObjectName_sequence_of, hf_index, ett_mms_SEQUENCE_OF_ObjectName);

  return offset;
}
static int dissect_listOfName_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_SEQUENCE_OF_ObjectName(TRUE, tvb, offset, pinfo, tree, hf_mms_listOfName);
}
static int dissect_listOfVariableListName_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_SEQUENCE_OF_ObjectName(TRUE, tvb, offset, pinfo, tree, hf_mms_listOfVariableListName);
}
static int dissect_listOfTypeName_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_SEQUENCE_OF_ObjectName(TRUE, tvb, offset, pinfo, tree, hf_mms_listOfTypeName);
}
static int dissect_specific_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_SEQUENCE_OF_ObjectName(TRUE, tvb, offset, pinfo, tree, hf_mms_specific);
}
static int dissect_eventEnrollmentNames_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_SEQUENCE_OF_ObjectName(TRUE, tvb, offset, pinfo, tree, hf_mms_eventEnrollmentNames);
}


static const ber_sequence_t DeleteVariableAccess_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_scopeOfDelete_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_listOfName_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_domainName_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_DeleteVariableAccess_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DeleteVariableAccess_Request_sequence, hf_index, ett_mms_DeleteVariableAccess_Request);

  return offset;
}
static int dissect_deleteVariableAccess_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DeleteVariableAccess_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_deleteVariableAccess);
}


static const ber_sequence_t T_listOfVariable_item_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_variableSpecification },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_alternateAccess_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_T_listOfVariable_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_listOfVariable_item_sequence, hf_index, ett_mms_T_listOfVariable_item);

  return offset;
}
static int dissect_listOfVariable_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_listOfVariable_item(FALSE, tvb, offset, pinfo, tree, hf_mms_listOfVariable_item);
}


static const ber_sequence_t T_listOfVariable_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_listOfVariable_item },
};

static int
dissect_mms_T_listOfVariable(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      T_listOfVariable_sequence_of, hf_index, ett_mms_T_listOfVariable);

  return offset;
}
static int dissect_listOfVariable_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_listOfVariable(TRUE, tvb, offset, pinfo, tree, hf_mms_listOfVariable);
}


static const ber_sequence_t DefineNamedVariableList_Request_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_variableListName },
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_listOfVariable_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_DefineNamedVariableList_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DefineNamedVariableList_Request_sequence, hf_index, ett_mms_DefineNamedVariableList_Request);

  return offset;
}
static int dissect_defineNamedVariableList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DefineNamedVariableList_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_defineNamedVariableList);
}



static int
dissect_mms_GetNamedVariableListAttributes_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_ObjectName(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_getNamedVariableListAttributes_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_GetNamedVariableListAttributes_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_getNamedVariableListAttributes);
}


static const value_string mms_T_scopeOfDelete1_vals[] = {
  {   0, "specific" },
  {   1, "aa-specific" },
  {   2, "domain" },
  {   3, "vmd" },
  { 0, NULL }
};


static int
dissect_mms_T_scopeOfDelete1(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_scopeOfDelete1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_scopeOfDelete1(TRUE, tvb, offset, pinfo, tree, hf_mms_scopeOfDelete1);
}


static const ber_sequence_t DeleteNamedVariableList_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_scopeOfDelete1_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_listOfVariableListName_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_domainName_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_DeleteNamedVariableList_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DeleteNamedVariableList_Request_sequence, hf_index, ett_mms_DeleteNamedVariableList_Request);

  return offset;
}
static int dissect_deleteNamedVariableList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DeleteNamedVariableList_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_deleteNamedVariableList);
}


static const ber_sequence_t DefineNamedType_Request_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_typeName },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_typeSpecification },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_DefineNamedType_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DefineNamedType_Request_sequence, hf_index, ett_mms_DefineNamedType_Request);

  return offset;
}
static int dissect_defineNamedType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DefineNamedType_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_defineNamedType);
}



static int
dissect_mms_GetNamedTypeAttributes_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_ObjectName(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_getNamedTypeAttributes_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_GetNamedTypeAttributes_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_getNamedTypeAttributes);
}


static const value_string mms_T_scopeOfDelete2_vals[] = {
  {   0, "specific" },
  {   1, "aa-specific" },
  {   2, "domain" },
  {   3, "vmd" },
  { 0, NULL }
};


static int
dissect_mms_T_scopeOfDelete2(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_scopeOfDelete2_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_scopeOfDelete2(TRUE, tvb, offset, pinfo, tree, hf_mms_scopeOfDelete2);
}


static const ber_sequence_t DeleteNamedType_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_scopeOfDelete2_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_listOfTypeName_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_domainName_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_DeleteNamedType_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DeleteNamedType_Request_sequence, hf_index, ett_mms_DeleteNamedType_Request);

  return offset;
}
static int dissect_deleteNamedType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DeleteNamedType_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_deleteNamedType);
}


static const ber_sequence_t T_listOfPromptData_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_listOfPromptData_item },
};

static int
dissect_mms_T_listOfPromptData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      T_listOfPromptData_sequence_of, hf_index, ett_mms_T_listOfPromptData);

  return offset;
}
static int dissect_listOfPromptData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_listOfPromptData(TRUE, tvb, offset, pinfo, tree, hf_mms_listOfPromptData);
}


static const ber_sequence_t Input_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_operatorStationName_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_echo_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_listOfPromptData_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inputTimeOut_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_Input_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Input_Request_sequence, hf_index, ett_mms_Input_Request);

  return offset;
}
static int dissect_input_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Input_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_input);
}


static const ber_sequence_t T_listOfOutputData_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_listOfOutputData_item },
};

static int
dissect_mms_T_listOfOutputData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      T_listOfOutputData_sequence_of, hf_index, ett_mms_T_listOfOutputData);

  return offset;
}
static int dissect_listOfOutputData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_listOfOutputData(TRUE, tvb, offset, pinfo, tree, hf_mms_listOfOutputData);
}


static const ber_sequence_t Output_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_operatorStationName_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_listOfOutputData_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_Output_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Output_Request_sequence, hf_index, ett_mms_Output_Request);

  return offset;
}
static int dissect_output_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Output_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_output);
}



static int
dissect_mms_T_ap_title(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 23 "mms.cnf"
  offset=dissect_acse_AP_title(FALSE, tvb, offset, pinfo, tree, hf_mms_ap_title);



  return offset;
}
static int dissect_ap_title(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_ap_title(FALSE, tvb, offset, pinfo, tree, hf_mms_ap_title);
}



static int
dissect_mms_T_ap_invocation_id(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 26 "mms.cnf"
  offset=dissect_acse_AP_invocation_identifier(FALSE, tvb, offset, pinfo, tree, hf_mms_ap_invocation_id);



  return offset;
}
static int dissect_ap_invocation_id(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_ap_invocation_id(FALSE, tvb, offset, pinfo, tree, hf_mms_ap_invocation_id);
}



static int
dissect_mms_T_ae_qualifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 29 "mms.cnf"
  offset=dissect_acse_AE_qualifier(FALSE, tvb, offset, pinfo, tree, hf_mms_ae_qualifier);



  return offset;
}
static int dissect_ae_qualifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_ae_qualifier(FALSE, tvb, offset, pinfo, tree, hf_mms_ae_qualifier);
}



static int
dissect_mms_T_ae_invocation_id(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 32 "mms.cnf"
  offset=dissect_acse_AE_invocation_identifier(FALSE, tvb, offset, pinfo, tree, hf_mms_ae_invocation_id);



  return offset;
}
static int dissect_ae_invocation_id(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_ae_invocation_id(FALSE, tvb, offset, pinfo, tree, hf_mms_ae_invocation_id);
}


static const ber_sequence_t ApplicationReference_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_ap_title },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_ap_invocation_id },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_ae_qualifier },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_ae_invocation_id },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_ApplicationReference(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ApplicationReference_sequence, hf_index, ett_mms_ApplicationReference);

  return offset;
}
static int dissect_thirdParty_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ApplicationReference(TRUE, tvb, offset, pinfo, tree, hf_mms_thirdParty);
}
static int dissect_applicationToPreempt_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ApplicationReference(TRUE, tvb, offset, pinfo, tree, hf_mms_applicationToPreempt);
}
static int dissect_applicationReference(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ApplicationReference(FALSE, tvb, offset, pinfo, tree, hf_mms_applicationReference);
}
static int dissect_clientApplication(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ApplicationReference(FALSE, tvb, offset, pinfo, tree, hf_mms_clientApplication);
}
static int dissect_originatingApplication(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ApplicationReference(FALSE, tvb, offset, pinfo, tree, hf_mms_originatingApplication);
}
static int dissect_sourceFileServer_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ApplicationReference(TRUE, tvb, offset, pinfo, tree, hf_mms_sourceFileServer);
}


static const ber_sequence_t TakeControl_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_semaphoreName },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_namedToken_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_priority_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acceptableDelay_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_controlTimeOut_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_abortOnTimeOut_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_relinquishIfConnectionLost_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_applicationToPreempt_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_TakeControl_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   TakeControl_Request_sequence, hf_index, ett_mms_TakeControl_Request);

  return offset;
}
static int dissect_takeControl_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_TakeControl_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_takeControl);
}


static const ber_sequence_t RelinquishControl_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_semaphoreName },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_namedToken_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_RelinquishControl_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   RelinquishControl_Request_sequence, hf_index, ett_mms_RelinquishControl_Request);

  return offset;
}
static int dissect_relinquishControl_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_RelinquishControl_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_relinquishControl);
}



static int
dissect_mms_Unsigned16(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_numbersOfTokens_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Unsigned16(TRUE, tvb, offset, pinfo, tree, hf_mms_numbersOfTokens);
}
static int dissect_numberOfTokens_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Unsigned16(TRUE, tvb, offset, pinfo, tree, hf_mms_numberOfTokens);
}
static int dissect_numberOfOwnedTokens_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Unsigned16(TRUE, tvb, offset, pinfo, tree, hf_mms_numberOfOwnedTokens);
}
static int dissect_numberOfHungTokens_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Unsigned16(TRUE, tvb, offset, pinfo, tree, hf_mms_numberOfHungTokens);
}


static const ber_sequence_t DefineSemaphore_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_semaphoreName },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_numbersOfTokens_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_DefineSemaphore_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DefineSemaphore_Request_sequence, hf_index, ett_mms_DefineSemaphore_Request);

  return offset;
}
static int dissect_defineSemaphore_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DefineSemaphore_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_defineSemaphore);
}



static int
dissect_mms_DeleteSemaphore_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_ObjectName(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_deleteSemaphore_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DeleteSemaphore_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_deleteSemaphore);
}



static int
dissect_mms_ReportSemaphoreStatus_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_ObjectName(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_reportSemaphoreStatus_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ReportSemaphoreStatus_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_reportSemaphoreStatus);
}


static const ber_sequence_t ReportPoolSemaphoreStatus_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_semaphoreName },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_nameToStartAfter_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_ReportPoolSemaphoreStatus_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ReportPoolSemaphoreStatus_Request_sequence, hf_index, ett_mms_ReportPoolSemaphoreStatus_Request);

  return offset;
}
static int dissect_reportPoolSemaphoreStatus_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ReportPoolSemaphoreStatus_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_reportPoolSemaphoreStatus);
}


static const value_string mms_T_state_vals[] = {
  {   0, "queued" },
  {   1, "owner" },
  {   2, "hung" },
  { 0, NULL }
};


static int
dissect_mms_T_state(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_state2_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_state(TRUE, tvb, offset, pinfo, tree, hf_mms_state2);
}


static const ber_sequence_t ReportSemaphoreEntryStatus_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_semaphoreName },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_state2_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_entryIdToStartAfter_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_ReportSemaphoreEntryStatus_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ReportSemaphoreEntryStatus_Request_sequence, hf_index, ett_mms_ReportSemaphoreEntryStatus_Request);

  return offset;
}
static int dissect_reportSemaphoreEntryStatus_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ReportSemaphoreEntryStatus_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_reportSemaphoreEntryStatus);
}


static const ber_sequence_t T_listOfCapabilities1_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_listOfCapabilities_item },
};

static int
dissect_mms_T_listOfCapabilities1(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      T_listOfCapabilities1_sequence_of, hf_index, ett_mms_T_listOfCapabilities1);

  return offset;
}
static int dissect_listOfCapabilities1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_listOfCapabilities1(TRUE, tvb, offset, pinfo, tree, hf_mms_listOfCapabilities1);
}


static const ber_sequence_t InitiateDownloadSequence_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_domainName_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_listOfCapabilities1_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_sharable_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_InitiateDownloadSequence_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   InitiateDownloadSequence_Request_sequence, hf_index, ett_mms_InitiateDownloadSequence_Request);

  return offset;
}
static int dissect_initiateDownloadSequence_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_InitiateDownloadSequence_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_initiateDownloadSequence);
}



static int
dissect_mms_DownloadSegment_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_Identifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_downloadSegment_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DownloadSegment_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_downloadSegment);
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
dissect_mms_T_vmd_state(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_vmd_state_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_vmd_state(TRUE, tvb, offset, pinfo, tree, hf_mms_vmd_state);
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
dissect_mms_T_application_reference(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_application_reference_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_application_reference(TRUE, tvb, offset, pinfo, tree, hf_mms_application_reference);
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
dissect_mms_T_definition(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_definition_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_definition(TRUE, tvb, offset, pinfo, tree, hf_mms_definition);
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
dissect_mms_T_resource(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_resource_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_resource(TRUE, tvb, offset, pinfo, tree, hf_mms_resource);
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
dissect_mms_T_service(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_service_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_service(TRUE, tvb, offset, pinfo, tree, hf_mms_service);
}


static const value_string mms_T_service_preempt_vals[] = {
  {   0, "other" },
  {   1, "timeout" },
  {   2, "deadlock" },
  {   3, "cancel" },
  { 0, NULL }
};


static int
dissect_mms_T_service_preempt(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_service_preempt_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_service_preempt(TRUE, tvb, offset, pinfo, tree, hf_mms_service_preempt);
}


static const value_string mms_T_time_resolution_vals[] = {
  {   0, "other" },
  {   1, "unsupportable-time-resolution" },
  { 0, NULL }
};


static int
dissect_mms_T_time_resolution(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_time_resolution_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_time_resolution(TRUE, tvb, offset, pinfo, tree, hf_mms_time_resolution);
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
dissect_mms_T_access(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_access_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_access(TRUE, tvb, offset, pinfo, tree, hf_mms_access);
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
dissect_mms_T_initiate(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_initiate_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_initiate(TRUE, tvb, offset, pinfo, tree, hf_mms_initiate);
}


static const value_string mms_T_conclude_vals[] = {
  {   0, "other" },
  {   1, "further-communication-required" },
  { 0, NULL }
};


static int
dissect_mms_T_conclude(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_conclude_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_conclude(TRUE, tvb, offset, pinfo, tree, hf_mms_conclude);
}


static const value_string mms_T_cancel_vals[] = {
  {   0, "other" },
  {   1, "invoke-id-unknown" },
  {   2, "cancel-not-possible" },
  { 0, NULL }
};


static int
dissect_mms_T_cancel(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_cancel_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_cancel(TRUE, tvb, offset, pinfo, tree, hf_mms_cancel);
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
dissect_mms_T_file(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_file_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_file(TRUE, tvb, offset, pinfo, tree, hf_mms_file);
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
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_vmd_state_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_application_reference_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_definition_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_resource_impl },
  {   4, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_service_impl },
  {   5, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_service_preempt_impl },
  {   6, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_time_resolution_impl },
  {   7, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_access_impl },
  {   8, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_initiate_impl },
  {   9, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_conclude_impl },
  {  10, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_cancel_impl },
  {  11, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_file_impl },
  {  12, BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_others_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_T_errorClass(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_errorClass_choice, hf_index, ett_mms_T_errorClass,
                                 NULL);

  return offset;
}
static int dissect_errorClass(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_errorClass(FALSE, tvb, offset, pinfo, tree, hf_mms_errorClass);
}


static const value_string mms_ObtainFile_Error_vals[] = {
  {   0, "source-file" },
  {   1, "destination-file" },
  { 0, NULL }
};


static int
dissect_mms_ObtainFile_Error(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_obtainFile2_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ObtainFile_Error(TRUE, tvb, offset, pinfo, tree, hf_mms_obtainFile2);
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
dissect_mms_ProgramInvocationState(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_state1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ProgramInvocationState(TRUE, tvb, offset, pinfo, tree, hf_mms_state1);
}



static int
dissect_mms_Start_Error(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_ProgramInvocationState(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_start2_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Start_Error(TRUE, tvb, offset, pinfo, tree, hf_mms_start2);
}



static int
dissect_mms_Stop_Error(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_ProgramInvocationState(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_stop2_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Stop_Error(TRUE, tvb, offset, pinfo, tree, hf_mms_stop2);
}



static int
dissect_mms_Resume_Error(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_ProgramInvocationState(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_resume2_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Resume_Error(TRUE, tvb, offset, pinfo, tree, hf_mms_resume2);
}



static int
dissect_mms_Reset_Error(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_ProgramInvocationState(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_reset2_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Reset_Error(TRUE, tvb, offset, pinfo, tree, hf_mms_reset2);
}



static int
dissect_mms_DeleteVariableAccess_Error(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_Unsigned32(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_deleteVariableAccess2_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DeleteVariableAccess_Error(TRUE, tvb, offset, pinfo, tree, hf_mms_deleteVariableAccess2);
}



static int
dissect_mms_DeleteNamedVariableList_Error(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_Unsigned32(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_deleteNamedVariableList2_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DeleteNamedVariableList_Error(TRUE, tvb, offset, pinfo, tree, hf_mms_deleteNamedVariableList2);
}



static int
dissect_mms_DeleteNamedType_Error(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_Unsigned32(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_deleteNamedType2_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DeleteNamedType_Error(TRUE, tvb, offset, pinfo, tree, hf_mms_deleteNamedType2);
}



static int
dissect_mms_DefineEventEnrollment_Error(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_ObjectName(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_defineEventEnrollment_Error(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DefineEventEnrollment_Error(FALSE, tvb, offset, pinfo, tree, hf_mms_defineEventEnrollment_Error);
}


static const value_string mms_FileRename_Error_vals[] = {
  {   0, "source-file" },
  {   1, "destination-file" },
  { 0, NULL }
};


static int
dissect_mms_FileRename_Error(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_fileRename2_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_FileRename_Error(TRUE, tvb, offset, pinfo, tree, hf_mms_fileRename2);
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
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_obtainFile2_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_start2_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_stop2_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_resume2_impl },
  {   4, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_reset2_impl },
  {   5, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_deleteVariableAccess2_impl },
  {   6, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_deleteNamedVariableList2_impl },
  {   7, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_deleteNamedType2_impl },
  {   8, BER_CLASS_CON, 8, 0, dissect_defineEventEnrollment_Error },
  {   9, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_fileRename2_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_T_serviceSpecificInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_serviceSpecificInformation_choice, hf_index, ett_mms_T_serviceSpecificInformation,
                                 NULL);

  return offset;
}
static int dissect_serviceSpecificInformation(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_serviceSpecificInformation(FALSE, tvb, offset, pinfo, tree, hf_mms_serviceSpecificInformation);
}


static const ber_sequence_t ServiceError_sequence[] = {
  { BER_CLASS_CON, 0, 0, dissect_errorClass },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_additionalCode_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_additionalDescription_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_serviceSpecificInformation },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_ServiceError(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ServiceError_sequence, hf_index, ett_mms_ServiceError);

  return offset;
}
static int dissect_serviceError_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ServiceError(TRUE, tvb, offset, pinfo, tree, hf_mms_serviceError);
}
static int dissect_discard_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ServiceError(TRUE, tvb, offset, pinfo, tree, hf_mms_discard);
}
static int dissect_failure1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ServiceError(TRUE, tvb, offset, pinfo, tree, hf_mms_failure1);
}


static const ber_sequence_t TerminateDownloadSequence_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_domainName_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_discard_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_TerminateDownloadSequence_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   TerminateDownloadSequence_Request_sequence, hf_index, ett_mms_TerminateDownloadSequence_Request);

  return offset;
}
static int dissect_terminateDownloadSequence_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_TerminateDownloadSequence_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_terminateDownloadSequence);
}



static int
dissect_mms_InitiateUploadSequence_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_Identifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_initiateUploadSequence_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_InitiateUploadSequence_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_initiateUploadSequence);
}



static int
dissect_mms_UploadSegment_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_Integer32(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_uploadSegment_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_UploadSegment_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_uploadSegment);
}



static int
dissect_mms_TerminateUploadSequence_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_Integer32(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_terminateUploadSequence_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_TerminateUploadSequence_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_terminateUploadSequence);
}


static const ber_sequence_t T_listOfCapabilities3_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_listOfCapabilities_item },
};

static int
dissect_mms_T_listOfCapabilities3(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      T_listOfCapabilities3_sequence_of, hf_index, ett_mms_T_listOfCapabilities3);

  return offset;
}
static int dissect_listOfCapabilities3_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_listOfCapabilities3(TRUE, tvb, offset, pinfo, tree, hf_mms_listOfCapabilities3);
}



static int
dissect_mms_GraphicString(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GraphicString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_FileName_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_GraphicString(FALSE, tvb, offset, pinfo, tree, hf_mms_FileName_item);
}


static const ber_sequence_t FileName_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_GraphicString, BER_FLAGS_NOOWNTAG, dissect_FileName_item },
};

static int
dissect_mms_FileName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      FileName_sequence_of, hf_index, ett_mms_FileName);

  return offset;
}
static int dissect_fileName_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_FileName(TRUE, tvb, offset, pinfo, tree, hf_mms_fileName);
}
static int dissect_filenName_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_FileName(TRUE, tvb, offset, pinfo, tree, hf_mms_filenName);
}
static int dissect_sourceFile_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_FileName(TRUE, tvb, offset, pinfo, tree, hf_mms_sourceFile);
}
static int dissect_destinationFile_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_FileName(TRUE, tvb, offset, pinfo, tree, hf_mms_destinationFile);
}
static int dissect_currentFileName_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_FileName(TRUE, tvb, offset, pinfo, tree, hf_mms_currentFileName);
}
static int dissect_newFileName_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_FileName(TRUE, tvb, offset, pinfo, tree, hf_mms_newFileName);
}
static int dissect_fileSpecification_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_FileName(TRUE, tvb, offset, pinfo, tree, hf_mms_fileSpecification);
}
static int dissect_continueAfter3_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_FileName(TRUE, tvb, offset, pinfo, tree, hf_mms_continueAfter3);
}
static int dissect_filename_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_FileName(TRUE, tvb, offset, pinfo, tree, hf_mms_filename);
}


static const ber_sequence_t RequestDomainDownload_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_domainName_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_listOfCapabilities3_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_sharable_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_fileName_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_RequestDomainDownload_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   RequestDomainDownload_Request_sequence, hf_index, ett_mms_RequestDomainDownload_Request);

  return offset;
}
static int dissect_requestDomainDownload_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_RequestDomainDownload_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_requestDomainDownload);
}


static const ber_sequence_t RequestDomainUpload_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_domainName_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_fileName_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_RequestDomainUpload_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   RequestDomainUpload_Request_sequence, hf_index, ett_mms_RequestDomainUpload_Request);

  return offset;
}
static int dissect_requestDomainUpload_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_RequestDomainUpload_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_requestDomainUpload);
}


static const ber_sequence_t T_listOfCapabilities4_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_listOfCapabilities_item },
};

static int
dissect_mms_T_listOfCapabilities4(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      T_listOfCapabilities4_sequence_of, hf_index, ett_mms_T_listOfCapabilities4);

  return offset;
}
static int dissect_listOfCapabilities4_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_listOfCapabilities4(TRUE, tvb, offset, pinfo, tree, hf_mms_listOfCapabilities4);
}


static const ber_sequence_t LoadDomainContent_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_domainName_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_listOfCapabilities4_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_sharable_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_fileName_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_thirdParty_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_LoadDomainContent_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   LoadDomainContent_Request_sequence, hf_index, ett_mms_LoadDomainContent_Request);

  return offset;
}
static int dissect_loadDomainContent_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_LoadDomainContent_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_loadDomainContent);
}


static const ber_sequence_t StoreDomainContent_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_domainName_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_filenName_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_thirdParty_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_StoreDomainContent_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   StoreDomainContent_Request_sequence, hf_index, ett_mms_StoreDomainContent_Request);

  return offset;
}
static int dissect_storeDomainContent_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_StoreDomainContent_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_storeDomainContent);
}



static int
dissect_mms_DeleteDomain_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_Identifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_deleteDomain_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DeleteDomain_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_deleteDomain);
}



static int
dissect_mms_GetDomainAttributes_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_Identifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_getDomainAttributes_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_GetDomainAttributes_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_getDomainAttributes);
}


static const ber_sequence_t SEQUENCE_OF_Identifier_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_listOfIdentifier_item },
};

static int
dissect_mms_SEQUENCE_OF_Identifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_Identifier_sequence_of, hf_index, ett_mms_SEQUENCE_OF_Identifier);

  return offset;
}
static int dissect_listOfIdentifier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_SEQUENCE_OF_Identifier(TRUE, tvb, offset, pinfo, tree, hf_mms_listOfIdentifier);
}
static int dissect_listOfProgramInvocations_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_SEQUENCE_OF_Identifier(TRUE, tvb, offset, pinfo, tree, hf_mms_listOfProgramInvocations);
}
static int dissect_listOfDomainName_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_SEQUENCE_OF_Identifier(TRUE, tvb, offset, pinfo, tree, hf_mms_listOfDomainName);
}
static int dissect_listOfDomainNames_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_SEQUENCE_OF_Identifier(TRUE, tvb, offset, pinfo, tree, hf_mms_listOfDomainNames);
}


static const ber_sequence_t CreateProgramInvocation_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_programInvocationName_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_listOfDomainName_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_reusable_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_monitorType_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_CreateProgramInvocation_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CreateProgramInvocation_Request_sequence, hf_index, ett_mms_CreateProgramInvocation_Request);

  return offset;
}
static int dissect_createProgramInvocation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_CreateProgramInvocation_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_createProgramInvocation);
}



static int
dissect_mms_DeleteProgramInvocation_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_Identifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_deleteProgramInvocation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DeleteProgramInvocation_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_deleteProgramInvocation);
}


static const value_string mms_T_executionArgument_vals[] = {
  {   0, "simpleString" },
  {   1, "encodedString" },
  { 0, NULL }
};

static const ber_choice_t T_executionArgument_choice[] = {
  {   0, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_simpleString_impl },
  {   1, BER_CLASS_UNI, 8, BER_FLAGS_NOOWNTAG, dissect_encodedString },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_T_executionArgument(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_executionArgument_choice, hf_index, ett_mms_T_executionArgument,
                                 NULL);

  return offset;
}
static int dissect_executionArgument(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_executionArgument(FALSE, tvb, offset, pinfo, tree, hf_mms_executionArgument);
}


static const ber_sequence_t Start_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_programInvocationName_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_executionArgument },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_Start_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Start_Request_sequence, hf_index, ett_mms_Start_Request);

  return offset;
}
static int dissect_start_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Start_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_start);
}


static const ber_sequence_t Stop_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_programInvocationName_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_Stop_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Stop_Request_sequence, hf_index, ett_mms_Stop_Request);

  return offset;
}
static int dissect_stop_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Stop_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_stop);
}


static const value_string mms_T_executionArgument1_vals[] = {
  {   0, "simpleString" },
  {   1, "encodedString" },
  { 0, NULL }
};

static const ber_choice_t T_executionArgument1_choice[] = {
  {   0, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_simpleString_impl },
  {   1, BER_CLASS_UNI, 8, BER_FLAGS_NOOWNTAG, dissect_encodedString },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_T_executionArgument1(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_executionArgument1_choice, hf_index, ett_mms_T_executionArgument1,
                                 NULL);

  return offset;
}
static int dissect_executionArgument1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_executionArgument1(FALSE, tvb, offset, pinfo, tree, hf_mms_executionArgument1);
}


static const ber_sequence_t Resume_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_programInvocationName_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_executionArgument1 },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_Resume_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Resume_Request_sequence, hf_index, ett_mms_Resume_Request);

  return offset;
}
static int dissect_resume_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Resume_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_resume);
}


static const ber_sequence_t Reset_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_programInvocationName_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_Reset_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Reset_Request_sequence, hf_index, ett_mms_Reset_Request);

  return offset;
}
static int dissect_reset_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Reset_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_reset);
}


static const ber_sequence_t Kill_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_programInvocationName_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_Kill_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Kill_Request_sequence, hf_index, ett_mms_Kill_Request);

  return offset;
}
static int dissect_kill_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Kill_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_kill);
}



static int
dissect_mms_GetProgramInvocationAttributes_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_Identifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_getProgramInvocationAttributes_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_GetProgramInvocationAttributes_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_getProgramInvocationAttributes);
}


static const ber_sequence_t ObtainFile_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sourceFileServer_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sourceFile_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_destinationFile_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_ObtainFile_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ObtainFile_Request_sequence, hf_index, ett_mms_ObtainFile_Request);

  return offset;
}
static int dissect_obtainFile_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ObtainFile_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_obtainFile);
}


static const value_string mms_EC_Class_vals[] = {
  {   0, "network-triggered" },
  {   1, "monitored" },
  { 0, NULL }
};


static int
dissect_mms_EC_Class(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_class1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_EC_Class(TRUE, tvb, offset, pinfo, tree, hf_mms_class1);
}


static const ber_sequence_t DefineEventCondition_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_eventConditionName },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_class1_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_prio_rity_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_severity_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_alarmSummaryReports_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_monitoredVariable },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_evaluationInterval_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_DefineEventCondition_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DefineEventCondition_Request_sequence, hf_index, ett_mms_DefineEventCondition_Request);

  return offset;
}
static int dissect_defineEventCondition_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DefineEventCondition_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_defineEventCondition);
}


static const value_string mms_DeleteEventCondition_Request_vals[] = {
  {   0, "specific" },
  {   1, "aa-specific" },
  {   2, "domain" },
  {   3, "vmd" },
  { 0, NULL }
};

static const ber_choice_t DeleteEventCondition_Request_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_specific_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_aa_specific1_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_domain_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_vmd_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_DeleteEventCondition_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 DeleteEventCondition_Request_choice, hf_index, ett_mms_DeleteEventCondition_Request,
                                 NULL);

  return offset;
}
static int dissect_deleteEventCondition(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DeleteEventCondition_Request(FALSE, tvb, offset, pinfo, tree, hf_mms_deleteEventCondition);
}



static int
dissect_mms_GetEventConditionAttributes_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_ObjectName(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_getEventConditionAttributes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_GetEventConditionAttributes_Request(FALSE, tvb, offset, pinfo, tree, hf_mms_getEventConditionAttributes);
}



static int
dissect_mms_ReportEventConditionStatus_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_ObjectName(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_reportEventConditionStatus(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ReportEventConditionStatus_Request(FALSE, tvb, offset, pinfo, tree, hf_mms_reportEventConditionStatus);
}


static const ber_sequence_t AlterEventConditionMonitoring_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_eventConditionName },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_enabled_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_priority_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_alarmSummaryReports_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_evaluationInterval_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_AlterEventConditionMonitoring_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AlterEventConditionMonitoring_Request_sequence, hf_index, ett_mms_AlterEventConditionMonitoring_Request);

  return offset;
}
static int dissect_alterEventConditionMonitoring_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_AlterEventConditionMonitoring_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_alterEventConditionMonitoring);
}


static const ber_sequence_t TriggerEvent_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_eventConditionName },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_priority_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_TriggerEvent_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   TriggerEvent_Request_sequence, hf_index, ett_mms_TriggerEvent_Request);

  return offset;
}
static int dissect_triggerEvent_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_TriggerEvent_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_triggerEvent);
}


static const ber_sequence_t DefineEventAction_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_eventActionName },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_listOfModifier_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_DefineEventAction_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DefineEventAction_Request_sequence, hf_index, ett_mms_DefineEventAction_Request);

  return offset;
}
static int dissect_defineEventAction_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DefineEventAction_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_defineEventAction);
}


static const value_string mms_DeleteEventAction_Request_vals[] = {
  {   0, "specific" },
  {   1, "aa-specific" },
  {   3, "domain" },
  {   4, "vmd" },
  { 0, NULL }
};

static const ber_choice_t DeleteEventAction_Request_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_specific_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_aa_specific1_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_domain_impl },
  {   4, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_vmd_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_DeleteEventAction_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 DeleteEventAction_Request_choice, hf_index, ett_mms_DeleteEventAction_Request,
                                 NULL);

  return offset;
}
static int dissect_deleteEventAction(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DeleteEventAction_Request(FALSE, tvb, offset, pinfo, tree, hf_mms_deleteEventAction);
}



static int
dissect_mms_GetEventActionAttributes_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_ObjectName(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_getEventActionAttributes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_GetEventActionAttributes_Request(FALSE, tvb, offset, pinfo, tree, hf_mms_getEventActionAttributes);
}



static int
dissect_mms_ReportEventActionStatus_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_ObjectName(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_reportEventActionStatus(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ReportEventActionStatus_Request(FALSE, tvb, offset, pinfo, tree, hf_mms_reportEventActionStatus);
}


static const value_string mms_AlarmAckRule_vals[] = {
  {   0, "none" },
  {   1, "simple" },
  {   2, "ack-active" },
  {   3, "ack-all" },
  { 0, NULL }
};


static int
dissect_mms_AlarmAckRule(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_alarmAcknowledgementRule_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_AlarmAckRule(TRUE, tvb, offset, pinfo, tree, hf_mms_alarmAcknowledgementRule);
}
static int dissect_alarmAcknowledgmentRule_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_AlarmAckRule(TRUE, tvb, offset, pinfo, tree, hf_mms_alarmAcknowledgmentRule);
}


static const ber_sequence_t DefineEventEnrollment_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_eventEnrollmentName },
  { BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_eventConditionName },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_eventConditionTransition_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_alarmAcknowledgementRule_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_eventActionName },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_clientApplication },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_DefineEventEnrollment_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DefineEventEnrollment_Request_sequence, hf_index, ett_mms_DefineEventEnrollment_Request);

  return offset;
}
static int dissect_defineEventEnrollment_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DefineEventEnrollment_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_defineEventEnrollment);
}


static const value_string mms_DeleteEventEnrollment_Request_vals[] = {
  {   0, "specific" },
  {   1, "ec" },
  {   2, "ea" },
  { 0, NULL }
};

static const ber_choice_t DeleteEventEnrollment_Request_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_specific_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_ec },
  {   2, BER_CLASS_CON, 2, 0, dissect_ea },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_DeleteEventEnrollment_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 DeleteEventEnrollment_Request_choice, hf_index, ett_mms_DeleteEventEnrollment_Request,
                                 NULL);

  return offset;
}
static int dissect_deleteEventEnrollment(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DeleteEventEnrollment_Request(FALSE, tvb, offset, pinfo, tree, hf_mms_deleteEventEnrollment);
}


static const ber_sequence_t AlterEventEnrollment_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_eventEnrollmentName },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_eventConditionTransitions_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_alarmAcknowledgmentRule_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_AlterEventEnrollment_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AlterEventEnrollment_Request_sequence, hf_index, ett_mms_AlterEventEnrollment_Request);

  return offset;
}
static int dissect_alterEventEnrollment_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_AlterEventEnrollment_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_alterEventEnrollment);
}



static int
dissect_mms_ReportEventEnrollmentStatus_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_ObjectName(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_reportEventEnrollmentStatus(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ReportEventEnrollmentStatus_Request(FALSE, tvb, offset, pinfo, tree, hf_mms_reportEventEnrollmentStatus);
}


static const value_string mms_T_scopeOfRequest_vals[] = {
  {   0, "specific" },
  {   1, "client" },
  {   2, "ec" },
  {   3, "ea" },
  { 0, NULL }
};


static int
dissect_mms_T_scopeOfRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_scopeOfRequest_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_scopeOfRequest(TRUE, tvb, offset, pinfo, tree, hf_mms_scopeOfRequest);
}


static const ber_sequence_t GetEventEnrollmentAttributes_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_scopeOfRequest_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_eventEnrollmentNames_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_clientApplication },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_eventConditionName },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_eventActionName },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_continueAfter2 },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_GetEventEnrollmentAttributes_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   GetEventEnrollmentAttributes_Request_sequence, hf_index, ett_mms_GetEventEnrollmentAttributes_Request);

  return offset;
}
static int dissect_getEventEnrollmentAttributes_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_GetEventEnrollmentAttributes_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_getEventEnrollmentAttributes);
}


static const value_string mms_EC_State_vals[] = {
  {   0, "disabled" },
  {   1, "idle" },
  {   2, "active" },
  { 0, NULL }
};


static int
dissect_mms_EC_State(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_currentState_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_EC_State(TRUE, tvb, offset, pinfo, tree, hf_mms_currentState);
}
static int dissect_acknowledgedState_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_EC_State(TRUE, tvb, offset, pinfo, tree, hf_mms_acknowledgedState);
}


static const value_string mms_EventTime_vals[] = {
  {   0, "timeOfDayT" },
  {   1, "timeSequenceIdentifier" },
  { 0, NULL }
};

static const ber_choice_t EventTime_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_timeOfDayT_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_timeSequenceIdentifier_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_EventTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 EventTime_choice, hf_index, ett_mms_EventTime,
                                 NULL);

  return offset;
}
static int dissect_timeOfLastTransitionToActive(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_EventTime(FALSE, tvb, offset, pinfo, tree, hf_mms_timeOfLastTransitionToActive);
}
static int dissect_timeOfLastTransitionToIdle(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_EventTime(FALSE, tvb, offset, pinfo, tree, hf_mms_timeOfLastTransitionToIdle);
}
static int dissect_transitionTime(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_EventTime(FALSE, tvb, offset, pinfo, tree, hf_mms_transitionTime);
}
static int dissect_timeOfAcknowledgedTransition(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_EventTime(FALSE, tvb, offset, pinfo, tree, hf_mms_timeOfAcknowledgedTransition);
}
static int dissect_timeActiveAcknowledged(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_EventTime(FALSE, tvb, offset, pinfo, tree, hf_mms_timeActiveAcknowledged);
}
static int dissect_timeIdleAcknowledged(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_EventTime(FALSE, tvb, offset, pinfo, tree, hf_mms_timeIdleAcknowledged);
}


static const ber_sequence_t AcknowledgeEventNotification_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_eventEnrollmentName },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_acknowledgedState_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_NOTCHKTAG, dissect_timeOfAcknowledgedTransition },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_AcknowledgeEventNotification_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AcknowledgeEventNotification_Request_sequence, hf_index, ett_mms_AcknowledgeEventNotification_Request);

  return offset;
}
static int dissect_acknowledgeEventNotification_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_AcknowledgeEventNotification_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_acknowledgeEventNotification);
}


static const value_string mms_T_acknowledgmentFilter_vals[] = {
  {   0, "not-acked" },
  {   1, "acked" },
  {   2, "all" },
  { 0, NULL }
};


static int
dissect_mms_T_acknowledgmentFilter(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_acknowledgmentFilter_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_acknowledgmentFilter(TRUE, tvb, offset, pinfo, tree, hf_mms_acknowledgmentFilter);
}


static const ber_sequence_t T_severityFilter_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mostSevere_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_leastSevere_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_T_severityFilter(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_severityFilter_sequence, hf_index, ett_mms_T_severityFilter);

  return offset;
}
static int dissect_severityFilter_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_severityFilter(TRUE, tvb, offset, pinfo, tree, hf_mms_severityFilter);
}


static const ber_sequence_t GetAlarmSummary_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_enrollmentsOnly_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_activeAlarmsOnly_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acknowledgmentFilter_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_severityFilter_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_continueAfter2 },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_GetAlarmSummary_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   GetAlarmSummary_Request_sequence, hf_index, ett_mms_GetAlarmSummary_Request);

  return offset;
}
static int dissect_getAlarmSummary_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_GetAlarmSummary_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_getAlarmSummary);
}


static const value_string mms_T_acknowledgmentFilter1_vals[] = {
  {   0, "not-acked" },
  {   1, "acked" },
  {   2, "all" },
  { 0, NULL }
};


static int
dissect_mms_T_acknowledgmentFilter1(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_acknowledgmentFilter1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_acknowledgmentFilter1(TRUE, tvb, offset, pinfo, tree, hf_mms_acknowledgmentFilter1);
}


static const ber_sequence_t T_severityFilter1_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mostSevere_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_leastSevere_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_T_severityFilter1(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_severityFilter1_sequence, hf_index, ett_mms_T_severityFilter1);

  return offset;
}
static int dissect_severityFilter1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_severityFilter1(TRUE, tvb, offset, pinfo, tree, hf_mms_severityFilter1);
}


static const ber_sequence_t GetAlarmEnrollmentSummary_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_enrollmentsOnly_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_activeAlarmsOnly_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acknowledgmentFilter1_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_severityFilter1_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_continueAfter2 },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_GetAlarmEnrollmentSummary_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   GetAlarmEnrollmentSummary_Request_sequence, hf_index, ett_mms_GetAlarmEnrollmentSummary_Request);

  return offset;
}
static int dissect_getAlarmEnrollmentSummary_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_GetAlarmEnrollmentSummary_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_getAlarmEnrollmentSummary);
}


static const value_string mms_T_rangeStartSpecification_vals[] = {
  {   0, "startingTime" },
  {   1, "startingEntry" },
  { 0, NULL }
};

static const ber_choice_t T_rangeStartSpecification_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_startingTime_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_startingEntry_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_T_rangeStartSpecification(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_rangeStartSpecification_choice, hf_index, ett_mms_T_rangeStartSpecification,
                                 NULL);

  return offset;
}
static int dissect_rangeStartSpecification(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_rangeStartSpecification(FALSE, tvb, offset, pinfo, tree, hf_mms_rangeStartSpecification);
}


static const value_string mms_T_rangeStopSpecification_vals[] = {
  {   0, "endingTime" },
  {   1, "numberOfEntries" },
  { 0, NULL }
};

static const ber_choice_t T_rangeStopSpecification_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_endingTime_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_numberOfEntries_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_T_rangeStopSpecification(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_rangeStopSpecification_choice, hf_index, ett_mms_T_rangeStopSpecification,
                                 NULL);

  return offset;
}
static int dissect_rangeStopSpecification(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_rangeStopSpecification(FALSE, tvb, offset, pinfo, tree, hf_mms_rangeStopSpecification);
}


static const ber_sequence_t T_listOfVariables_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_listOfVariables_item },
};

static int
dissect_mms_T_listOfVariables(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      T_listOfVariables_sequence_of, hf_index, ett_mms_T_listOfVariables);

  return offset;
}
static int dissect_listOfVariables_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_listOfVariables(TRUE, tvb, offset, pinfo, tree, hf_mms_listOfVariables);
}


static const ber_sequence_t T_entryToStartAfter_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_timeSpecification_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_entrySpecification_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_T_entryToStartAfter(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_entryToStartAfter_sequence, hf_index, ett_mms_T_entryToStartAfter);

  return offset;
}
static int dissect_entryToStartAfter_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_entryToStartAfter(TRUE, tvb, offset, pinfo, tree, hf_mms_entryToStartAfter);
}


static const ber_sequence_t ReadJournal_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_journalName },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_rangeStartSpecification },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_rangeStopSpecification },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_listOfVariables_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_entryToStartAfter_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_ReadJournal_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ReadJournal_Request_sequence, hf_index, ett_mms_ReadJournal_Request);

  return offset;
}
static int dissect_readJournal_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ReadJournal_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_readJournal);
}



static int
dissect_mms_JOU_Additional_Detail(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_additionalDetail(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_JOU_Additional_Detail(FALSE, tvb, offset, pinfo, tree, hf_mms_additionalDetail);
}


static const ber_sequence_t T_event_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_eventConditionName },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_currentState_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_T_event(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_event_sequence, hf_index, ett_mms_T_event);

  return offset;
}
static int dissect_event_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_event(TRUE, tvb, offset, pinfo, tree, hf_mms_event);
}


static const ber_sequence_t T_listOfVariables_item_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_variableTag_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_valueSpecification },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_T_listOfVariables_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_listOfVariables_item_sequence, hf_index, ett_mms_T_listOfVariables_item);

  return offset;
}
static int dissect_listOfVariables_item1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_listOfVariables_item(FALSE, tvb, offset, pinfo, tree, hf_mms_listOfVariables_item1);
}


static const ber_sequence_t T_listOfVariables1_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_listOfVariables_item1 },
};

static int
dissect_mms_T_listOfVariables1(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      T_listOfVariables1_sequence_of, hf_index, ett_mms_T_listOfVariables1);

  return offset;
}
static int dissect_listOfVariables1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_listOfVariables1(TRUE, tvb, offset, pinfo, tree, hf_mms_listOfVariables1);
}


static const ber_sequence_t T_data_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_event_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_listOfVariables1_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_T_data(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_data_sequence, hf_index, ett_mms_T_data);

  return offset;
}
static int dissect_data_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_data(TRUE, tvb, offset, pinfo, tree, hf_mms_data);
}


static const value_string mms_T_entryForm_vals[] = {
  {   2, "data" },
  {   3, "annotation" },
  { 0, NULL }
};

static const ber_choice_t T_entryForm_choice[] = {
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_data_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_annotation_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_T_entryForm(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_entryForm_choice, hf_index, ett_mms_T_entryForm,
                                 NULL);

  return offset;
}
static int dissect_entryForm(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_entryForm(FALSE, tvb, offset, pinfo, tree, hf_mms_entryForm);
}


static const ber_sequence_t EntryContent_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_occurenceTime_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_additionalDetail },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_entryForm },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_EntryContent(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   EntryContent_sequence, hf_index, ett_mms_EntryContent);

  return offset;
}
static int dissect_entryContent_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_EntryContent(TRUE, tvb, offset, pinfo, tree, hf_mms_entryContent);
}
static int dissect_listOfJournalEntry_item1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_EntryContent(FALSE, tvb, offset, pinfo, tree, hf_mms_listOfJournalEntry_item1);
}


static const ber_sequence_t SEQUENCE_OF_EntryContent_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_listOfJournalEntry_item1 },
};

static int
dissect_mms_SEQUENCE_OF_EntryContent(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_EntryContent_sequence_of, hf_index, ett_mms_SEQUENCE_OF_EntryContent);

  return offset;
}
static int dissect_listOfJournalEntry1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_SEQUENCE_OF_EntryContent(TRUE, tvb, offset, pinfo, tree, hf_mms_listOfJournalEntry1);
}


static const ber_sequence_t WriteJournal_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_journalName },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_listOfJournalEntry1_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_WriteJournal_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   WriteJournal_Request_sequence, hf_index, ett_mms_WriteJournal_Request);

  return offset;
}
static int dissect_writeJournal_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_WriteJournal_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_writeJournal);
}


static const ber_sequence_t T_limitSpecification_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_limitingTime_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_limitingEntry_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_T_limitSpecification(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_limitSpecification_sequence, hf_index, ett_mms_T_limitSpecification);

  return offset;
}
static int dissect_limitSpecification_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_limitSpecification(TRUE, tvb, offset, pinfo, tree, hf_mms_limitSpecification);
}


static const ber_sequence_t InitializeJournal_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_journalName },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_limitSpecification_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_InitializeJournal_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   InitializeJournal_Request_sequence, hf_index, ett_mms_InitializeJournal_Request);

  return offset;
}
static int dissect_initializeJournal_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_InitializeJournal_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_initializeJournal);
}



static int
dissect_mms_ReportJournalStatus_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_ObjectName(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_reportJournalStatus_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ReportJournalStatus_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_reportJournalStatus);
}


static const ber_sequence_t CreateJournal_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_journalName },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_CreateJournal_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CreateJournal_Request_sequence, hf_index, ett_mms_CreateJournal_Request);

  return offset;
}
static int dissect_createJournal_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_CreateJournal_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_createJournal);
}


static const ber_sequence_t DeleteJournal_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_journalName },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_DeleteJournal_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DeleteJournal_Request_sequence, hf_index, ett_mms_DeleteJournal_Request);

  return offset;
}
static int dissect_deleteJournal_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DeleteJournal_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_deleteJournal);
}


static const ber_sequence_t GetCapabilityList_Request_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_continueAfter1 },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_GetCapabilityList_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   GetCapabilityList_Request_sequence, hf_index, ett_mms_GetCapabilityList_Request);

  return offset;
}
static int dissect_getCapabilityList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_GetCapabilityList_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_getCapabilityList);
}


static const ber_sequence_t FileOpen_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_fileName_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_initialPosition_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_FileOpen_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   FileOpen_Request_sequence, hf_index, ett_mms_FileOpen_Request);

  return offset;
}
static int dissect_fileOpen_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_FileOpen_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_fileOpen);
}



static int
dissect_mms_FileRead_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_Integer32(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_fileRead_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_FileRead_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_fileRead);
}



static int
dissect_mms_FileClose_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_Integer32(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_fileClose_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_FileClose_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_fileClose);
}


static const ber_sequence_t FileRename_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_currentFileName_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_newFileName_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_FileRename_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   FileRename_Request_sequence, hf_index, ett_mms_FileRename_Request);

  return offset;
}
static int dissect_fileRename_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_FileRename_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_fileRename);
}



static int
dissect_mms_FileDelete_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_FileName(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_fileDelete_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_FileDelete_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_fileDelete);
}


static const ber_sequence_t FileDirectory_Request_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_fileSpecification_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_continueAfter3_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_FileDirectory_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   FileDirectory_Request_sequence, hf_index, ett_mms_FileDirectory_Request);

  return offset;
}
static int dissect_fileDirectory_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_FileDirectory_Request(TRUE, tvb, offset, pinfo, tree, hf_mms_fileDirectory);
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
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_status_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_getNameList_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_identify_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_rename_impl },
  {   4, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_read_impl },
  {   5, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_write_impl },
  {   6, BER_CLASS_CON, 6, 0, dissect_getVariableAccessAttributes },
  {   7, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_defineNamedVariable_impl },
  {   8, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_defineScatteredAccess_impl },
  {   9, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_getScatteredAccessAttributes_impl },
  {  10, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_deleteVariableAccess_impl },
  {  11, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_defineNamedVariableList_impl },
  {  12, BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_getNamedVariableListAttributes_impl },
  {  13, BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_deleteNamedVariableList_impl },
  {  14, BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_defineNamedType_impl },
  {  15, BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_getNamedTypeAttributes_impl },
  {  16, BER_CLASS_CON, 16, BER_FLAGS_IMPLTAG, dissect_deleteNamedType_impl },
  {  17, BER_CLASS_CON, 17, BER_FLAGS_IMPLTAG, dissect_input_impl },
  {  18, BER_CLASS_CON, 18, BER_FLAGS_IMPLTAG, dissect_output_impl },
  {  19, BER_CLASS_CON, 19, BER_FLAGS_IMPLTAG, dissect_takeControl_impl },
  {  20, BER_CLASS_CON, 20, BER_FLAGS_IMPLTAG, dissect_relinquishControl_impl },
  {  21, BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_defineSemaphore_impl },
  {  22, BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_deleteSemaphore_impl },
  {  23, BER_CLASS_CON, 23, BER_FLAGS_IMPLTAG, dissect_reportSemaphoreStatus_impl },
  {  24, BER_CLASS_CON, 24, BER_FLAGS_IMPLTAG, dissect_reportPoolSemaphoreStatus_impl },
  {  25, BER_CLASS_CON, 25, BER_FLAGS_IMPLTAG, dissect_reportSemaphoreEntryStatus_impl },
  {  26, BER_CLASS_CON, 26, BER_FLAGS_IMPLTAG, dissect_initiateDownloadSequence_impl },
  {  27, BER_CLASS_CON, 27, BER_FLAGS_IMPLTAG, dissect_downloadSegment_impl },
  {  28, BER_CLASS_CON, 28, BER_FLAGS_IMPLTAG, dissect_terminateDownloadSequence_impl },
  {  29, BER_CLASS_CON, 29, BER_FLAGS_IMPLTAG, dissect_initiateUploadSequence_impl },
  {  30, BER_CLASS_CON, 30, BER_FLAGS_IMPLTAG, dissect_uploadSegment_impl },
  {  31, BER_CLASS_CON, 31, BER_FLAGS_IMPLTAG, dissect_terminateUploadSequence_impl },
  {  32, BER_CLASS_CON, 32, BER_FLAGS_IMPLTAG, dissect_requestDomainDownload_impl },
  {  33, BER_CLASS_CON, 33, BER_FLAGS_IMPLTAG, dissect_requestDomainUpload_impl },
  {  34, BER_CLASS_CON, 34, BER_FLAGS_IMPLTAG, dissect_loadDomainContent_impl },
  {  35, BER_CLASS_CON, 35, BER_FLAGS_IMPLTAG, dissect_storeDomainContent_impl },
  {  36, BER_CLASS_CON, 36, BER_FLAGS_IMPLTAG, dissect_deleteDomain_impl },
  {  37, BER_CLASS_CON, 37, BER_FLAGS_IMPLTAG, dissect_getDomainAttributes_impl },
  {  38, BER_CLASS_CON, 38, BER_FLAGS_IMPLTAG, dissect_createProgramInvocation_impl },
  {  39, BER_CLASS_CON, 39, BER_FLAGS_IMPLTAG, dissect_deleteProgramInvocation_impl },
  {  40, BER_CLASS_CON, 40, BER_FLAGS_IMPLTAG, dissect_start_impl },
  {  41, BER_CLASS_CON, 41, BER_FLAGS_IMPLTAG, dissect_stop_impl },
  {  42, BER_CLASS_CON, 42, BER_FLAGS_IMPLTAG, dissect_resume_impl },
  {  43, BER_CLASS_CON, 43, BER_FLAGS_IMPLTAG, dissect_reset_impl },
  {  44, BER_CLASS_CON, 44, BER_FLAGS_IMPLTAG, dissect_kill_impl },
  {  45, BER_CLASS_CON, 45, BER_FLAGS_IMPLTAG, dissect_getProgramInvocationAttributes_impl },
  {  46, BER_CLASS_CON, 46, BER_FLAGS_IMPLTAG, dissect_obtainFile_impl },
  {  47, BER_CLASS_CON, 47, BER_FLAGS_IMPLTAG, dissect_defineEventCondition_impl },
  {  48, BER_CLASS_CON, 48, 0, dissect_deleteEventCondition },
  {  49, BER_CLASS_CON, 49, 0, dissect_getEventConditionAttributes },
  {  50, BER_CLASS_CON, 50, 0, dissect_reportEventConditionStatus },
  {  51, BER_CLASS_CON, 51, BER_FLAGS_IMPLTAG, dissect_alterEventConditionMonitoring_impl },
  {  52, BER_CLASS_CON, 52, BER_FLAGS_IMPLTAG, dissect_triggerEvent_impl },
  {  53, BER_CLASS_CON, 53, BER_FLAGS_IMPLTAG, dissect_defineEventAction_impl },
  {  54, BER_CLASS_CON, 54, 0, dissect_deleteEventAction },
  {  55, BER_CLASS_CON, 55, 0, dissect_getEventActionAttributes },
  {  56, BER_CLASS_CON, 56, 0, dissect_reportEventActionStatus },
  {  57, BER_CLASS_CON, 57, BER_FLAGS_IMPLTAG, dissect_defineEventEnrollment_impl },
  {  58, BER_CLASS_CON, 58, 0, dissect_deleteEventEnrollment },
  {  59, BER_CLASS_CON, 59, BER_FLAGS_IMPLTAG, dissect_alterEventEnrollment_impl },
  {  60, BER_CLASS_CON, 60, 0, dissect_reportEventEnrollmentStatus },
  {  61, BER_CLASS_CON, 61, BER_FLAGS_IMPLTAG, dissect_getEventEnrollmentAttributes_impl },
  {  62, BER_CLASS_CON, 62, BER_FLAGS_IMPLTAG, dissect_acknowledgeEventNotification_impl },
  {  63, BER_CLASS_CON, 63, BER_FLAGS_IMPLTAG, dissect_getAlarmSummary_impl },
  {  64, BER_CLASS_CON, 64, BER_FLAGS_IMPLTAG, dissect_getAlarmEnrollmentSummary_impl },
  {  65, BER_CLASS_CON, 65, BER_FLAGS_IMPLTAG, dissect_readJournal_impl },
  {  66, BER_CLASS_CON, 66, BER_FLAGS_IMPLTAG, dissect_writeJournal_impl },
  {  67, BER_CLASS_CON, 67, BER_FLAGS_IMPLTAG, dissect_initializeJournal_impl },
  {  68, BER_CLASS_CON, 68, BER_FLAGS_IMPLTAG, dissect_reportJournalStatus_impl },
  {  69, BER_CLASS_CON, 69, BER_FLAGS_IMPLTAG, dissect_createJournal_impl },
  {  70, BER_CLASS_CON, 70, BER_FLAGS_IMPLTAG, dissect_deleteJournal_impl },
  {  71, BER_CLASS_CON, 71, BER_FLAGS_IMPLTAG, dissect_getCapabilityList_impl },
  {  72, BER_CLASS_CON, 72, BER_FLAGS_IMPLTAG, dissect_fileOpen_impl },
  {  73, BER_CLASS_CON, 73, BER_FLAGS_IMPLTAG, dissect_fileRead_impl },
  {  74, BER_CLASS_CON, 74, BER_FLAGS_IMPLTAG, dissect_fileClose_impl },
  {  75, BER_CLASS_CON, 75, BER_FLAGS_IMPLTAG, dissect_fileRename_impl },
  {  76, BER_CLASS_CON, 76, BER_FLAGS_IMPLTAG, dissect_fileDelete_impl },
  {  77, BER_CLASS_CON, 77, BER_FLAGS_IMPLTAG, dissect_fileDirectory_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_ConfirmedServiceRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ConfirmedServiceRequest_choice, hf_index, ett_mms_ConfirmedServiceRequest,
                                 NULL);

  return offset;
}
static int dissect_confirmedServiceRequest(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ConfirmedServiceRequest(FALSE, tvb, offset, pinfo, tree, hf_mms_confirmedServiceRequest);
}


static const value_string mms_CS_Request_Detail_vals[] = {
  {   0, "foo" },
  { 0, NULL }
};

static const ber_choice_t CS_Request_Detail_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_foo },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_CS_Request_Detail(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 CS_Request_Detail_choice, hf_index, ett_mms_CS_Request_Detail,
                                 NULL);

  return offset;
}
static int dissect_cs_request_detail(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_CS_Request_Detail(FALSE, tvb, offset, pinfo, tree, hf_mms_cs_request_detail);
}


static const ber_sequence_t Confirmed_RequestPDU_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_invokeID },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_listOfModifier },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_confirmedServiceRequest },
  { BER_CLASS_CON, 79, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_cs_request_detail },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_Confirmed_RequestPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Confirmed_RequestPDU_sequence, hf_index, ett_mms_Confirmed_RequestPDU);

  return offset;
}
static int dissect_confirmed_RequestPDU_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Confirmed_RequestPDU(TRUE, tvb, offset, pinfo, tree, hf_mms_confirmed_RequestPDU);
}


static const value_string mms_T_vmdLogicalStatus_vals[] = {
  {   0, "state-changes-allowed" },
  {   1, "no-state-changes-allowed" },
  {   2, "limited-services-allowed" },
  {   3, "support-services-allowed" },
  { 0, NULL }
};


static int
dissect_mms_T_vmdLogicalStatus(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_vmdLogicalStatus_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_vmdLogicalStatus(TRUE, tvb, offset, pinfo, tree, hf_mms_vmdLogicalStatus);
}


static const value_string mms_T_vmdPhysicalStatus_vals[] = {
  {   0, "operational" },
  {   1, "partially-operational" },
  {   2, "inoperable" },
  {   3, "needs-commissioning" },
  { 0, NULL }
};


static int
dissect_mms_T_vmdPhysicalStatus(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_vmdPhysicalStatus_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_vmdPhysicalStatus(TRUE, tvb, offset, pinfo, tree, hf_mms_vmdPhysicalStatus);
}



static int
dissect_mms_BIT_STRING_SIZE_0_128(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}
static int dissect_localDetail_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_BIT_STRING_SIZE_0_128(TRUE, tvb, offset, pinfo, tree, hf_mms_localDetail);
}


static const ber_sequence_t Status_Response_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_vmdLogicalStatus_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_vmdPhysicalStatus_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_localDetail_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_Status_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Status_Response_sequence, hf_index, ett_mms_Status_Response);

  return offset;
}
static int dissect_status1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Status_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_status1);
}


static const ber_sequence_t GetNameList_Response_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_listOfIdentifier_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_moreFollows_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_GetNameList_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   GetNameList_Response_sequence, hf_index, ett_mms_GetNameList_Response);

  return offset;
}
static int dissect_getNameList1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_GetNameList_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_getNameList1);
}



static int
dissect_mms_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_listOfAbstractSyntaxes_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_mms_listOfAbstractSyntaxes_item);
}


static const ber_sequence_t T_listOfAbstractSyntaxes_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_listOfAbstractSyntaxes_item },
};

static int
dissect_mms_T_listOfAbstractSyntaxes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      T_listOfAbstractSyntaxes_sequence_of, hf_index, ett_mms_T_listOfAbstractSyntaxes);

  return offset;
}
static int dissect_listOfAbstractSyntaxes_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_listOfAbstractSyntaxes(TRUE, tvb, offset, pinfo, tree, hf_mms_listOfAbstractSyntaxes);
}


static const ber_sequence_t Identify_Response_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_vendorName_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_modelName_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_revision_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_listOfAbstractSyntaxes_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_Identify_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Identify_Response_sequence, hf_index, ett_mms_Identify_Response);

  return offset;
}
static int dissect_identify1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Identify_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_identify1);
}



static int
dissect_mms_Rename_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_rename1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Rename_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_rename1);
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
dissect_mms_DataAccessError(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_failure_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DataAccessError(TRUE, tvb, offset, pinfo, tree, hf_mms_failure);
}


static const value_string mms_AccessResult_vals[] = {
  {   0, "failure" },
  {   1, "success" },
  { 0, NULL }
};

static const ber_choice_t AccessResult_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_failure_impl },
  {   1, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_success1 },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_AccessResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 AccessResult_choice, hf_index, ett_mms_AccessResult,
                                 NULL);

  return offset;
}
static int dissect_listOfAccessResult_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_AccessResult(FALSE, tvb, offset, pinfo, tree, hf_mms_listOfAccessResult_item);
}


static const ber_sequence_t SEQUENCE_OF_AccessResult_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_listOfAccessResult_item },
};

static int
dissect_mms_SEQUENCE_OF_AccessResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_AccessResult_sequence_of, hf_index, ett_mms_SEQUENCE_OF_AccessResult);

  return offset;
}
static int dissect_listOfAccessResult_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_SEQUENCE_OF_AccessResult(TRUE, tvb, offset, pinfo, tree, hf_mms_listOfAccessResult);
}


static const ber_sequence_t Read_Response_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_variableAccessSpecificatn },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_listOfAccessResult_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_Read_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Read_Response_sequence, hf_index, ett_mms_Read_Response);

  return offset;
}
static int dissect_read1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Read_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_read1);
}


static const value_string mms_Write_Response_item_vals[] = {
  {   0, "failure" },
  {   1, "success" },
  { 0, NULL }
};

static const ber_choice_t Write_Response_item_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_failure_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_success_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_Write_Response_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Write_Response_item_choice, hf_index, ett_mms_Write_Response_item,
                                 NULL);

  return offset;
}
static int dissect_Write_Response_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Write_Response_item(FALSE, tvb, offset, pinfo, tree, hf_mms_Write_Response_item);
}


static const ber_sequence_t Write_Response_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_Write_Response_item },
};

static int
dissect_mms_Write_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      Write_Response_sequence_of, hf_index, ett_mms_Write_Response);

  return offset;
}
static int dissect_write1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Write_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_write1);
}


static const ber_sequence_t GetVariableAccessAttributes_Response_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mmsDeletable_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_address },
  { BER_CLASS_CON, 2, BER_FLAGS_NOTCHKTAG, dissect_typeSpecification },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_GetVariableAccessAttributes_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   GetVariableAccessAttributes_Response_sequence, hf_index, ett_mms_GetVariableAccessAttributes_Response);

  return offset;
}
static int dissect_getVariableAccessAttributes1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_GetVariableAccessAttributes_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_getVariableAccessAttributes1);
}



static int
dissect_mms_DefineNamedVariable_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_defineNamedVariable1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DefineNamedVariable_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_defineNamedVariable1);
}



static int
dissect_mms_DefineScatteredAccess_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_defineScatteredAccess1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DefineScatteredAccess_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_defineScatteredAccess1);
}


static const ber_sequence_t GetScatteredAccessAttributes_Response_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mmsDeletable_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_scatteredAccessDescription_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_GetScatteredAccessAttributes_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   GetScatteredAccessAttributes_Response_sequence, hf_index, ett_mms_GetScatteredAccessAttributes_Response);

  return offset;
}
static int dissect_getScatteredAccessAttributes1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_GetScatteredAccessAttributes_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_getScatteredAccessAttributes1);
}


static const ber_sequence_t DeleteVariableAccess_Response_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_numberMatched_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_numberDeleted_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_DeleteVariableAccess_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DeleteVariableAccess_Response_sequence, hf_index, ett_mms_DeleteVariableAccess_Response);

  return offset;
}
static int dissect_deleteVariableAccess1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DeleteVariableAccess_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_deleteVariableAccess1);
}



static int
dissect_mms_DefineNamedVariableList_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_defineNamedVariableList1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DefineNamedVariableList_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_defineNamedVariableList1);
}


static const ber_sequence_t T_listOfVariable_item1_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_variableSpecification },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_alternateAccess_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_T_listOfVariable_item1(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_listOfVariable_item1_sequence, hf_index, ett_mms_T_listOfVariable_item1);

  return offset;
}
static int dissect_listOfVariable_item1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_listOfVariable_item1(FALSE, tvb, offset, pinfo, tree, hf_mms_listOfVariable_item1);
}


static const ber_sequence_t T_listOfVariable1_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_listOfVariable_item1 },
};

static int
dissect_mms_T_listOfVariable1(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      T_listOfVariable1_sequence_of, hf_index, ett_mms_T_listOfVariable1);

  return offset;
}
static int dissect_listOfVariable1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_listOfVariable1(TRUE, tvb, offset, pinfo, tree, hf_mms_listOfVariable1);
}


static const ber_sequence_t GetNamedVariableListAttributes_Response_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mmsDeletable_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_listOfVariable1_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_GetNamedVariableListAttributes_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   GetNamedVariableListAttributes_Response_sequence, hf_index, ett_mms_GetNamedVariableListAttributes_Response);

  return offset;
}
static int dissect_getNamedVariableListAttributes1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_GetNamedVariableListAttributes_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_getNamedVariableListAttributes1);
}


static const ber_sequence_t DeleteNamedVariableList_Response_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_numberMatched_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_numberDeleted_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_DeleteNamedVariableList_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DeleteNamedVariableList_Response_sequence, hf_index, ett_mms_DeleteNamedVariableList_Response);

  return offset;
}
static int dissect_deleteNamedVariableList1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DeleteNamedVariableList_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_deleteNamedVariableList1);
}



static int
dissect_mms_DefineNamedType_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_defineNamedType1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DefineNamedType_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_defineNamedType1);
}


static const ber_sequence_t GetNamedTypeAttributes_Response_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mmsDeletable_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_typeSpecification },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_GetNamedTypeAttributes_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   GetNamedTypeAttributes_Response_sequence, hf_index, ett_mms_GetNamedTypeAttributes_Response);

  return offset;
}
static int dissect_getNamedTypeAttributes1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_GetNamedTypeAttributes_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_getNamedTypeAttributes1);
}


static const ber_sequence_t DeleteNamedType_Response_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_numberMatched_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_numberDeleted_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_DeleteNamedType_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DeleteNamedType_Response_sequence, hf_index, ett_mms_DeleteNamedType_Response);

  return offset;
}
static int dissect_deleteNamedType1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DeleteNamedType_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_deleteNamedType1);
}



static int
dissect_mms_Input_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_VisibleString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_input1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Input_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_input1);
}



static int
dissect_mms_Output_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_output1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Output_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_output1);
}


static const value_string mms_TakeControl_Response_vals[] = {
  {   0, "noResult" },
  {   1, "namedToken" },
  { 0, NULL }
};

static const ber_choice_t TakeControl_Response_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_noResult_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_namedToken_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_TakeControl_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 TakeControl_Response_choice, hf_index, ett_mms_TakeControl_Response,
                                 NULL);

  return offset;
}
static int dissect_takeControl1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_TakeControl_Response(FALSE, tvb, offset, pinfo, tree, hf_mms_takeControl1);
}



static int
dissect_mms_RelinquishControl_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_relinquishControl1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_RelinquishControl_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_relinquishControl1);
}



static int
dissect_mms_DefineSemaphore_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_defineSemaphore1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DefineSemaphore_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_defineSemaphore1);
}



static int
dissect_mms_DeleteSemaphore_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_deleteSemaphore1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DeleteSemaphore_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_deleteSemaphore1);
}


static const value_string mms_T_class_vals[] = {
  {   0, "token" },
  {   1, "pool" },
  { 0, NULL }
};


static int
dissect_mms_T_class(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_class_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_class(TRUE, tvb, offset, pinfo, tree, hf_mms_class);
}


static const ber_sequence_t ReportSemaphoreStatus_Response_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mmsDeletable_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_class_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_numberOfTokens_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_numberOfOwnedTokens_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_numberOfHungTokens_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_ReportSemaphoreStatus_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ReportSemaphoreStatus_Response_sequence, hf_index, ett_mms_ReportSemaphoreStatus_Response);

  return offset;
}
static int dissect_reportSemaphoreStatus1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ReportSemaphoreStatus_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_reportSemaphoreStatus1);
}


static const value_string mms_T_listOfNamedTokens_item_vals[] = {
  {   0, "freeNamedToken" },
  {   1, "ownedNamedToken" },
  {   2, "hungNamedToken" },
  { 0, NULL }
};

static const ber_choice_t T_listOfNamedTokens_item_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_freeNamedToken_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ownedNamedToken_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_hungNamedToken_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_T_listOfNamedTokens_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_listOfNamedTokens_item_choice, hf_index, ett_mms_T_listOfNamedTokens_item,
                                 NULL);

  return offset;
}
static int dissect_listOfNamedTokens_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_listOfNamedTokens_item(FALSE, tvb, offset, pinfo, tree, hf_mms_listOfNamedTokens_item);
}


static const ber_sequence_t T_listOfNamedTokens_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_listOfNamedTokens_item },
};

static int
dissect_mms_T_listOfNamedTokens(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      T_listOfNamedTokens_sequence_of, hf_index, ett_mms_T_listOfNamedTokens);

  return offset;
}
static int dissect_listOfNamedTokens_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_listOfNamedTokens(TRUE, tvb, offset, pinfo, tree, hf_mms_listOfNamedTokens);
}


static const ber_sequence_t ReportPoolSemaphoreStatus_Response_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_listOfNamedTokens_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_moreFollows_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_ReportPoolSemaphoreStatus_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ReportPoolSemaphoreStatus_Response_sequence, hf_index, ett_mms_ReportPoolSemaphoreStatus_Response);

  return offset;
}
static int dissect_reportPoolSemaphoreStatus1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ReportPoolSemaphoreStatus_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_reportPoolSemaphoreStatus1);
}


static const value_string mms_T_entryClass_vals[] = {
  {   0, "simple" },
  {   1, "modifier" },
  { 0, NULL }
};


static int
dissect_mms_T_entryClass(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_entryClass_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_entryClass(TRUE, tvb, offset, pinfo, tree, hf_mms_entryClass);
}


static const ber_sequence_t SemaphoreEntry_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_entryId_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_entryClass_impl },
  { BER_CLASS_CON, 2, 0, dissect_applicationReference },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_namedToken_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_priority_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_remainingTimeOut_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_abortOnTimeOut_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_relinquishIfConnectionLost_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_SemaphoreEntry(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SemaphoreEntry_sequence, hf_index, ett_mms_SemaphoreEntry);

  return offset;
}
static int dissect_listOfSemaphoreEntry_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_SemaphoreEntry(FALSE, tvb, offset, pinfo, tree, hf_mms_listOfSemaphoreEntry_item);
}


static const ber_sequence_t SEQUENCE_OF_SemaphoreEntry_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_listOfSemaphoreEntry_item },
};

static int
dissect_mms_SEQUENCE_OF_SemaphoreEntry(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_SemaphoreEntry_sequence_of, hf_index, ett_mms_SEQUENCE_OF_SemaphoreEntry);

  return offset;
}
static int dissect_listOfSemaphoreEntry_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_SEQUENCE_OF_SemaphoreEntry(TRUE, tvb, offset, pinfo, tree, hf_mms_listOfSemaphoreEntry);
}


static const ber_sequence_t ReportSemaphoreEntryStatus_Response_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_listOfSemaphoreEntry_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_moreFollows_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_ReportSemaphoreEntryStatus_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ReportSemaphoreEntryStatus_Response_sequence, hf_index, ett_mms_ReportSemaphoreEntryStatus_Response);

  return offset;
}
static int dissect_reportSemaphoreEntryStatus1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ReportSemaphoreEntryStatus_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_reportSemaphoreEntryStatus1);
}



static int
dissect_mms_InitiateDownloadSequence_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_initiateDownloadSequence1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_InitiateDownloadSequence_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_initiateDownloadSequence1);
}


static const value_string mms_T_loadData_vals[] = {
  {   0, "non-coded" },
  {   1, "coded" },
  { 0, NULL }
};

static const ber_choice_t T_loadData_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_non_coded_impl },
  {   1, BER_CLASS_UNI, 8, BER_FLAGS_NOOWNTAG, dissect_coded },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_T_loadData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_loadData_choice, hf_index, ett_mms_T_loadData,
                                 NULL);

  return offset;
}
static int dissect_loadData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_loadData(FALSE, tvb, offset, pinfo, tree, hf_mms_loadData);
}


static const ber_sequence_t DownloadSegment_Response_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_loadData },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_moreFollows_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_DownloadSegment_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DownloadSegment_Response_sequence, hf_index, ett_mms_DownloadSegment_Response);

  return offset;
}
static int dissect_downloadSegment1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DownloadSegment_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_downloadSegment1);
}



static int
dissect_mms_TerminateDownloadSequence_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_terminateDownloadSequence1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_TerminateDownloadSequence_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_terminateDownloadSequence1);
}


static const ber_sequence_t T_listOfCapabilities2_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_listOfCapabilities_item },
};

static int
dissect_mms_T_listOfCapabilities2(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      T_listOfCapabilities2_sequence_of, hf_index, ett_mms_T_listOfCapabilities2);

  return offset;
}
static int dissect_listOfCapabilities2_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_listOfCapabilities2(TRUE, tvb, offset, pinfo, tree, hf_mms_listOfCapabilities2);
}


static const ber_sequence_t InitiateUploadSequence_Response_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ulsmID_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_listOfCapabilities2_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_InitiateUploadSequence_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   InitiateUploadSequence_Response_sequence, hf_index, ett_mms_InitiateUploadSequence_Response);

  return offset;
}
static int dissect_initiateUploadSequence1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_InitiateUploadSequence_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_initiateUploadSequence1);
}


static const value_string mms_T_loadData1_vals[] = {
  {   0, "non-coded" },
  {   1, "coded" },
  { 0, NULL }
};

static const ber_choice_t T_loadData1_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_non_coded_impl },
  {   1, BER_CLASS_UNI, 8, BER_FLAGS_NOOWNTAG, dissect_coded },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_T_loadData1(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_loadData1_choice, hf_index, ett_mms_T_loadData1,
                                 NULL);

  return offset;
}
static int dissect_loadData1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_loadData1(FALSE, tvb, offset, pinfo, tree, hf_mms_loadData1);
}


static const ber_sequence_t UploadSegment_Response_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_loadData1 },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_moreFollows_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_UploadSegment_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   UploadSegment_Response_sequence, hf_index, ett_mms_UploadSegment_Response);

  return offset;
}
static int dissect_uploadSegment1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_UploadSegment_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_uploadSegment1);
}



static int
dissect_mms_TerminateUploadSequence_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_terminateUploadSequence1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_TerminateUploadSequence_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_terminateUploadSequence1);
}



static int
dissect_mms_RequestDomainDownload_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_requestDomainDownLoad_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_RequestDomainDownload_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_requestDomainDownLoad);
}



static int
dissect_mms_RequestDomainUpload_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_requestDomainUpload1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_RequestDomainUpload_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_requestDomainUpload1);
}



static int
dissect_mms_LoadDomainContent_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_loadDomainContent1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_LoadDomainContent_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_loadDomainContent1);
}



static int
dissect_mms_StoreDomainContent_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_storeDomainContent1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_StoreDomainContent_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_storeDomainContent1);
}



static int
dissect_mms_DeleteDomain_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_deleteDomain1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DeleteDomain_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_deleteDomain1);
}


static const ber_sequence_t T_listOfCapabilities5_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_listOfCapabilities_item },
};

static int
dissect_mms_T_listOfCapabilities5(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      T_listOfCapabilities5_sequence_of, hf_index, ett_mms_T_listOfCapabilities5);

  return offset;
}
static int dissect_listOfCapabilities5_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_listOfCapabilities5(TRUE, tvb, offset, pinfo, tree, hf_mms_listOfCapabilities5);
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
dissect_mms_DomainState(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_state_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DomainState(TRUE, tvb, offset, pinfo, tree, hf_mms_state);
}



static int
dissect_mms_Integer8(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_proposedDataStructureNestingLevel_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Integer8(TRUE, tvb, offset, pinfo, tree, hf_mms_proposedDataStructureNestingLevel);
}
static int dissect_negociatedDataStructureNestingLevel_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Integer8(TRUE, tvb, offset, pinfo, tree, hf_mms_negociatedDataStructureNestingLevel);
}
static int dissect_uploadInProgress_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Integer8(TRUE, tvb, offset, pinfo, tree, hf_mms_uploadInProgress);
}


static const ber_sequence_t GetDomainAttributes_Response_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_listOfCapabilities5_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_state_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mmsDeletable_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_sharable_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_listOfProgramInvocations_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_uploadInProgress_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_GetDomainAttributes_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   GetDomainAttributes_Response_sequence, hf_index, ett_mms_GetDomainAttributes_Response);

  return offset;
}
static int dissect_getDomainAttributes1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_GetDomainAttributes_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_getDomainAttributes1);
}



static int
dissect_mms_CreateProgramInvocation_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_createProgramInvocation1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_CreateProgramInvocation_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_createProgramInvocation1);
}



static int
dissect_mms_DeleteProgramInvocation_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_deleteProgramInvocation1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DeleteProgramInvocation_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_deleteProgramInvocation1);
}



static int
dissect_mms_Start_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_start1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Start_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_start1);
}



static int
dissect_mms_Stop_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_stop1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Stop_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_stop1);
}



static int
dissect_mms_Resume_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_resume1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Resume_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_resume1);
}



static int
dissect_mms_Reset_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_reset1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Reset_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_reset1);
}



static int
dissect_mms_Kill_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_kill1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Kill_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_kill1);
}


static const value_string mms_T_executionArgument2_vals[] = {
  {   0, "simpleString" },
  {   1, "encodedString" },
  { 0, NULL }
};

static const ber_choice_t T_executionArgument2_choice[] = {
  {   0, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_simpleString_impl },
  {   1, BER_CLASS_UNI, 8, BER_FLAGS_NOOWNTAG, dissect_encodedString },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_T_executionArgument2(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_executionArgument2_choice, hf_index, ett_mms_T_executionArgument2,
                                 NULL);

  return offset;
}
static int dissect_executionArgument2(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_executionArgument2(FALSE, tvb, offset, pinfo, tree, hf_mms_executionArgument2);
}


static const ber_sequence_t GetProgramInvocationAttributes_Response_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_state1_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_listOfDomainNames_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mmsDeletable_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_reusable_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_monitor_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_startArgument_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_executionArgument2 },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_GetProgramInvocationAttributes_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   GetProgramInvocationAttributes_Response_sequence, hf_index, ett_mms_GetProgramInvocationAttributes_Response);

  return offset;
}
static int dissect_getProgramInvocationAttributes1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_GetProgramInvocationAttributes_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_getProgramInvocationAttributes1);
}



static int
dissect_mms_ObtainFile_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_obtainFile1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ObtainFile_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_obtainFile1);
}



static int
dissect_mms_GeneralizedTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_lastModified_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_GeneralizedTime(TRUE, tvb, offset, pinfo, tree, hf_mms_lastModified);
}


static const ber_sequence_t FileAttributes_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sizeOfFile_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lastModified_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_FileAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   FileAttributes_sequence, hf_index, ett_mms_FileAttributes);

  return offset;
}
static int dissect_fileAttributes_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_FileAttributes(TRUE, tvb, offset, pinfo, tree, hf_mms_fileAttributes);
}


static const ber_sequence_t FileOpen_Response_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_frsmID_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_fileAttributes_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_FileOpen_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   FileOpen_Response_sequence, hf_index, ett_mms_FileOpen_Response);

  return offset;
}
static int dissect_fileOpen1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_FileOpen_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_fileOpen1);
}



static int
dissect_mms_DefineEventCondition_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_defineEventCondition1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DefineEventCondition_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_defineEventCondition1);
}



static int
dissect_mms_DeleteEventCondition_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_Unsigned32(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_deleteEventCondition1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DeleteEventCondition_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_deleteEventCondition1);
}


static const value_string mms_T_monitoredVariable_vals[] = {
  {   0, "variableReference" },
  {   1, "undefined" },
  { 0, NULL }
};

static const ber_choice_t T_monitoredVariable_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_variableReference },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_undefined_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_T_monitoredVariable(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_monitoredVariable_choice, hf_index, ett_mms_T_monitoredVariable,
                                 NULL);

  return offset;
}
static int dissect_monitoredVariable1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_monitoredVariable(FALSE, tvb, offset, pinfo, tree, hf_mms_monitoredVariable1);
}


static const ber_sequence_t GetEventConditionAttributes_Response_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mmsDeletable_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_class1_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_prio_rity_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_severity_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_alarmSummaryReports_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_monitoredVariable1 },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_evaluationInterval_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_GetEventConditionAttributes_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   GetEventConditionAttributes_Response_sequence, hf_index, ett_mms_GetEventConditionAttributes_Response);

  return offset;
}
static int dissect_getEventConditionAttributes1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_GetEventConditionAttributes_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_getEventConditionAttributes1);
}


static const ber_sequence_t ReportEventConditionStatus_Response_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_currentState_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_numberOfEventEnrollments_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_enabled_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_timeOfLastTransitionToActive },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_timeOfLastTransitionToIdle },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_ReportEventConditionStatus_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ReportEventConditionStatus_Response_sequence, hf_index, ett_mms_ReportEventConditionStatus_Response);

  return offset;
}
static int dissect_reportEventConditionStatus1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ReportEventConditionStatus_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_reportEventConditionStatus1);
}



static int
dissect_mms_AlterEventConditionMonitoring_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_alterEventConditionMonitoring1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_AlterEventConditionMonitoring_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_alterEventConditionMonitoring1);
}



static int
dissect_mms_TriggerEvent_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_triggerEvent1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_TriggerEvent_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_triggerEvent1);
}



static int
dissect_mms_DefineEventAction_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_defineEventAction1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DefineEventAction_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_defineEventAction1);
}



static int
dissect_mms_DeleteEventAction_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_Unsigned32(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_deleteEventAction1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DeleteEventAction_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_deleteEventAction1);
}


static const ber_sequence_t GetEventActionAttributes_Response_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mmsDeletable_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_listOfModifier_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_GetEventActionAttributes_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   GetEventActionAttributes_Response_sequence, hf_index, ett_mms_GetEventActionAttributes_Response);

  return offset;
}
static int dissect_getEventActionAttributes1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_GetEventActionAttributes_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_getEventActionAttributes1);
}



static int
dissect_mms_ReportEventActionStatus_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_Unsigned32(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_reportActionStatus_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ReportEventActionStatus_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_reportActionStatus);
}



static int
dissect_mms_DefineEventEnrollment_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_defineEventEnrollment1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DefineEventEnrollment_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_defineEventEnrollment1);
}



static int
dissect_mms_DeleteEventEnrollment_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_Unsigned32(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_deleteEventEnrollment1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DeleteEventEnrollment_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_deleteEventEnrollment1);
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
dissect_mms_EE_State(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_currentState1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_EE_State(TRUE, tvb, offset, pinfo, tree, hf_mms_currentState1);
}
static int dissect_state3_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_EE_State(TRUE, tvb, offset, pinfo, tree, hf_mms_state3);
}
static int dissect_enrollementState_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_EE_State(TRUE, tvb, offset, pinfo, tree, hf_mms_enrollementState);
}


static const value_string mms_T_currentState_vals[] = {
  {   0, "state" },
  {   1, "undefined" },
  { 0, NULL }
};

static const ber_choice_t T_currentState_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_state3_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_undefined_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_T_currentState(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_currentState_choice, hf_index, ett_mms_T_currentState,
                                 NULL);

  return offset;
}
static int dissect_currentState2(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_currentState(FALSE, tvb, offset, pinfo, tree, hf_mms_currentState2);
}


static const ber_sequence_t AlterEventEnrollment_Response_sequence[] = {
  { BER_CLASS_CON, 0, 0, dissect_currentState2 },
  { BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_transitionTime },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_AlterEventEnrollment_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AlterEventEnrollment_Response_sequence, hf_index, ett_mms_AlterEventEnrollment_Response);

  return offset;
}
static int dissect_alterEventEnrollment1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_AlterEventEnrollment_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_alterEventEnrollment1);
}


static const value_string mms_EE_Duration_vals[] = {
  {   0, "current" },
  {   1, "permanent" },
  { 0, NULL }
};


static int
dissect_mms_EE_Duration(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_duration_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_EE_Duration(TRUE, tvb, offset, pinfo, tree, hf_mms_duration);
}


static const ber_sequence_t ReportEventEnrollmentStatus_Response_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_eventConditionTransitions_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_notificationLost_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_duration_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_alarmAcknowledgmentRule_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_currentState1_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_ReportEventEnrollmentStatus_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ReportEventEnrollmentStatus_Response_sequence, hf_index, ett_mms_ReportEventEnrollmentStatus_Response);

  return offset;
}
static int dissect_reportEventEnrollmentStatus1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ReportEventEnrollmentStatus_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_reportEventEnrollmentStatus1);
}


static const value_string mms_T_eventConditionName_vals[] = {
  {   0, "eventCondition" },
  {   1, "undefined" },
  { 0, NULL }
};

static const ber_choice_t T_eventConditionName_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_eventCondition },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_undefined_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_T_eventConditionName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_eventConditionName_choice, hf_index, ett_mms_T_eventConditionName,
                                 NULL);

  return offset;
}
static int dissect_eventConditionName1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_eventConditionName(FALSE, tvb, offset, pinfo, tree, hf_mms_eventConditionName1);
}


static const value_string mms_T_eventActionName_vals[] = {
  {   0, "eventAction" },
  {   1, "undefined" },
  { 0, NULL }
};

static const ber_choice_t T_eventActionName_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_eventAction },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_undefined_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_T_eventActionName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_eventActionName_choice, hf_index, ett_mms_T_eventActionName,
                                 NULL);

  return offset;
}
static int dissect_eventActionName1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_eventActionName(FALSE, tvb, offset, pinfo, tree, hf_mms_eventActionName1);
}


static const value_string mms_EE_Class_vals[] = {
  {   0, "modifier" },
  {   1, "notification" },
  { 0, NULL }
};


static int
dissect_mms_EE_Class(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_enrollmentClass_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_EE_Class(TRUE, tvb, offset, pinfo, tree, hf_mms_enrollmentClass);
}


static const ber_sequence_t EventEnrollment_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_eventEnrollmentName },
  { BER_CLASS_CON, 1, 0, dissect_eventConditionName1 },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_eventActionName1 },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_clientApplication },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mmsDeletable_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_enrollmentClass_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_duration_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_invokeID_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_remainingAcceptableDelay_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_EventEnrollment(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   EventEnrollment_sequence, hf_index, ett_mms_EventEnrollment);

  return offset;
}
static int dissect_listOfEventEnrollment_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_EventEnrollment(FALSE, tvb, offset, pinfo, tree, hf_mms_listOfEventEnrollment_item);
}


static const ber_sequence_t SEQUENCE_OF_EventEnrollment_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_listOfEventEnrollment_item },
};

static int
dissect_mms_SEQUENCE_OF_EventEnrollment(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_EventEnrollment_sequence_of, hf_index, ett_mms_SEQUENCE_OF_EventEnrollment);

  return offset;
}
static int dissect_listOfEventEnrollment_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_SEQUENCE_OF_EventEnrollment(TRUE, tvb, offset, pinfo, tree, hf_mms_listOfEventEnrollment);
}


static const ber_sequence_t GetEventEnrollmentAttributes_Response_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_listOfEventEnrollment_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_moreFollows_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_GetEventEnrollmentAttributes_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   GetEventEnrollmentAttributes_Response_sequence, hf_index, ett_mms_GetEventEnrollmentAttributes_Response);

  return offset;
}
static int dissect_getEventEnrollmentAttributes1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_GetEventEnrollmentAttributes_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_getEventEnrollmentAttributes1);
}



static int
dissect_mms_AcknowledgeEventNotification_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_acknowledgeEventNotification1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_AcknowledgeEventNotification_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_acknowledgeEventNotification1);
}


static const value_string mms_T_unacknowledgedState_vals[] = {
  {   0, "none" },
  {   1, "active" },
  {   2, "idle" },
  {   3, "both" },
  { 0, NULL }
};


static int
dissect_mms_T_unacknowledgedState(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_unacknowledgedState_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_unacknowledgedState(TRUE, tvb, offset, pinfo, tree, hf_mms_unacknowledgedState);
}


static const ber_sequence_t AlarmSummary_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_eventConditionName },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_severity_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_currentState_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_unacknowledgedState_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_timeOfLastTransitionToActive },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_timeOfLastTransitionToIdle },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_AlarmSummary(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AlarmSummary_sequence, hf_index, ett_mms_AlarmSummary);

  return offset;
}
static int dissect_listOfAlarmSummary_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_AlarmSummary(FALSE, tvb, offset, pinfo, tree, hf_mms_listOfAlarmSummary_item);
}


static const ber_sequence_t SEQUENCE_OF_AlarmSummary_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_listOfAlarmSummary_item },
};

static int
dissect_mms_SEQUENCE_OF_AlarmSummary(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_AlarmSummary_sequence_of, hf_index, ett_mms_SEQUENCE_OF_AlarmSummary);

  return offset;
}
static int dissect_listOfAlarmSummary_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_SEQUENCE_OF_AlarmSummary(TRUE, tvb, offset, pinfo, tree, hf_mms_listOfAlarmSummary);
}


static const ber_sequence_t GetAlarmSummary_Response_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_listOfAlarmSummary_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_moreFollows_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_GetAlarmSummary_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   GetAlarmSummary_Response_sequence, hf_index, ett_mms_GetAlarmSummary_Response);

  return offset;
}
static int dissect_getAlarmSummary1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_GetAlarmSummary_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_getAlarmSummary1);
}


static const ber_sequence_t AlarmEnrollmentSummary_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_eventEnrollmentName },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_clientApplication },
  { BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_severity_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_currentState_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_notificationLost_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_alarmAcknowledgmentRule_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_enrollementState_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_timeOfLastTransitionToActive },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_timeActiveAcknowledged },
  { BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_timeOfLastTransitionToIdle },
  { BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_timeIdleAcknowledged },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_AlarmEnrollmentSummary(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AlarmEnrollmentSummary_sequence, hf_index, ett_mms_AlarmEnrollmentSummary);

  return offset;
}
static int dissect_listOfAlarmEnrollmentSummary_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_AlarmEnrollmentSummary(FALSE, tvb, offset, pinfo, tree, hf_mms_listOfAlarmEnrollmentSummary_item);
}


static const ber_sequence_t SEQUENCE_OF_AlarmEnrollmentSummary_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_listOfAlarmEnrollmentSummary_item },
};

static int
dissect_mms_SEQUENCE_OF_AlarmEnrollmentSummary(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_AlarmEnrollmentSummary_sequence_of, hf_index, ett_mms_SEQUENCE_OF_AlarmEnrollmentSummary);

  return offset;
}
static int dissect_listOfAlarmEnrollmentSummary_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_SEQUENCE_OF_AlarmEnrollmentSummary(TRUE, tvb, offset, pinfo, tree, hf_mms_listOfAlarmEnrollmentSummary);
}


static const ber_sequence_t GetAlarmEnrollmentSummary_Response_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_listOfAlarmEnrollmentSummary_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_moreFollows_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_GetAlarmEnrollmentSummary_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   GetAlarmEnrollmentSummary_Response_sequence, hf_index, ett_mms_GetAlarmEnrollmentSummary_Response);

  return offset;
}
static int dissect_getAlarmEnrollmentSummary1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_GetAlarmEnrollmentSummary_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_getAlarmEnrollmentSummary1);
}


static const ber_sequence_t JournalEntry_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_entryIdentifier_impl },
  { BER_CLASS_CON, 1, 0, dissect_originatingApplication },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_entryContent_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_JournalEntry(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   JournalEntry_sequence, hf_index, ett_mms_JournalEntry);

  return offset;
}
static int dissect_listOfJournalEntry_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_JournalEntry(FALSE, tvb, offset, pinfo, tree, hf_mms_listOfJournalEntry_item);
}


static const ber_sequence_t SEQUENCE_OF_JournalEntry_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_listOfJournalEntry_item },
};

static int
dissect_mms_SEQUENCE_OF_JournalEntry(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_JournalEntry_sequence_of, hf_index, ett_mms_SEQUENCE_OF_JournalEntry);

  return offset;
}
static int dissect_listOfJournalEntry_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_SEQUENCE_OF_JournalEntry(TRUE, tvb, offset, pinfo, tree, hf_mms_listOfJournalEntry);
}


static const ber_sequence_t ReadJournal_Response_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_listOfJournalEntry_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_moreFollows_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_ReadJournal_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ReadJournal_Response_sequence, hf_index, ett_mms_ReadJournal_Response);

  return offset;
}
static int dissect_readJournal1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ReadJournal_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_readJournal1);
}



static int
dissect_mms_WriteJournal_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_writeJournal1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_WriteJournal_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_writeJournal1);
}



static int
dissect_mms_InitializeJournal_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_Unsigned32(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_initializeJournal1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_InitializeJournal_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_initializeJournal1);
}


static const ber_sequence_t ReportJournalStatus_Response_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_currentEntries_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mmsDeletable_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_ReportJournalStatus_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ReportJournalStatus_Response_sequence, hf_index, ett_mms_ReportJournalStatus_Response);

  return offset;
}
static int dissect_reportJournalStatus1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ReportJournalStatus_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_reportJournalStatus1);
}



static int
dissect_mms_CreateJournal_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_createJournal1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_CreateJournal_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_createJournal1);
}



static int
dissect_mms_DeleteJournal_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_deleteJournal1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DeleteJournal_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_deleteJournal1);
}


static const ber_sequence_t T_listOfCapabilities_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_listOfCapabilities_item },
};

static int
dissect_mms_T_listOfCapabilities(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      T_listOfCapabilities_sequence_of, hf_index, ett_mms_T_listOfCapabilities);

  return offset;
}
static int dissect_listOfCapabilities_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_listOfCapabilities(TRUE, tvb, offset, pinfo, tree, hf_mms_listOfCapabilities);
}


static const ber_sequence_t GetCapabilityList_Response_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_listOfCapabilities_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_moreFollows_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_GetCapabilityList_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   GetCapabilityList_Response_sequence, hf_index, ett_mms_GetCapabilityList_Response);

  return offset;
}
static int dissect_getCapabilityList1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_GetCapabilityList_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_getCapabilityList1);
}


static const ber_sequence_t FileRead_Response_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_fileData_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_moreFollows_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_FileRead_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   FileRead_Response_sequence, hf_index, ett_mms_FileRead_Response);

  return offset;
}
static int dissect_fileRead1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_FileRead_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_fileRead1);
}



static int
dissect_mms_FileClose_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_fileClose1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_FileClose_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_fileClose1);
}



static int
dissect_mms_FileRename_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_fileRename1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_FileRename_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_fileRename1);
}



static int
dissect_mms_FileDelete_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_fileDelete1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_FileDelete_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_fileDelete1);
}


static const ber_sequence_t DirectoryEntry_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_filename_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_fileAttributes_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_DirectoryEntry(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DirectoryEntry_sequence, hf_index, ett_mms_DirectoryEntry);

  return offset;
}
static int dissect_listOfDirectoryEntry_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_DirectoryEntry(FALSE, tvb, offset, pinfo, tree, hf_mms_listOfDirectoryEntry_item);
}


static const ber_sequence_t SEQUENCE_OF_DirectoryEntry_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_listOfDirectoryEntry_item },
};

static int
dissect_mms_SEQUENCE_OF_DirectoryEntry(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_DirectoryEntry_sequence_of, hf_index, ett_mms_SEQUENCE_OF_DirectoryEntry);

  return offset;
}
static int dissect_listOfDirectoryEntry(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_SEQUENCE_OF_DirectoryEntry(FALSE, tvb, offset, pinfo, tree, hf_mms_listOfDirectoryEntry);
}


static const ber_sequence_t FileDirectory_Response_sequence[] = {
  { BER_CLASS_CON, 0, 0, dissect_listOfDirectoryEntry },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_moreFollows_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_FileDirectory_Response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   FileDirectory_Response_sequence, hf_index, ett_mms_FileDirectory_Response);

  return offset;
}
static int dissect_fileDirectory1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_FileDirectory_Response(TRUE, tvb, offset, pinfo, tree, hf_mms_fileDirectory1);
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
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_status1_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_getNameList1_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_identify1_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_rename1_impl },
  {   4, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_read1_impl },
  {   5, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_write1_impl },
  {   6, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_getVariableAccessAttributes1_impl },
  {   7, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_defineNamedVariable1_impl },
  {   8, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_defineScatteredAccess1_impl },
  {   9, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_getScatteredAccessAttributes1_impl },
  {  10, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_deleteVariableAccess1_impl },
  {  11, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_defineNamedVariableList1_impl },
  {  12, BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_getNamedVariableListAttributes1_impl },
  {  13, BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_deleteNamedVariableList1_impl },
  {  14, BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_defineNamedType1_impl },
  {  15, BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_getNamedTypeAttributes1_impl },
  {  16, BER_CLASS_CON, 16, BER_FLAGS_IMPLTAG, dissect_deleteNamedType1_impl },
  {  17, BER_CLASS_CON, 17, BER_FLAGS_IMPLTAG, dissect_input1_impl },
  {  18, BER_CLASS_CON, 18, BER_FLAGS_IMPLTAG, dissect_output1_impl },
  {  19, BER_CLASS_CON, 19, 0, dissect_takeControl1 },
  {  20, BER_CLASS_CON, 20, BER_FLAGS_IMPLTAG, dissect_relinquishControl1_impl },
  {  21, BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_defineSemaphore1_impl },
  {  22, BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_deleteSemaphore1_impl },
  {  23, BER_CLASS_CON, 23, BER_FLAGS_IMPLTAG, dissect_reportSemaphoreStatus1_impl },
  {  24, BER_CLASS_CON, 24, BER_FLAGS_IMPLTAG, dissect_reportPoolSemaphoreStatus1_impl },
  {  25, BER_CLASS_CON, 25, BER_FLAGS_IMPLTAG, dissect_reportSemaphoreEntryStatus1_impl },
  {  26, BER_CLASS_CON, 26, BER_FLAGS_IMPLTAG, dissect_initiateDownloadSequence1_impl },
  {  27, BER_CLASS_CON, 27, BER_FLAGS_IMPLTAG, dissect_downloadSegment1_impl },
  {  28, BER_CLASS_CON, 28, BER_FLAGS_IMPLTAG, dissect_terminateDownloadSequence1_impl },
  {  29, BER_CLASS_CON, 29, BER_FLAGS_IMPLTAG, dissect_initiateUploadSequence1_impl },
  {  30, BER_CLASS_CON, 30, BER_FLAGS_IMPLTAG, dissect_uploadSegment1_impl },
  {  31, BER_CLASS_CON, 31, BER_FLAGS_IMPLTAG, dissect_terminateUploadSequence1_impl },
  {  32, BER_CLASS_CON, 32, BER_FLAGS_IMPLTAG, dissect_requestDomainDownLoad_impl },
  {  33, BER_CLASS_CON, 33, BER_FLAGS_IMPLTAG, dissect_requestDomainUpload1_impl },
  {  34, BER_CLASS_CON, 34, BER_FLAGS_IMPLTAG, dissect_loadDomainContent1_impl },
  {  35, BER_CLASS_CON, 35, BER_FLAGS_IMPLTAG, dissect_storeDomainContent1_impl },
  {  36, BER_CLASS_CON, 36, BER_FLAGS_IMPLTAG, dissect_deleteDomain1_impl },
  {  37, BER_CLASS_CON, 37, BER_FLAGS_IMPLTAG, dissect_getDomainAttributes1_impl },
  {  38, BER_CLASS_CON, 38, BER_FLAGS_IMPLTAG, dissect_createProgramInvocation1_impl },
  {  39, BER_CLASS_CON, 39, BER_FLAGS_IMPLTAG, dissect_deleteProgramInvocation1_impl },
  {  40, BER_CLASS_CON, 40, BER_FLAGS_IMPLTAG, dissect_start1_impl },
  {  41, BER_CLASS_CON, 41, BER_FLAGS_IMPLTAG, dissect_stop1_impl },
  {  42, BER_CLASS_CON, 42, BER_FLAGS_IMPLTAG, dissect_resume1_impl },
  {  43, BER_CLASS_CON, 43, BER_FLAGS_IMPLTAG, dissect_reset1_impl },
  {  44, BER_CLASS_CON, 44, BER_FLAGS_IMPLTAG, dissect_kill1_impl },
  {  45, BER_CLASS_CON, 45, BER_FLAGS_IMPLTAG, dissect_getProgramInvocationAttributes1_impl },
  {  46, BER_CLASS_CON, 46, BER_FLAGS_IMPLTAG, dissect_obtainFile1_impl },
  {  72, BER_CLASS_CON, 72, BER_FLAGS_IMPLTAG, dissect_fileOpen1_impl },
  {  47, BER_CLASS_CON, 47, BER_FLAGS_IMPLTAG, dissect_defineEventCondition1_impl },
  {  48, BER_CLASS_CON, 48, BER_FLAGS_IMPLTAG, dissect_deleteEventCondition1_impl },
  {  49, BER_CLASS_CON, 49, BER_FLAGS_IMPLTAG, dissect_getEventConditionAttributes1_impl },
  {  50, BER_CLASS_CON, 50, BER_FLAGS_IMPLTAG, dissect_reportEventConditionStatus1_impl },
  {  51, BER_CLASS_CON, 51, BER_FLAGS_IMPLTAG, dissect_alterEventConditionMonitoring1_impl },
  {  52, BER_CLASS_CON, 52, BER_FLAGS_IMPLTAG, dissect_triggerEvent1_impl },
  {  53, BER_CLASS_CON, 53, BER_FLAGS_IMPLTAG, dissect_defineEventAction1_impl },
  {  54, BER_CLASS_CON, 54, BER_FLAGS_IMPLTAG, dissect_deleteEventAction1_impl },
  {  55, BER_CLASS_CON, 55, BER_FLAGS_IMPLTAG, dissect_getEventActionAttributes1_impl },
  {  56, BER_CLASS_CON, 56, BER_FLAGS_IMPLTAG, dissect_reportActionStatus_impl },
  {  57, BER_CLASS_CON, 57, BER_FLAGS_IMPLTAG, dissect_defineEventEnrollment1_impl },
  {  58, BER_CLASS_CON, 58, BER_FLAGS_IMPLTAG, dissect_deleteEventEnrollment1_impl },
  {  59, BER_CLASS_CON, 59, BER_FLAGS_IMPLTAG, dissect_alterEventEnrollment1_impl },
  {  60, BER_CLASS_CON, 60, BER_FLAGS_IMPLTAG, dissect_reportEventEnrollmentStatus1_impl },
  {  61, BER_CLASS_CON, 61, BER_FLAGS_IMPLTAG, dissect_getEventEnrollmentAttributes1_impl },
  {  62, BER_CLASS_CON, 62, BER_FLAGS_IMPLTAG, dissect_acknowledgeEventNotification1_impl },
  {  63, BER_CLASS_CON, 63, BER_FLAGS_IMPLTAG, dissect_getAlarmSummary1_impl },
  {  64, BER_CLASS_CON, 64, BER_FLAGS_IMPLTAG, dissect_getAlarmEnrollmentSummary1_impl },
  {  65, BER_CLASS_CON, 65, BER_FLAGS_IMPLTAG, dissect_readJournal1_impl },
  {  66, BER_CLASS_CON, 66, BER_FLAGS_IMPLTAG, dissect_writeJournal1_impl },
  {  67, BER_CLASS_CON, 67, BER_FLAGS_IMPLTAG, dissect_initializeJournal1_impl },
  {  68, BER_CLASS_CON, 68, BER_FLAGS_IMPLTAG, dissect_reportJournalStatus1_impl },
  {  69, BER_CLASS_CON, 69, BER_FLAGS_IMPLTAG, dissect_createJournal1_impl },
  {  70, BER_CLASS_CON, 70, BER_FLAGS_IMPLTAG, dissect_deleteJournal1_impl },
  {  71, BER_CLASS_CON, 71, BER_FLAGS_IMPLTAG, dissect_getCapabilityList1_impl },
  {  73, BER_CLASS_CON, 73, BER_FLAGS_IMPLTAG, dissect_fileRead1_impl },
  {  74, BER_CLASS_CON, 74, BER_FLAGS_IMPLTAG, dissect_fileClose1_impl },
  {  75, BER_CLASS_CON, 75, BER_FLAGS_IMPLTAG, dissect_fileRename1_impl },
  {  76, BER_CLASS_CON, 76, BER_FLAGS_IMPLTAG, dissect_fileDelete1_impl },
  {  77, BER_CLASS_CON, 77, BER_FLAGS_IMPLTAG, dissect_fileDirectory1_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_ConfirmedServiceResponse(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ConfirmedServiceResponse_choice, hf_index, ett_mms_ConfirmedServiceResponse,
                                 NULL);

  return offset;
}
static int dissect_confirmedServiceResponse(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ConfirmedServiceResponse(FALSE, tvb, offset, pinfo, tree, hf_mms_confirmedServiceResponse);
}
static int dissect_success2(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ConfirmedServiceResponse(FALSE, tvb, offset, pinfo, tree, hf_mms_success2);
}


static const ber_sequence_t Confirmed_ResponsePDU_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_invokeID },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_confirmedServiceResponse },
  { BER_CLASS_CON, 79, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_cs_request_detail },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_Confirmed_ResponsePDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Confirmed_ResponsePDU_sequence, hf_index, ett_mms_Confirmed_ResponsePDU);

  return offset;
}
static int dissect_confirmed_ResponsePDU_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Confirmed_ResponsePDU(TRUE, tvb, offset, pinfo, tree, hf_mms_confirmed_ResponsePDU);
}


static const ber_sequence_t Confirmed_ErrorPDU_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_invokeID_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_modifierPosition_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_serviceError_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_Confirmed_ErrorPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Confirmed_ErrorPDU_sequence, hf_index, ett_mms_Confirmed_ErrorPDU);

  return offset;
}
static int dissect_confirmed_ErrorPDU_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Confirmed_ErrorPDU(TRUE, tvb, offset, pinfo, tree, hf_mms_confirmed_ErrorPDU);
}


static const ber_sequence_t InformationReport_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_variableAccessSpecification },
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_listOfAccessResult_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_InformationReport(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   InformationReport_sequence, hf_index, ett_mms_InformationReport);

  return offset;
}
static int dissect_informationReport_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_InformationReport(TRUE, tvb, offset, pinfo, tree, hf_mms_informationReport);
}



static int
dissect_mms_UnsolicitedStatus(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_Status_Response(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_unsolicitedStatus_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_UnsolicitedStatus(TRUE, tvb, offset, pinfo, tree, hf_mms_unsolicitedStatus);
}


static const value_string mms_T_eventConditionName1_vals[] = {
  {   0, "eventCondition" },
  {   1, "undefined" },
  { 0, NULL }
};

static const ber_choice_t T_eventConditionName1_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_eventCondition },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_undefined_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_T_eventConditionName1(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_eventConditionName1_choice, hf_index, ett_mms_T_eventConditionName1,
                                 NULL);

  return offset;
}
static int dissect_eventConditionName2(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_eventConditionName1(FALSE, tvb, offset, pinfo, tree, hf_mms_eventConditionName2);
}


static const value_string mms_T_eventActionResult_vals[] = {
  {   0, "success" },
  {   1, "failure" },
  { 0, NULL }
};

static const ber_choice_t T_eventActionResult_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_success2 },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_failure1_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_T_eventActionResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_eventActionResult_choice, hf_index, ett_mms_T_eventActionResult,
                                 NULL);

  return offset;
}
static int dissect_eventActionResult(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_eventActionResult(FALSE, tvb, offset, pinfo, tree, hf_mms_eventActionResult);
}


static const ber_sequence_t T_actionResult_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_eventActioName },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_eventActionResult },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_T_actionResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_actionResult_sequence, hf_index, ett_mms_T_actionResult);

  return offset;
}
static int dissect_actionResult_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_actionResult(TRUE, tvb, offset, pinfo, tree, hf_mms_actionResult);
}


static const ber_sequence_t EventNotification_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_eventEnrollmentName },
  { BER_CLASS_CON, 1, 0, dissect_eventConditionName2 },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_severity_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_currentState_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_NOTCHKTAG, dissect_transitionTime },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_notificationLost_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_alarmAcknowledgmentRule_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_actionResult_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_EventNotification(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   EventNotification_sequence, hf_index, ett_mms_EventNotification);

  return offset;
}
static int dissect_eventNotification_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_EventNotification(TRUE, tvb, offset, pinfo, tree, hf_mms_eventNotification);
}


static const value_string mms_UnconfirmedService_vals[] = {
  {   0, "informationReport" },
  {   1, "unsolicitedStatus" },
  {   2, "eventNotification" },
  { 0, NULL }
};

static const ber_choice_t UnconfirmedService_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_informationReport_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_unsolicitedStatus_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_eventNotification_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_UnconfirmedService(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 UnconfirmedService_choice, hf_index, ett_mms_UnconfirmedService,
                                 NULL);

  return offset;
}
static int dissect_unconfirmedService(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_UnconfirmedService(FALSE, tvb, offset, pinfo, tree, hf_mms_unconfirmedService);
}


static const ber_sequence_t Unconfirmed_PDU_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_unconfirmedService },
  { BER_CLASS_CON, 79, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_cs_request_detail },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_Unconfirmed_PDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Unconfirmed_PDU_sequence, hf_index, ett_mms_Unconfirmed_PDU);

  return offset;
}
static int dissect_unconfirmed_PDU_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Unconfirmed_PDU(TRUE, tvb, offset, pinfo, tree, hf_mms_unconfirmed_PDU);
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
dissect_mms_T_confirmed_requestPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_confirmed_requestPDU_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_confirmed_requestPDU(TRUE, tvb, offset, pinfo, tree, hf_mms_confirmed_requestPDU);
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
dissect_mms_T_confirmed_responsePDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_confirmed_responsePDU_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_confirmed_responsePDU(TRUE, tvb, offset, pinfo, tree, hf_mms_confirmed_responsePDU);
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
dissect_mms_T_confirmed_errorPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_confirmed_errorPDU_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_confirmed_errorPDU(TRUE, tvb, offset, pinfo, tree, hf_mms_confirmed_errorPDU);
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
dissect_mms_T_unconfirmedPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_unconfirmedPDU_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_unconfirmedPDU(TRUE, tvb, offset, pinfo, tree, hf_mms_unconfirmedPDU);
}


static const value_string mms_T_pdu_error_vals[] = {
  {   0, "unknown-pdu-type" },
  {   1, "invalid-pdu" },
  {   2, "illegal-acse-mapping" },
  { 0, NULL }
};


static int
dissect_mms_T_pdu_error(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_pdu_error_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_pdu_error(TRUE, tvb, offset, pinfo, tree, hf_mms_pdu_error);
}


static const value_string mms_T_cancel_requestPDU_vals[] = {
  {   0, "other" },
  {   1, "invalid-invokeID" },
  { 0, NULL }
};


static int
dissect_mms_T_cancel_requestPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_cancel_requestPDU_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_cancel_requestPDU(TRUE, tvb, offset, pinfo, tree, hf_mms_cancel_requestPDU);
}


static const value_string mms_T_cancel_responsePDU_vals[] = {
  {   0, "other" },
  {   1, "invalid-invokeID" },
  { 0, NULL }
};


static int
dissect_mms_T_cancel_responsePDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_cancel_responsePDU_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_cancel_responsePDU(TRUE, tvb, offset, pinfo, tree, hf_mms_cancel_responsePDU);
}


static const value_string mms_T_cancel_errorPDU_vals[] = {
  {   0, "other" },
  {   1, "invalid-invokeID" },
  {   2, "invalid-serviceError" },
  {   3, "value-out-of-range" },
  { 0, NULL }
};


static int
dissect_mms_T_cancel_errorPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_cancel_errorPDU_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_cancel_errorPDU(TRUE, tvb, offset, pinfo, tree, hf_mms_cancel_errorPDU);
}


static const value_string mms_T_conclude_requestPDU_vals[] = {
  {   0, "other" },
  {   1, "invalid-argument" },
  { 0, NULL }
};


static int
dissect_mms_T_conclude_requestPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_conclude_requestPDU_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_conclude_requestPDU(TRUE, tvb, offset, pinfo, tree, hf_mms_conclude_requestPDU);
}


static const value_string mms_T_conclude_responsePDU_vals[] = {
  {   0, "other" },
  {   1, "invalid-result" },
  { 0, NULL }
};


static int
dissect_mms_T_conclude_responsePDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_conclude_responsePDU_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_conclude_responsePDU(TRUE, tvb, offset, pinfo, tree, hf_mms_conclude_responsePDU);
}


static const value_string mms_T_conclude_errorPDU_vals[] = {
  {   0, "other" },
  {   1, "invalid-serviceError" },
  {   2, "value-out-of-range" },
  { 0, NULL }
};


static int
dissect_mms_T_conclude_errorPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_conclude_errorPDU_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_conclude_errorPDU(TRUE, tvb, offset, pinfo, tree, hf_mms_conclude_errorPDU);
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
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_confirmed_requestPDU_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_confirmed_responsePDU_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_confirmed_errorPDU_impl },
  {   4, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_unconfirmedPDU_impl },
  {   5, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_pdu_error_impl },
  {   6, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_cancel_requestPDU_impl },
  {   7, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_cancel_responsePDU_impl },
  {   8, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_cancel_errorPDU_impl },
  {   9, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_conclude_requestPDU_impl },
  {  10, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_conclude_responsePDU_impl },
  {  11, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_conclude_errorPDU_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_mms_T_rejectReason(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_rejectReason_choice, hf_index, ett_mms_T_rejectReason,
                                 NULL);

  return offset;
}
static int dissect_rejectReason(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_T_rejectReason(FALSE, tvb, offset, pinfo, tree, hf_mms_rejectReason);
}


static const ber_sequence_t RejectPDU_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_originalInvokeID_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_rejectReason },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_RejectPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   RejectPDU_sequence, hf_index, ett_mms_RejectPDU);

  return offset;
}
static int dissect_rejectPDU_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_RejectPDU(TRUE, tvb, offset, pinfo, tree, hf_mms_rejectPDU);
}



static int
dissect_mms_Cancel_RequestPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_Unsigned32(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_cancel_RequestPDU_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Cancel_RequestPDU(TRUE, tvb, offset, pinfo, tree, hf_mms_cancel_RequestPDU);
}



static int
dissect_mms_Cancel_ResponsePDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_Unsigned32(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_cancel_ResponsePDU_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Cancel_ResponsePDU(TRUE, tvb, offset, pinfo, tree, hf_mms_cancel_ResponsePDU);
}


static const ber_sequence_t Cancel_ErrorPDU_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_originalInvokeID_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_serviceError_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_Cancel_ErrorPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Cancel_ErrorPDU_sequence, hf_index, ett_mms_Cancel_ErrorPDU);

  return offset;
}
static int dissect_cancel_ErrorPDU_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Cancel_ErrorPDU(TRUE, tvb, offset, pinfo, tree, hf_mms_cancel_ErrorPDU);
}



static int
dissect_mms_Integer16(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_proposedMaxServOutstandingCalling_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Integer16(TRUE, tvb, offset, pinfo, tree, hf_mms_proposedMaxServOutstandingCalling);
}
static int dissect_proposedMaxServOutstandingCalled_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Integer16(TRUE, tvb, offset, pinfo, tree, hf_mms_proposedMaxServOutstandingCalled);
}
static int dissect_proposedVersionNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Integer16(TRUE, tvb, offset, pinfo, tree, hf_mms_proposedVersionNumber);
}
static int dissect_negociatedMaxServOutstandingCalling_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Integer16(TRUE, tvb, offset, pinfo, tree, hf_mms_negociatedMaxServOutstandingCalling);
}
static int dissect_negociatedMaxServOutstandingCalled_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Integer16(TRUE, tvb, offset, pinfo, tree, hf_mms_negociatedMaxServOutstandingCalled);
}
static int dissect_negociatedVersionNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Integer16(TRUE, tvb, offset, pinfo, tree, hf_mms_negociatedVersionNumber);
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
dissect_mms_ParameterSupportOptions(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    ParameterSupportOptions_bits, hf_index, ett_mms_ParameterSupportOptions,
                                    NULL);

  return offset;
}
static int dissect_proposedParameterCBB_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ParameterSupportOptions(TRUE, tvb, offset, pinfo, tree, hf_mms_proposedParameterCBB);
}
static int dissect_negociatedParameterCBB_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ParameterSupportOptions(TRUE, tvb, offset, pinfo, tree, hf_mms_negociatedParameterCBB);
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
dissect_mms_ServiceSupportOptions(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    ServiceSupportOptions_bits, hf_index, ett_mms_ServiceSupportOptions,
                                    NULL);

  return offset;
}
static int dissect_servicesSupportedCalling_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ServiceSupportOptions(TRUE, tvb, offset, pinfo, tree, hf_mms_servicesSupportedCalling);
}
static int dissect_servicesSupportedCalled_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_ServiceSupportOptions(TRUE, tvb, offset, pinfo, tree, hf_mms_servicesSupportedCalled);
}


static const ber_sequence_t InitRequestDetail_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_proposedVersionNumber_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_proposedParameterCBB_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_servicesSupportedCalling_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_InitRequestDetail(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   InitRequestDetail_sequence, hf_index, ett_mms_InitRequestDetail);

  return offset;
}
static int dissect_mmsInitRequestDetail_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_InitRequestDetail(TRUE, tvb, offset, pinfo, tree, hf_mms_mmsInitRequestDetail);
}


static const ber_sequence_t Initiate_RequestPDU_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_localDetailCalling_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_proposedMaxServOutstandingCalling_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_proposedMaxServOutstandingCalled_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_proposedDataStructureNestingLevel_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_mmsInitRequestDetail_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_Initiate_RequestPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Initiate_RequestPDU_sequence, hf_index, ett_mms_Initiate_RequestPDU);

  return offset;
}
static int dissect_initiate_RequestPDU_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Initiate_RequestPDU(TRUE, tvb, offset, pinfo, tree, hf_mms_initiate_RequestPDU);
}


static const ber_sequence_t InitResponseDetail_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_negociatedVersionNumber_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_negociatedParameterCBB_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_servicesSupportedCalled_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_InitResponseDetail(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   InitResponseDetail_sequence, hf_index, ett_mms_InitResponseDetail);

  return offset;
}
static int dissect_mmsInitResponseDetail_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_InitResponseDetail(TRUE, tvb, offset, pinfo, tree, hf_mms_mmsInitResponseDetail);
}


static const ber_sequence_t Initiate_ResponsePDU_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_localDetailCalled_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_negociatedMaxServOutstandingCalling_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_negociatedMaxServOutstandingCalled_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_negociatedDataStructureNestingLevel_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_mmsInitResponseDetail_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_mms_Initiate_ResponsePDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Initiate_ResponsePDU_sequence, hf_index, ett_mms_Initiate_ResponsePDU);

  return offset;
}
static int dissect_initiate_ResponsePDU_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Initiate_ResponsePDU(TRUE, tvb, offset, pinfo, tree, hf_mms_initiate_ResponsePDU);
}



static int
dissect_mms_Initiate_ErrorPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_ServiceError(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_initiate_ErrorPDU_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Initiate_ErrorPDU(TRUE, tvb, offset, pinfo, tree, hf_mms_initiate_ErrorPDU);
}



static int
dissect_mms_Conclude_RequestPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_conclude_RequestPDU_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Conclude_RequestPDU(TRUE, tvb, offset, pinfo, tree, hf_mms_conclude_RequestPDU);
}



static int
dissect_mms_Conclude_ResponsePDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_conclude_ResponsePDU_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Conclude_ResponsePDU(TRUE, tvb, offset, pinfo, tree, hf_mms_conclude_ResponsePDU);
}



static int
dissect_mms_Conclude_ErrorPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_mms_ServiceError(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_conclude_ErrorPDU_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_mms_Conclude_ErrorPDU(TRUE, tvb, offset, pinfo, tree, hf_mms_conclude_ErrorPDU);
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
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_confirmed_RequestPDU_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_confirmed_ResponsePDU_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_confirmed_ErrorPDU_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_unconfirmed_PDU_impl },
  {   4, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_rejectPDU_impl },
  {   5, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_cancel_RequestPDU_impl },
  {   6, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_cancel_ResponsePDU_impl },
  {   7, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_cancel_ErrorPDU_impl },
  {   8, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_initiate_RequestPDU_impl },
  {   9, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_initiate_ResponsePDU_impl },
  {  10, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_initiate_ErrorPDU_impl },
  {  11, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_conclude_RequestPDU_impl },
  {  12, BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_conclude_ResponsePDU_impl },
  {  13, BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_conclude_ErrorPDU_impl },
  { 0, 0, 0, 0, NULL }
};

int
dissect_mms_MMSpdu(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 35 "mms.cnf"
  gint branch_taken;

  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 MMSpdu_choice, hf_index, ett_mms_MMSpdu,
                                 &branch_taken);

  if(check_col(pinfo->cinfo, COL_INFO))
    col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(branch_taken, mms_MMSpdu_vals, "Unknown"));




  return offset;
}


/*--- End of included file: packet-mms-fn.c ---*/
#line 55 "packet-mms-template.c"

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

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_mms, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_mms);
	}
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "MMS");
  	if (check_col(pinfo->cinfo, COL_INFO))
  		col_clear(pinfo->cinfo, COL_INFO);

	while (tvb_reported_length_remaining(tvb, offset) > 0){
		old_offset=offset;
		offset=dissect_mms_MMSpdu(FALSE, tvb, offset, pinfo , tree, -1);
		if(offset == old_offset){
			proto_tree_add_text(tree, tvb, offset, -1,"Internal error, zero-byte MMS PDU");
			offset = tvb_length(tvb);
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
#line 1 "packet-mms-hfarr.c"
    { &hf_mms_confirmed_RequestPDU,
      { "confirmed-RequestPDU", "mms.confirmed_RequestPDU",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.Confirmed_RequestPDU", HFILL }},
    { &hf_mms_confirmed_ResponsePDU,
      { "confirmed-ResponsePDU", "mms.confirmed_ResponsePDU",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.Confirmed_ResponsePDU", HFILL }},
    { &hf_mms_confirmed_ErrorPDU,
      { "confirmed-ErrorPDU", "mms.confirmed_ErrorPDU",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.Confirmed_ErrorPDU", HFILL }},
    { &hf_mms_unconfirmed_PDU,
      { "unconfirmed-PDU", "mms.unconfirmed_PDU",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.Unconfirmed_PDU", HFILL }},
    { &hf_mms_rejectPDU,
      { "rejectPDU", "mms.rejectPDU",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.RejectPDU", HFILL }},
    { &hf_mms_cancel_RequestPDU,
      { "cancel-RequestPDU", "mms.cancel_RequestPDU",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Cancel_RequestPDU", HFILL }},
    { &hf_mms_cancel_ResponsePDU,
      { "cancel-ResponsePDU", "mms.cancel_ResponsePDU",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Cancel_ResponsePDU", HFILL }},
    { &hf_mms_cancel_ErrorPDU,
      { "cancel-ErrorPDU", "mms.cancel_ErrorPDU",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.Cancel_ErrorPDU", HFILL }},
    { &hf_mms_initiate_RequestPDU,
      { "initiate-RequestPDU", "mms.initiate_RequestPDU",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.Initiate_RequestPDU", HFILL }},
    { &hf_mms_initiate_ResponsePDU,
      { "initiate-ResponsePDU", "mms.initiate_ResponsePDU",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.Initiate_ResponsePDU", HFILL }},
    { &hf_mms_initiate_ErrorPDU,
      { "initiate-ErrorPDU", "mms.initiate_ErrorPDU",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.Initiate_ErrorPDU", HFILL }},
    { &hf_mms_conclude_RequestPDU,
      { "conclude-RequestPDU", "mms.conclude_RequestPDU",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.Conclude_RequestPDU", HFILL }},
    { &hf_mms_conclude_ResponsePDU,
      { "conclude-ResponsePDU", "mms.conclude_ResponsePDU",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.Conclude_ResponsePDU", HFILL }},
    { &hf_mms_conclude_ErrorPDU,
      { "conclude-ErrorPDU", "mms.conclude_ErrorPDU",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.Conclude_ErrorPDU", HFILL }},
    { &hf_mms_invokeID,
      { "invokeID", "mms.invokeID",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Unsigned32", HFILL }},
    { &hf_mms_listOfModifier,
      { "listOfModifier", "mms.listOfModifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.SEQUENCE_OF_Modifier", HFILL }},
    { &hf_mms_listOfModifier_item,
      { "Item", "mms.listOfModifier_item",
        FT_UINT32, BASE_DEC, VALS(mms_Modifier_vals), 0,
        "mms.Modifier", HFILL }},
    { &hf_mms_confirmedServiceRequest,
      { "confirmedServiceRequest", "mms.confirmedServiceRequest",
        FT_UINT32, BASE_DEC, VALS(mms_ConfirmedServiceRequest_vals), 0,
        "mms.ConfirmedServiceRequest", HFILL }},
    { &hf_mms_cs_request_detail,
      { "cs-request-detail", "mms.cs_request_detail",
        FT_UINT32, BASE_DEC, VALS(mms_CS_Request_Detail_vals), 0,
        "mms.CS_Request_Detail", HFILL }},
    { &hf_mms_unconfirmedService,
      { "unconfirmedService", "mms.unconfirmedService",
        FT_UINT32, BASE_DEC, VALS(mms_UnconfirmedService_vals), 0,
        "mms.UnconfirmedService", HFILL }},
    { &hf_mms_confirmedServiceResponse,
      { "confirmedServiceResponse", "mms.confirmedServiceResponse",
        FT_UINT32, BASE_DEC, VALS(mms_ConfirmedServiceResponse_vals), 0,
        "mms.ConfirmedServiceResponse", HFILL }},
    { &hf_mms_modifierPosition,
      { "modifierPosition", "mms.modifierPosition",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Unsigned32", HFILL }},
    { &hf_mms_serviceError,
      { "serviceError", "mms.serviceError",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.ServiceError", HFILL }},
    { &hf_mms_informationReport,
      { "informationReport", "mms.informationReport",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.InformationReport", HFILL }},
    { &hf_mms_unsolicitedStatus,
      { "unsolicitedStatus", "mms.unsolicitedStatus",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.UnsolicitedStatus", HFILL }},
    { &hf_mms_eventNotification,
      { "eventNotification", "mms.eventNotification",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.EventNotification", HFILL }},
    { &hf_mms_attach_To_Event_Condition,
      { "attach-To-Event-Condition", "mms.attach_To_Event_Condition",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.AttachToEventCondition", HFILL }},
    { &hf_mms_attach_To_Semaphore,
      { "attach-To-Semaphore", "mms.attach_To_Semaphore",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.AttachToSemaphore", HFILL }},
    { &hf_mms_status,
      { "status", "mms.status",
        FT_BOOLEAN, 8, NULL, 0,
        "mms.Status_Request", HFILL }},
    { &hf_mms_getNameList,
      { "getNameList", "mms.getNameList",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.GetNameList_Request", HFILL }},
    { &hf_mms_identify,
      { "identify", "mms.identify",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.Identify_Request", HFILL }},
    { &hf_mms_rename,
      { "rename", "mms.rename",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.Rename_Request", HFILL }},
    { &hf_mms_read,
      { "read", "mms.read",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.Read_Request", HFILL }},
    { &hf_mms_write,
      { "write", "mms.write",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.Write_Request", HFILL }},
    { &hf_mms_getVariableAccessAttributes,
      { "getVariableAccessAttributes", "mms.getVariableAccessAttributes",
        FT_UINT32, BASE_DEC, VALS(mms_GetVariableAccessAttributes_Request_vals), 0,
        "mms.GetVariableAccessAttributes_Request", HFILL }},
    { &hf_mms_defineNamedVariable,
      { "defineNamedVariable", "mms.defineNamedVariable",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.DefineNamedVariable_Request", HFILL }},
    { &hf_mms_defineScatteredAccess,
      { "defineScatteredAccess", "mms.defineScatteredAccess",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.DefineScatteredAccess_Request", HFILL }},
    { &hf_mms_getScatteredAccessAttributes,
      { "getScatteredAccessAttributes", "mms.getScatteredAccessAttributes",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "mms.GetScatteredAccessAttributes_Request", HFILL }},
    { &hf_mms_deleteVariableAccess,
      { "deleteVariableAccess", "mms.deleteVariableAccess",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.DeleteVariableAccess_Request", HFILL }},
    { &hf_mms_defineNamedVariableList,
      { "defineNamedVariableList", "mms.defineNamedVariableList",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.DefineNamedVariableList_Request", HFILL }},
    { &hf_mms_getNamedVariableListAttributes,
      { "getNamedVariableListAttributes", "mms.getNamedVariableListAttributes",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "mms.GetNamedVariableListAttributes_Request", HFILL }},
    { &hf_mms_deleteNamedVariableList,
      { "deleteNamedVariableList", "mms.deleteNamedVariableList",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.DeleteNamedVariableList_Request", HFILL }},
    { &hf_mms_defineNamedType,
      { "defineNamedType", "mms.defineNamedType",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.DefineNamedType_Request", HFILL }},
    { &hf_mms_getNamedTypeAttributes,
      { "getNamedTypeAttributes", "mms.getNamedTypeAttributes",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "mms.GetNamedTypeAttributes_Request", HFILL }},
    { &hf_mms_deleteNamedType,
      { "deleteNamedType", "mms.deleteNamedType",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.DeleteNamedType_Request", HFILL }},
    { &hf_mms_input,
      { "input", "mms.input",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.Input_Request", HFILL }},
    { &hf_mms_output,
      { "output", "mms.output",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.Output_Request", HFILL }},
    { &hf_mms_takeControl,
      { "takeControl", "mms.takeControl",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.TakeControl_Request", HFILL }},
    { &hf_mms_relinquishControl,
      { "relinquishControl", "mms.relinquishControl",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.RelinquishControl_Request", HFILL }},
    { &hf_mms_defineSemaphore,
      { "defineSemaphore", "mms.defineSemaphore",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.DefineSemaphore_Request", HFILL }},
    { &hf_mms_deleteSemaphore,
      { "deleteSemaphore", "mms.deleteSemaphore",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "mms.DeleteSemaphore_Request", HFILL }},
    { &hf_mms_reportSemaphoreStatus,
      { "reportSemaphoreStatus", "mms.reportSemaphoreStatus",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "mms.ReportSemaphoreStatus_Request", HFILL }},
    { &hf_mms_reportPoolSemaphoreStatus,
      { "reportPoolSemaphoreStatus", "mms.reportPoolSemaphoreStatus",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.ReportPoolSemaphoreStatus_Request", HFILL }},
    { &hf_mms_reportSemaphoreEntryStatus,
      { "reportSemaphoreEntryStatus", "mms.reportSemaphoreEntryStatus",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.ReportSemaphoreEntryStatus_Request", HFILL }},
    { &hf_mms_initiateDownloadSequence,
      { "initiateDownloadSequence", "mms.initiateDownloadSequence",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.InitiateDownloadSequence_Request", HFILL }},
    { &hf_mms_downloadSegment,
      { "downloadSegment", "mms.downloadSegment",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.DownloadSegment_Request", HFILL }},
    { &hf_mms_terminateDownloadSequence,
      { "terminateDownloadSequence", "mms.terminateDownloadSequence",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.TerminateDownloadSequence_Request", HFILL }},
    { &hf_mms_initiateUploadSequence,
      { "initiateUploadSequence", "mms.initiateUploadSequence",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.InitiateUploadSequence_Request", HFILL }},
    { &hf_mms_uploadSegment,
      { "uploadSegment", "mms.uploadSegment",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.UploadSegment_Request", HFILL }},
    { &hf_mms_terminateUploadSequence,
      { "terminateUploadSequence", "mms.terminateUploadSequence",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.TerminateUploadSequence_Request", HFILL }},
    { &hf_mms_requestDomainDownload,
      { "requestDomainDownload", "mms.requestDomainDownload",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.RequestDomainDownload_Request", HFILL }},
    { &hf_mms_requestDomainUpload,
      { "requestDomainUpload", "mms.requestDomainUpload",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.RequestDomainUpload_Request", HFILL }},
    { &hf_mms_loadDomainContent,
      { "loadDomainContent", "mms.loadDomainContent",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.LoadDomainContent_Request", HFILL }},
    { &hf_mms_storeDomainContent,
      { "storeDomainContent", "mms.storeDomainContent",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.StoreDomainContent_Request", HFILL }},
    { &hf_mms_deleteDomain,
      { "deleteDomain", "mms.deleteDomain",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.DeleteDomain_Request", HFILL }},
    { &hf_mms_getDomainAttributes,
      { "getDomainAttributes", "mms.getDomainAttributes",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.GetDomainAttributes_Request", HFILL }},
    { &hf_mms_createProgramInvocation,
      { "createProgramInvocation", "mms.createProgramInvocation",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.CreateProgramInvocation_Request", HFILL }},
    { &hf_mms_deleteProgramInvocation,
      { "deleteProgramInvocation", "mms.deleteProgramInvocation",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.DeleteProgramInvocation_Request", HFILL }},
    { &hf_mms_start,
      { "start", "mms.start",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.Start_Request", HFILL }},
    { &hf_mms_stop,
      { "stop", "mms.stop",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.Stop_Request", HFILL }},
    { &hf_mms_resume,
      { "resume", "mms.resume",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.Resume_Request", HFILL }},
    { &hf_mms_reset,
      { "reset", "mms.reset",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.Reset_Request", HFILL }},
    { &hf_mms_kill,
      { "kill", "mms.kill",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.Kill_Request", HFILL }},
    { &hf_mms_getProgramInvocationAttributes,
      { "getProgramInvocationAttributes", "mms.getProgramInvocationAttributes",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.GetProgramInvocationAttributes_Request", HFILL }},
    { &hf_mms_obtainFile,
      { "obtainFile", "mms.obtainFile",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.ObtainFile_Request", HFILL }},
    { &hf_mms_defineEventCondition,
      { "defineEventCondition", "mms.defineEventCondition",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.DefineEventCondition_Request", HFILL }},
    { &hf_mms_deleteEventCondition,
      { "deleteEventCondition", "mms.deleteEventCondition",
        FT_UINT32, BASE_DEC, VALS(mms_DeleteEventCondition_Request_vals), 0,
        "mms.DeleteEventCondition_Request", HFILL }},
    { &hf_mms_getEventConditionAttributes,
      { "getEventConditionAttributes", "mms.getEventConditionAttributes",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "mms.GetEventConditionAttributes_Request", HFILL }},
    { &hf_mms_reportEventConditionStatus,
      { "reportEventConditionStatus", "mms.reportEventConditionStatus",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "mms.ReportEventConditionStatus_Request", HFILL }},
    { &hf_mms_alterEventConditionMonitoring,
      { "alterEventConditionMonitoring", "mms.alterEventConditionMonitoring",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.AlterEventConditionMonitoring_Request", HFILL }},
    { &hf_mms_triggerEvent,
      { "triggerEvent", "mms.triggerEvent",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.TriggerEvent_Request", HFILL }},
    { &hf_mms_defineEventAction,
      { "defineEventAction", "mms.defineEventAction",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.DefineEventAction_Request", HFILL }},
    { &hf_mms_deleteEventAction,
      { "deleteEventAction", "mms.deleteEventAction",
        FT_UINT32, BASE_DEC, VALS(mms_DeleteEventAction_Request_vals), 0,
        "mms.DeleteEventAction_Request", HFILL }},
    { &hf_mms_getEventActionAttributes,
      { "getEventActionAttributes", "mms.getEventActionAttributes",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "mms.GetEventActionAttributes_Request", HFILL }},
    { &hf_mms_reportEventActionStatus,
      { "reportEventActionStatus", "mms.reportEventActionStatus",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "mms.ReportEventActionStatus_Request", HFILL }},
    { &hf_mms_defineEventEnrollment,
      { "defineEventEnrollment", "mms.defineEventEnrollment",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.DefineEventEnrollment_Request", HFILL }},
    { &hf_mms_deleteEventEnrollment,
      { "deleteEventEnrollment", "mms.deleteEventEnrollment",
        FT_UINT32, BASE_DEC, VALS(mms_DeleteEventEnrollment_Request_vals), 0,
        "mms.DeleteEventEnrollment_Request", HFILL }},
    { &hf_mms_alterEventEnrollment,
      { "alterEventEnrollment", "mms.alterEventEnrollment",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.AlterEventEnrollment_Request", HFILL }},
    { &hf_mms_reportEventEnrollmentStatus,
      { "reportEventEnrollmentStatus", "mms.reportEventEnrollmentStatus",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "mms.ReportEventEnrollmentStatus_Request", HFILL }},
    { &hf_mms_getEventEnrollmentAttributes,
      { "getEventEnrollmentAttributes", "mms.getEventEnrollmentAttributes",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.GetEventEnrollmentAttributes_Request", HFILL }},
    { &hf_mms_acknowledgeEventNotification,
      { "acknowledgeEventNotification", "mms.acknowledgeEventNotification",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.AcknowledgeEventNotification_Request", HFILL }},
    { &hf_mms_getAlarmSummary,
      { "getAlarmSummary", "mms.getAlarmSummary",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.GetAlarmSummary_Request", HFILL }},
    { &hf_mms_getAlarmEnrollmentSummary,
      { "getAlarmEnrollmentSummary", "mms.getAlarmEnrollmentSummary",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.GetAlarmEnrollmentSummary_Request", HFILL }},
    { &hf_mms_readJournal,
      { "readJournal", "mms.readJournal",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.ReadJournal_Request", HFILL }},
    { &hf_mms_writeJournal,
      { "writeJournal", "mms.writeJournal",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.WriteJournal_Request", HFILL }},
    { &hf_mms_initializeJournal,
      { "initializeJournal", "mms.initializeJournal",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.InitializeJournal_Request", HFILL }},
    { &hf_mms_reportJournalStatus,
      { "reportJournalStatus", "mms.reportJournalStatus",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "mms.ReportJournalStatus_Request", HFILL }},
    { &hf_mms_createJournal,
      { "createJournal", "mms.createJournal",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.CreateJournal_Request", HFILL }},
    { &hf_mms_deleteJournal,
      { "deleteJournal", "mms.deleteJournal",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.DeleteJournal_Request", HFILL }},
    { &hf_mms_getCapabilityList,
      { "getCapabilityList", "mms.getCapabilityList",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.GetCapabilityList_Request", HFILL }},
    { &hf_mms_fileOpen,
      { "fileOpen", "mms.fileOpen",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.FileOpen_Request", HFILL }},
    { &hf_mms_fileRead,
      { "fileRead", "mms.fileRead",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.FileRead_Request", HFILL }},
    { &hf_mms_fileClose,
      { "fileClose", "mms.fileClose",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.FileClose_Request", HFILL }},
    { &hf_mms_fileRename,
      { "fileRename", "mms.fileRename",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.FileRename_Request", HFILL }},
    { &hf_mms_fileDelete,
      { "fileDelete", "mms.fileDelete",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.FileDelete_Request", HFILL }},
    { &hf_mms_fileDirectory,
      { "fileDirectory", "mms.fileDirectory",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.FileDirectory_Request", HFILL }},
    { &hf_mms_foo,
      { "foo", "mms.foo",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.INTEGER", HFILL }},
    { &hf_mms_status1,
      { "status", "mms.status",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.Status_Response", HFILL }},
    { &hf_mms_getNameList1,
      { "getNameList", "mms.getNameList",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.GetNameList_Response", HFILL }},
    { &hf_mms_identify1,
      { "identify", "mms.identify",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.Identify_Response", HFILL }},
    { &hf_mms_rename1,
      { "rename", "mms.rename",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.Rename_Response", HFILL }},
    { &hf_mms_read1,
      { "read", "mms.read",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.Read_Response", HFILL }},
    { &hf_mms_write1,
      { "write", "mms.write",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.Write_Response", HFILL }},
    { &hf_mms_getVariableAccessAttributes1,
      { "getVariableAccessAttributes", "mms.getVariableAccessAttributes",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.GetVariableAccessAttributes_Response", HFILL }},
    { &hf_mms_defineNamedVariable1,
      { "defineNamedVariable", "mms.defineNamedVariable",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.DefineNamedVariable_Response", HFILL }},
    { &hf_mms_defineScatteredAccess1,
      { "defineScatteredAccess", "mms.defineScatteredAccess",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.DefineScatteredAccess_Response", HFILL }},
    { &hf_mms_getScatteredAccessAttributes1,
      { "getScatteredAccessAttributes", "mms.getScatteredAccessAttributes",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.GetScatteredAccessAttributes_Response", HFILL }},
    { &hf_mms_deleteVariableAccess1,
      { "deleteVariableAccess", "mms.deleteVariableAccess",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.DeleteVariableAccess_Response", HFILL }},
    { &hf_mms_defineNamedVariableList1,
      { "defineNamedVariableList", "mms.defineNamedVariableList",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.DefineNamedVariableList_Response", HFILL }},
    { &hf_mms_getNamedVariableListAttributes1,
      { "getNamedVariableListAttributes", "mms.getNamedVariableListAttributes",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.GetNamedVariableListAttributes_Response", HFILL }},
    { &hf_mms_deleteNamedVariableList1,
      { "deleteNamedVariableList", "mms.deleteNamedVariableList",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.DeleteNamedVariableList_Response", HFILL }},
    { &hf_mms_defineNamedType1,
      { "defineNamedType", "mms.defineNamedType",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.DefineNamedType_Response", HFILL }},
    { &hf_mms_getNamedTypeAttributes1,
      { "getNamedTypeAttributes", "mms.getNamedTypeAttributes",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.GetNamedTypeAttributes_Response", HFILL }},
    { &hf_mms_deleteNamedType1,
      { "deleteNamedType", "mms.deleteNamedType",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.DeleteNamedType_Response", HFILL }},
    { &hf_mms_input1,
      { "input", "mms.input",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.Input_Response", HFILL }},
    { &hf_mms_output1,
      { "output", "mms.output",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.Output_Response", HFILL }},
    { &hf_mms_takeControl1,
      { "takeControl", "mms.takeControl",
        FT_UINT32, BASE_DEC, VALS(mms_TakeControl_Response_vals), 0,
        "mms.TakeControl_Response", HFILL }},
    { &hf_mms_relinquishControl1,
      { "relinquishControl", "mms.relinquishControl",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.RelinquishControl_Response", HFILL }},
    { &hf_mms_defineSemaphore1,
      { "defineSemaphore", "mms.defineSemaphore",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.DefineSemaphore_Response", HFILL }},
    { &hf_mms_deleteSemaphore1,
      { "deleteSemaphore", "mms.deleteSemaphore",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.DeleteSemaphore_Response", HFILL }},
    { &hf_mms_reportSemaphoreStatus1,
      { "reportSemaphoreStatus", "mms.reportSemaphoreStatus",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.ReportSemaphoreStatus_Response", HFILL }},
    { &hf_mms_reportPoolSemaphoreStatus1,
      { "reportPoolSemaphoreStatus", "mms.reportPoolSemaphoreStatus",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.ReportPoolSemaphoreStatus_Response", HFILL }},
    { &hf_mms_reportSemaphoreEntryStatus1,
      { "reportSemaphoreEntryStatus", "mms.reportSemaphoreEntryStatus",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.ReportSemaphoreEntryStatus_Response", HFILL }},
    { &hf_mms_initiateDownloadSequence1,
      { "initiateDownloadSequence", "mms.initiateDownloadSequence",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.InitiateDownloadSequence_Response", HFILL }},
    { &hf_mms_downloadSegment1,
      { "downloadSegment", "mms.downloadSegment",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.DownloadSegment_Response", HFILL }},
    { &hf_mms_terminateDownloadSequence1,
      { "terminateDownloadSequence", "mms.terminateDownloadSequence",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.TerminateDownloadSequence_Response", HFILL }},
    { &hf_mms_initiateUploadSequence1,
      { "initiateUploadSequence", "mms.initiateUploadSequence",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.InitiateUploadSequence_Response", HFILL }},
    { &hf_mms_uploadSegment1,
      { "uploadSegment", "mms.uploadSegment",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.UploadSegment_Response", HFILL }},
    { &hf_mms_terminateUploadSequence1,
      { "terminateUploadSequence", "mms.terminateUploadSequence",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.TerminateUploadSequence_Response", HFILL }},
    { &hf_mms_requestDomainDownLoad,
      { "requestDomainDownLoad", "mms.requestDomainDownLoad",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.RequestDomainDownload_Response", HFILL }},
    { &hf_mms_requestDomainUpload1,
      { "requestDomainUpload", "mms.requestDomainUpload",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.RequestDomainUpload_Response", HFILL }},
    { &hf_mms_loadDomainContent1,
      { "loadDomainContent", "mms.loadDomainContent",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.LoadDomainContent_Response", HFILL }},
    { &hf_mms_storeDomainContent1,
      { "storeDomainContent", "mms.storeDomainContent",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.StoreDomainContent_Response", HFILL }},
    { &hf_mms_deleteDomain1,
      { "deleteDomain", "mms.deleteDomain",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.DeleteDomain_Response", HFILL }},
    { &hf_mms_getDomainAttributes1,
      { "getDomainAttributes", "mms.getDomainAttributes",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.GetDomainAttributes_Response", HFILL }},
    { &hf_mms_createProgramInvocation1,
      { "createProgramInvocation", "mms.createProgramInvocation",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.CreateProgramInvocation_Response", HFILL }},
    { &hf_mms_deleteProgramInvocation1,
      { "deleteProgramInvocation", "mms.deleteProgramInvocation",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.DeleteProgramInvocation_Response", HFILL }},
    { &hf_mms_start1,
      { "start", "mms.start",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.Start_Response", HFILL }},
    { &hf_mms_stop1,
      { "stop", "mms.stop",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.Stop_Response", HFILL }},
    { &hf_mms_resume1,
      { "resume", "mms.resume",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.Resume_Response", HFILL }},
    { &hf_mms_reset1,
      { "reset", "mms.reset",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.Reset_Response", HFILL }},
    { &hf_mms_kill1,
      { "kill", "mms.kill",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.Kill_Response", HFILL }},
    { &hf_mms_getProgramInvocationAttributes1,
      { "getProgramInvocationAttributes", "mms.getProgramInvocationAttributes",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.GetProgramInvocationAttributes_Response", HFILL }},
    { &hf_mms_obtainFile1,
      { "obtainFile", "mms.obtainFile",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.ObtainFile_Response", HFILL }},
    { &hf_mms_fileOpen1,
      { "fileOpen", "mms.fileOpen",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.FileOpen_Response", HFILL }},
    { &hf_mms_defineEventCondition1,
      { "defineEventCondition", "mms.defineEventCondition",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.DefineEventCondition_Response", HFILL }},
    { &hf_mms_deleteEventCondition1,
      { "deleteEventCondition", "mms.deleteEventCondition",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.DeleteEventCondition_Response", HFILL }},
    { &hf_mms_getEventConditionAttributes1,
      { "getEventConditionAttributes", "mms.getEventConditionAttributes",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.GetEventConditionAttributes_Response", HFILL }},
    { &hf_mms_reportEventConditionStatus1,
      { "reportEventConditionStatus", "mms.reportEventConditionStatus",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.ReportEventConditionStatus_Response", HFILL }},
    { &hf_mms_alterEventConditionMonitoring1,
      { "alterEventConditionMonitoring", "mms.alterEventConditionMonitoring",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.AlterEventConditionMonitoring_Response", HFILL }},
    { &hf_mms_triggerEvent1,
      { "triggerEvent", "mms.triggerEvent",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.TriggerEvent_Response", HFILL }},
    { &hf_mms_defineEventAction1,
      { "defineEventAction", "mms.defineEventAction",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.DefineEventAction_Response", HFILL }},
    { &hf_mms_deleteEventAction1,
      { "deleteEventAction", "mms.deleteEventAction",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.DeleteEventAction_Response", HFILL }},
    { &hf_mms_getEventActionAttributes1,
      { "getEventActionAttributes", "mms.getEventActionAttributes",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.GetEventActionAttributes_Response", HFILL }},
    { &hf_mms_reportActionStatus,
      { "reportActionStatus", "mms.reportActionStatus",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.ReportEventActionStatus_Response", HFILL }},
    { &hf_mms_defineEventEnrollment1,
      { "defineEventEnrollment", "mms.defineEventEnrollment",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.DefineEventEnrollment_Response", HFILL }},
    { &hf_mms_deleteEventEnrollment1,
      { "deleteEventEnrollment", "mms.deleteEventEnrollment",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.DeleteEventEnrollment_Response", HFILL }},
    { &hf_mms_alterEventEnrollment1,
      { "alterEventEnrollment", "mms.alterEventEnrollment",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.AlterEventEnrollment_Response", HFILL }},
    { &hf_mms_reportEventEnrollmentStatus1,
      { "reportEventEnrollmentStatus", "mms.reportEventEnrollmentStatus",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.ReportEventEnrollmentStatus_Response", HFILL }},
    { &hf_mms_getEventEnrollmentAttributes1,
      { "getEventEnrollmentAttributes", "mms.getEventEnrollmentAttributes",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.GetEventEnrollmentAttributes_Response", HFILL }},
    { &hf_mms_acknowledgeEventNotification1,
      { "acknowledgeEventNotification", "mms.acknowledgeEventNotification",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.AcknowledgeEventNotification_Response", HFILL }},
    { &hf_mms_getAlarmSummary1,
      { "getAlarmSummary", "mms.getAlarmSummary",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.GetAlarmSummary_Response", HFILL }},
    { &hf_mms_getAlarmEnrollmentSummary1,
      { "getAlarmEnrollmentSummary", "mms.getAlarmEnrollmentSummary",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.GetAlarmEnrollmentSummary_Response", HFILL }},
    { &hf_mms_readJournal1,
      { "readJournal", "mms.readJournal",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.ReadJournal_Response", HFILL }},
    { &hf_mms_writeJournal1,
      { "writeJournal", "mms.writeJournal",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.WriteJournal_Response", HFILL }},
    { &hf_mms_initializeJournal1,
      { "initializeJournal", "mms.initializeJournal",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.InitializeJournal_Response", HFILL }},
    { &hf_mms_reportJournalStatus1,
      { "reportJournalStatus", "mms.reportJournalStatus",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.ReportJournalStatus_Response", HFILL }},
    { &hf_mms_createJournal1,
      { "createJournal", "mms.createJournal",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.CreateJournal_Response", HFILL }},
    { &hf_mms_deleteJournal1,
      { "deleteJournal", "mms.deleteJournal",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.DeleteJournal_Response", HFILL }},
    { &hf_mms_getCapabilityList1,
      { "getCapabilityList", "mms.getCapabilityList",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.GetCapabilityList_Response", HFILL }},
    { &hf_mms_fileRead1,
      { "fileRead", "mms.fileRead",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.FileRead_Response", HFILL }},
    { &hf_mms_fileClose1,
      { "fileClose", "mms.fileClose",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.FileClose_Response", HFILL }},
    { &hf_mms_fileRename1,
      { "fileRename", "mms.fileRename",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.FileRename_Response", HFILL }},
    { &hf_mms_fileDelete1,
      { "fileDelete", "mms.fileDelete",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.FileDelete_Response", HFILL }},
    { &hf_mms_fileDirectory1,
      { "fileDirectory", "mms.fileDirectory",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.FileDirectory_Response", HFILL }},
    { &hf_mms_FileName_item,
      { "Item", "mms.FileName_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.GraphicString", HFILL }},
    { &hf_mms_vmd_specific,
      { "vmd-specific", "mms.vmd_specific",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.Identifier", HFILL }},
    { &hf_mms_domain_specific,
      { "domain-specific", "mms.domain_specific",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.T_domain_specific", HFILL }},
    { &hf_mms_domainId,
      { "domainId", "mms.domainId",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.Identifier", HFILL }},
    { &hf_mms_itemId,
      { "itemId", "mms.itemId",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.Identifier", HFILL }},
    { &hf_mms_aa_specific,
      { "aa-specific", "mms.aa_specific",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.Identifier", HFILL }},
    { &hf_mms_ap_title,
      { "ap-title", "mms.ap_title",
        FT_UINT32, BASE_DEC, VALS(acse_AP_title_vals), 0,
        "mms.T_ap_title", HFILL }},
    { &hf_mms_ap_invocation_id,
      { "ap-invocation-id", "mms.ap_invocation_id",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.T_ap_invocation_id", HFILL }},
    { &hf_mms_ae_qualifier,
      { "ae-qualifier", "mms.ae_qualifier",
        FT_UINT32, BASE_DEC, VALS(acse_ASO_qualifier_vals), 0,
        "mms.T_ae_qualifier", HFILL }},
    { &hf_mms_ae_invocation_id,
      { "ae-invocation-id", "mms.ae_invocation_id",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.T_ae_invocation_id", HFILL }},
    { &hf_mms_localDetailCalling,
      { "localDetailCalling", "mms.localDetailCalling",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Integer32", HFILL }},
    { &hf_mms_proposedMaxServOutstandingCalling,
      { "proposedMaxServOutstandingCalling", "mms.proposedMaxServOutstandingCalling",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Integer16", HFILL }},
    { &hf_mms_proposedMaxServOutstandingCalled,
      { "proposedMaxServOutstandingCalled", "mms.proposedMaxServOutstandingCalled",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Integer16", HFILL }},
    { &hf_mms_proposedDataStructureNestingLevel,
      { "proposedDataStructureNestingLevel", "mms.proposedDataStructureNestingLevel",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Integer8", HFILL }},
    { &hf_mms_mmsInitRequestDetail,
      { "mmsInitRequestDetail", "mms.mmsInitRequestDetail",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.InitRequestDetail", HFILL }},
    { &hf_mms_proposedVersionNumber,
      { "proposedVersionNumber", "mms.proposedVersionNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Integer16", HFILL }},
    { &hf_mms_proposedParameterCBB,
      { "proposedParameterCBB", "mms.proposedParameterCBB",
        FT_BYTES, BASE_HEX, NULL, 0,
        "mms.ParameterSupportOptions", HFILL }},
    { &hf_mms_servicesSupportedCalling,
      { "servicesSupportedCalling", "mms.servicesSupportedCalling",
        FT_BYTES, BASE_HEX, NULL, 0,
        "mms.ServiceSupportOptions", HFILL }},
    { &hf_mms_localDetailCalled,
      { "localDetailCalled", "mms.localDetailCalled",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Integer32", HFILL }},
    { &hf_mms_negociatedMaxServOutstandingCalling,
      { "negociatedMaxServOutstandingCalling", "mms.negociatedMaxServOutstandingCalling",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Integer16", HFILL }},
    { &hf_mms_negociatedMaxServOutstandingCalled,
      { "negociatedMaxServOutstandingCalled", "mms.negociatedMaxServOutstandingCalled",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Integer16", HFILL }},
    { &hf_mms_negociatedDataStructureNestingLevel,
      { "negociatedDataStructureNestingLevel", "mms.negociatedDataStructureNestingLevel",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Integer8", HFILL }},
    { &hf_mms_mmsInitResponseDetail,
      { "mmsInitResponseDetail", "mms.mmsInitResponseDetail",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.InitResponseDetail", HFILL }},
    { &hf_mms_negociatedVersionNumber,
      { "negociatedVersionNumber", "mms.negociatedVersionNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Integer16", HFILL }},
    { &hf_mms_negociatedParameterCBB,
      { "negociatedParameterCBB", "mms.negociatedParameterCBB",
        FT_BYTES, BASE_HEX, NULL, 0,
        "mms.ParameterSupportOptions", HFILL }},
    { &hf_mms_servicesSupportedCalled,
      { "servicesSupportedCalled", "mms.servicesSupportedCalled",
        FT_BYTES, BASE_HEX, NULL, 0,
        "mms.ServiceSupportOptions", HFILL }},
    { &hf_mms_originalInvokeID,
      { "originalInvokeID", "mms.originalInvokeID",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Unsigned32", HFILL }},
    { &hf_mms_errorClass,
      { "errorClass", "mms.errorClass",
        FT_UINT32, BASE_DEC, VALS(mms_T_errorClass_vals), 0,
        "mms.T_errorClass", HFILL }},
    { &hf_mms_vmd_state,
      { "vmd-state", "mms.vmd_state",
        FT_INT32, BASE_DEC, VALS(mms_T_vmd_state_vals), 0,
        "mms.T_vmd_state", HFILL }},
    { &hf_mms_application_reference,
      { "application-reference", "mms.application_reference",
        FT_INT32, BASE_DEC, VALS(mms_T_application_reference_vals), 0,
        "mms.T_application_reference", HFILL }},
    { &hf_mms_definition,
      { "definition", "mms.definition",
        FT_INT32, BASE_DEC, VALS(mms_T_definition_vals), 0,
        "mms.T_definition", HFILL }},
    { &hf_mms_resource,
      { "resource", "mms.resource",
        FT_INT32, BASE_DEC, VALS(mms_T_resource_vals), 0,
        "mms.T_resource", HFILL }},
    { &hf_mms_service,
      { "service", "mms.service",
        FT_INT32, BASE_DEC, VALS(mms_T_service_vals), 0,
        "mms.T_service", HFILL }},
    { &hf_mms_service_preempt,
      { "service-preempt", "mms.service_preempt",
        FT_INT32, BASE_DEC, VALS(mms_T_service_preempt_vals), 0,
        "mms.T_service_preempt", HFILL }},
    { &hf_mms_time_resolution,
      { "time-resolution", "mms.time_resolution",
        FT_INT32, BASE_DEC, VALS(mms_T_time_resolution_vals), 0,
        "mms.T_time_resolution", HFILL }},
    { &hf_mms_access,
      { "access", "mms.access",
        FT_INT32, BASE_DEC, VALS(mms_T_access_vals), 0,
        "mms.T_access", HFILL }},
    { &hf_mms_initiate,
      { "initiate", "mms.initiate",
        FT_INT32, BASE_DEC, VALS(mms_T_initiate_vals), 0,
        "mms.T_initiate", HFILL }},
    { &hf_mms_conclude,
      { "conclude", "mms.conclude",
        FT_INT32, BASE_DEC, VALS(mms_T_conclude_vals), 0,
        "mms.T_conclude", HFILL }},
    { &hf_mms_cancel,
      { "cancel", "mms.cancel",
        FT_INT32, BASE_DEC, VALS(mms_T_cancel_vals), 0,
        "mms.T_cancel", HFILL }},
    { &hf_mms_file,
      { "file", "mms.file",
        FT_INT32, BASE_DEC, VALS(mms_T_file_vals), 0,
        "mms.T_file", HFILL }},
    { &hf_mms_others,
      { "others", "mms.others",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.INTEGER", HFILL }},
    { &hf_mms_additionalCode,
      { "additionalCode", "mms.additionalCode",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.INTEGER", HFILL }},
    { &hf_mms_additionalDescription,
      { "additionalDescription", "mms.additionalDescription",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.VisibleString", HFILL }},
    { &hf_mms_serviceSpecificInformation,
      { "serviceSpecificInformation", "mms.serviceSpecificInformation",
        FT_UINT32, BASE_DEC, VALS(mms_T_serviceSpecificInformation_vals), 0,
        "mms.T_serviceSpecificInformation", HFILL }},
    { &hf_mms_obtainFile2,
      { "obtainFile", "mms.obtainFile",
        FT_INT32, BASE_DEC, VALS(mms_ObtainFile_Error_vals), 0,
        "mms.ObtainFile_Error", HFILL }},
    { &hf_mms_start2,
      { "start", "mms.start",
        FT_INT32, BASE_DEC, VALS(mms_ProgramInvocationState_vals), 0,
        "mms.Start_Error", HFILL }},
    { &hf_mms_stop2,
      { "stop", "mms.stop",
        FT_INT32, BASE_DEC, VALS(mms_ProgramInvocationState_vals), 0,
        "mms.Stop_Error", HFILL }},
    { &hf_mms_resume2,
      { "resume", "mms.resume",
        FT_INT32, BASE_DEC, VALS(mms_ProgramInvocationState_vals), 0,
        "mms.Resume_Error", HFILL }},
    { &hf_mms_reset2,
      { "reset", "mms.reset",
        FT_INT32, BASE_DEC, VALS(mms_ProgramInvocationState_vals), 0,
        "mms.Reset_Error", HFILL }},
    { &hf_mms_deleteVariableAccess2,
      { "deleteVariableAccess", "mms.deleteVariableAccess",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.DeleteVariableAccess_Error", HFILL }},
    { &hf_mms_deleteNamedVariableList2,
      { "deleteNamedVariableList", "mms.deleteNamedVariableList",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.DeleteNamedVariableList_Error", HFILL }},
    { &hf_mms_deleteNamedType2,
      { "deleteNamedType", "mms.deleteNamedType",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.DeleteNamedType_Error", HFILL }},
    { &hf_mms_defineEventEnrollment_Error,
      { "defineEventEnrollment-Error", "mms.defineEventEnrollment_Error",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "mms.DefineEventEnrollment_Error", HFILL }},
    { &hf_mms_fileRename2,
      { "fileRename", "mms.fileRename",
        FT_INT32, BASE_DEC, VALS(mms_FileRename_Error_vals), 0,
        "mms.FileRename_Error", HFILL }},
    { &hf_mms_rejectReason,
      { "rejectReason", "mms.rejectReason",
        FT_UINT32, BASE_DEC, VALS(mms_T_rejectReason_vals), 0,
        "mms.T_rejectReason", HFILL }},
    { &hf_mms_confirmed_requestPDU,
      { "confirmed-requestPDU", "mms.confirmed_requestPDU",
        FT_INT32, BASE_DEC, VALS(mms_T_confirmed_requestPDU_vals), 0,
        "mms.T_confirmed_requestPDU", HFILL }},
    { &hf_mms_confirmed_responsePDU,
      { "confirmed-responsePDU", "mms.confirmed_responsePDU",
        FT_INT32, BASE_DEC, VALS(mms_T_confirmed_responsePDU_vals), 0,
        "mms.T_confirmed_responsePDU", HFILL }},
    { &hf_mms_confirmed_errorPDU,
      { "confirmed-errorPDU", "mms.confirmed_errorPDU",
        FT_INT32, BASE_DEC, VALS(mms_T_confirmed_errorPDU_vals), 0,
        "mms.T_confirmed_errorPDU", HFILL }},
    { &hf_mms_unconfirmedPDU,
      { "unconfirmedPDU", "mms.unconfirmedPDU",
        FT_INT32, BASE_DEC, VALS(mms_T_unconfirmedPDU_vals), 0,
        "mms.T_unconfirmedPDU", HFILL }},
    { &hf_mms_pdu_error,
      { "pdu-error", "mms.pdu_error",
        FT_INT32, BASE_DEC, VALS(mms_T_pdu_error_vals), 0,
        "mms.T_pdu_error", HFILL }},
    { &hf_mms_cancel_requestPDU,
      { "cancel-requestPDU", "mms.cancel_requestPDU",
        FT_INT32, BASE_DEC, VALS(mms_T_cancel_requestPDU_vals), 0,
        "mms.T_cancel_requestPDU", HFILL }},
    { &hf_mms_cancel_responsePDU,
      { "cancel-responsePDU", "mms.cancel_responsePDU",
        FT_INT32, BASE_DEC, VALS(mms_T_cancel_responsePDU_vals), 0,
        "mms.T_cancel_responsePDU", HFILL }},
    { &hf_mms_cancel_errorPDU,
      { "cancel-errorPDU", "mms.cancel_errorPDU",
        FT_INT32, BASE_DEC, VALS(mms_T_cancel_errorPDU_vals), 0,
        "mms.T_cancel_errorPDU", HFILL }},
    { &hf_mms_conclude_requestPDU,
      { "conclude-requestPDU", "mms.conclude_requestPDU",
        FT_INT32, BASE_DEC, VALS(mms_T_conclude_requestPDU_vals), 0,
        "mms.T_conclude_requestPDU", HFILL }},
    { &hf_mms_conclude_responsePDU,
      { "conclude-responsePDU", "mms.conclude_responsePDU",
        FT_INT32, BASE_DEC, VALS(mms_T_conclude_responsePDU_vals), 0,
        "mms.T_conclude_responsePDU", HFILL }},
    { &hf_mms_conclude_errorPDU,
      { "conclude-errorPDU", "mms.conclude_errorPDU",
        FT_INT32, BASE_DEC, VALS(mms_T_conclude_errorPDU_vals), 0,
        "mms.T_conclude_errorPDU", HFILL }},
    { &hf_mms_vmdLogicalStatus,
      { "vmdLogicalStatus", "mms.vmdLogicalStatus",
        FT_INT32, BASE_DEC, VALS(mms_T_vmdLogicalStatus_vals), 0,
        "mms.T_vmdLogicalStatus", HFILL }},
    { &hf_mms_vmdPhysicalStatus,
      { "vmdPhysicalStatus", "mms.vmdPhysicalStatus",
        FT_INT32, BASE_DEC, VALS(mms_T_vmdPhysicalStatus_vals), 0,
        "mms.T_vmdPhysicalStatus", HFILL }},
    { &hf_mms_localDetail,
      { "localDetail", "mms.localDetail",
        FT_BYTES, BASE_HEX, NULL, 0,
        "mms.BIT_STRING_SIZE_0_128", HFILL }},
    { &hf_mms_extendedObjectClass,
      { "extendedObjectClass", "mms.extendedObjectClass",
        FT_UINT32, BASE_DEC, VALS(mms_T_extendedObjectClass_vals), 0,
        "mms.T_extendedObjectClass", HFILL }},
    { &hf_mms_objectClass,
      { "objectClass", "mms.objectClass",
        FT_INT32, BASE_DEC, VALS(mms_T_objectClass_vals), 0,
        "mms.T_objectClass", HFILL }},
    { &hf_mms_objectScope,
      { "objectScope", "mms.objectScope",
        FT_UINT32, BASE_DEC, VALS(mms_T_objectScope_vals), 0,
        "mms.T_objectScope", HFILL }},
    { &hf_mms_vmdSpecific,
      { "vmdSpecific", "mms.vmdSpecific",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.NULL", HFILL }},
    { &hf_mms_domainSpecific,
      { "domainSpecific", "mms.domainSpecific",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.Identifier", HFILL }},
    { &hf_mms_aaSpecific,
      { "aaSpecific", "mms.aaSpecific",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.NULL", HFILL }},
    { &hf_mms_continueAfter,
      { "continueAfter", "mms.continueAfter",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.Identifier", HFILL }},
    { &hf_mms_listOfIdentifier,
      { "listOfIdentifier", "mms.listOfIdentifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.SEQUENCE_OF_Identifier", HFILL }},
    { &hf_mms_listOfIdentifier_item,
      { "Item", "mms.listOfIdentifier_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.Identifier", HFILL }},
    { &hf_mms_moreFollows,
      { "moreFollows", "mms.moreFollows",
        FT_BOOLEAN, 8, NULL, 0,
        "mms.BOOLEAN", HFILL }},
    { &hf_mms_vendorName,
      { "vendorName", "mms.vendorName",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.VisibleString", HFILL }},
    { &hf_mms_modelName,
      { "modelName", "mms.modelName",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.VisibleString", HFILL }},
    { &hf_mms_revision,
      { "revision", "mms.revision",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.VisibleString", HFILL }},
    { &hf_mms_listOfAbstractSyntaxes,
      { "listOfAbstractSyntaxes", "mms.listOfAbstractSyntaxes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.T_listOfAbstractSyntaxes", HFILL }},
    { &hf_mms_listOfAbstractSyntaxes_item,
      { "Item", "mms.listOfAbstractSyntaxes_item",
        FT_OID, BASE_NONE, NULL, 0,
        "mms.OBJECT_IDENTIFIER", HFILL }},
    { &hf_mms_extendedObjectClass1,
      { "extendedObjectClass", "mms.extendedObjectClass",
        FT_UINT32, BASE_DEC, VALS(mms_T_extendedObjectClass1_vals), 0,
        "mms.T_extendedObjectClass1", HFILL }},
    { &hf_mms_objectClass1,
      { "objectClass", "mms.objectClass",
        FT_INT32, BASE_DEC, VALS(mms_T_objectClass1_vals), 0,
        "mms.T_objectClass1", HFILL }},
    { &hf_mms_currentName,
      { "currentName", "mms.currentName",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "mms.ObjectName", HFILL }},
    { &hf_mms_newIdentifier,
      { "newIdentifier", "mms.newIdentifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.Identifier", HFILL }},
    { &hf_mms_continueAfter1,
      { "continueAfter", "mms.continueAfter",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.VisibleString", HFILL }},
    { &hf_mms_listOfCapabilities,
      { "listOfCapabilities", "mms.listOfCapabilities",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.T_listOfCapabilities", HFILL }},
    { &hf_mms_listOfCapabilities_item,
      { "Item", "mms.listOfCapabilities_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.VisibleString", HFILL }},
    { &hf_mms_domainName,
      { "domainName", "mms.domainName",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.Identifier", HFILL }},
    { &hf_mms_listOfCapabilities1,
      { "listOfCapabilities", "mms.listOfCapabilities",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.T_listOfCapabilities1", HFILL }},
    { &hf_mms_sharable,
      { "sharable", "mms.sharable",
        FT_BOOLEAN, 8, NULL, 0,
        "mms.BOOLEAN", HFILL }},
    { &hf_mms_loadData,
      { "loadData", "mms.loadData",
        FT_UINT32, BASE_DEC, VALS(mms_T_loadData_vals), 0,
        "mms.T_loadData", HFILL }},
    { &hf_mms_non_coded,
      { "non-coded", "mms.non_coded",
        FT_BYTES, BASE_HEX, NULL, 0,
        "mms.OCTET_STRING", HFILL }},
    { &hf_mms_coded,
      { "coded", "mms.coded",
        FT_NONE, BASE_NONE, NULL, 0,
        "acse.EXTERNAL", HFILL }},
    { &hf_mms_discard,
      { "discard", "mms.discard",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.ServiceError", HFILL }},
    { &hf_mms_ulsmID,
      { "ulsmID", "mms.ulsmID",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Integer32", HFILL }},
    { &hf_mms_listOfCapabilities2,
      { "listOfCapabilities", "mms.listOfCapabilities",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.T_listOfCapabilities2", HFILL }},
    { &hf_mms_loadData1,
      { "loadData", "mms.loadData",
        FT_UINT32, BASE_DEC, VALS(mms_T_loadData1_vals), 0,
        "mms.T_loadData1", HFILL }},
    { &hf_mms_listOfCapabilities3,
      { "listOfCapabilities", "mms.listOfCapabilities",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.T_listOfCapabilities3", HFILL }},
    { &hf_mms_fileName,
      { "fileName", "mms.fileName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.FileName", HFILL }},
    { &hf_mms_listOfCapabilities4,
      { "listOfCapabilities", "mms.listOfCapabilities",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.T_listOfCapabilities4", HFILL }},
    { &hf_mms_thirdParty,
      { "thirdParty", "mms.thirdParty",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.ApplicationReference", HFILL }},
    { &hf_mms_filenName,
      { "filenName", "mms.filenName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.FileName", HFILL }},
    { &hf_mms_listOfCapabilities5,
      { "listOfCapabilities", "mms.listOfCapabilities",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.T_listOfCapabilities5", HFILL }},
    { &hf_mms_state,
      { "state", "mms.state",
        FT_INT32, BASE_DEC, VALS(mms_DomainState_vals), 0,
        "mms.DomainState", HFILL }},
    { &hf_mms_mmsDeletable,
      { "mmsDeletable", "mms.mmsDeletable",
        FT_BOOLEAN, 8, NULL, 0,
        "mms.BOOLEAN", HFILL }},
    { &hf_mms_listOfProgramInvocations,
      { "listOfProgramInvocations", "mms.listOfProgramInvocations",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.SEQUENCE_OF_Identifier", HFILL }},
    { &hf_mms_listOfProgramInvocations_item,
      { "Item", "mms.listOfProgramInvocations_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.Identifier", HFILL }},
    { &hf_mms_uploadInProgress,
      { "uploadInProgress", "mms.uploadInProgress",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Integer8", HFILL }},
    { &hf_mms_programInvocationName,
      { "programInvocationName", "mms.programInvocationName",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.Identifier", HFILL }},
    { &hf_mms_listOfDomainName,
      { "listOfDomainName", "mms.listOfDomainName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.SEQUENCE_OF_Identifier", HFILL }},
    { &hf_mms_listOfDomainName_item,
      { "Item", "mms.listOfDomainName_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.Identifier", HFILL }},
    { &hf_mms_reusable,
      { "reusable", "mms.reusable",
        FT_BOOLEAN, 8, NULL, 0,
        "mms.BOOLEAN", HFILL }},
    { &hf_mms_monitorType,
      { "monitorType", "mms.monitorType",
        FT_BOOLEAN, 8, NULL, 0,
        "mms.BOOLEAN", HFILL }},
    { &hf_mms_executionArgument,
      { "executionArgument", "mms.executionArgument",
        FT_UINT32, BASE_DEC, VALS(mms_T_executionArgument_vals), 0,
        "mms.T_executionArgument", HFILL }},
    { &hf_mms_simpleString,
      { "simpleString", "mms.simpleString",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.VisibleString", HFILL }},
    { &hf_mms_encodedString,
      { "encodedString", "mms.encodedString",
        FT_NONE, BASE_NONE, NULL, 0,
        "acse.EXTERNAL", HFILL }},
    { &hf_mms_executionArgument1,
      { "executionArgument", "mms.executionArgument",
        FT_UINT32, BASE_DEC, VALS(mms_T_executionArgument1_vals), 0,
        "mms.T_executionArgument1", HFILL }},
    { &hf_mms_state1,
      { "state", "mms.state",
        FT_INT32, BASE_DEC, VALS(mms_ProgramInvocationState_vals), 0,
        "mms.ProgramInvocationState", HFILL }},
    { &hf_mms_listOfDomainNames,
      { "listOfDomainNames", "mms.listOfDomainNames",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.SEQUENCE_OF_Identifier", HFILL }},
    { &hf_mms_listOfDomainNames_item,
      { "Item", "mms.listOfDomainNames_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.Identifier", HFILL }},
    { &hf_mms_monitor,
      { "monitor", "mms.monitor",
        FT_BOOLEAN, 8, NULL, 0,
        "mms.BOOLEAN", HFILL }},
    { &hf_mms_startArgument,
      { "startArgument", "mms.startArgument",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.VisibleString", HFILL }},
    { &hf_mms_executionArgument2,
      { "executionArgument", "mms.executionArgument",
        FT_UINT32, BASE_DEC, VALS(mms_T_executionArgument2_vals), 0,
        "mms.T_executionArgument2", HFILL }},
    { &hf_mms_typeName,
      { "typeName", "mms.typeName",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "mms.ObjectName", HFILL }},
    { &hf_mms_array,
      { "array", "mms.array",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.T_array", HFILL }},
    { &hf_mms_packed,
      { "packed", "mms.packed",
        FT_BOOLEAN, 8, NULL, 0,
        "mms.BOOLEAN", HFILL }},
    { &hf_mms_numberOfElements,
      { "numberOfElements", "mms.numberOfElements",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Unsigned32", HFILL }},
    { &hf_mms_elementType,
      { "elementType", "mms.elementType",
        FT_UINT32, BASE_DEC, VALS(mms_TypeSpecification_vals), 0,
        "mms.TypeSpecification", HFILL }},
    { &hf_mms_structure,
      { "structure", "mms.structure",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.T_structure", HFILL }},
    { &hf_mms_components,
      { "components", "mms.components",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.T_components", HFILL }},
    { &hf_mms_components_item,
      { "Item", "mms.components_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.T_components_item", HFILL }},
    { &hf_mms_componentName,
      { "componentName", "mms.componentName",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.Identifier", HFILL }},
    { &hf_mms_componentType,
      { "componentType", "mms.componentType",
        FT_UINT32, BASE_DEC, VALS(mms_TypeSpecification_vals), 0,
        "mms.TypeSpecification", HFILL }},
    { &hf_mms_boolean,
      { "boolean", "mms.boolean",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.NULL", HFILL }},
    { &hf_mms_bit_string,
      { "bit-string", "mms.bit_string",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Integer32", HFILL }},
    { &hf_mms_integer,
      { "integer", "mms.integer",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Unsigned8", HFILL }},
    { &hf_mms_unsigned,
      { "unsigned", "mms.unsigned",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Unsigned8", HFILL }},
    { &hf_mms_octet_string,
      { "octet-string", "mms.octet_string",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Integer32", HFILL }},
    { &hf_mms_visible_string,
      { "visible-string", "mms.visible_string",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Integer32", HFILL }},
    { &hf_mms_generalized_time,
      { "generalized-time", "mms.generalized_time",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.NULL", HFILL }},
    { &hf_mms_binary_time,
      { "binary-time", "mms.binary_time",
        FT_BOOLEAN, 8, NULL, 0,
        "mms.BOOLEAN", HFILL }},
    { &hf_mms_bcd,
      { "bcd", "mms.bcd",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Unsigned8", HFILL }},
    { &hf_mms_objId,
      { "objId", "mms.objId",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.NULL", HFILL }},
    { &hf_mms_AlternateAccess_item,
      { "Item", "mms.AlternateAccess_item",
        FT_UINT32, BASE_DEC, VALS(mms_AlternateAccess_item_vals), 0,
        "mms.AlternateAccess_item", HFILL }},
    { &hf_mms_unnamed,
      { "unnamed", "mms.unnamed",
        FT_UINT32, BASE_DEC, VALS(mms_AlternateAccessSelection_vals), 0,
        "mms.AlternateAccessSelection", HFILL }},
    { &hf_mms_named,
      { "named", "mms.named",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.T_named", HFILL }},
    { &hf_mms_accesst,
      { "accesst", "mms.accesst",
        FT_UINT32, BASE_DEC, VALS(mms_AlternateAccessSelection_vals), 0,
        "mms.AlternateAccessSelection", HFILL }},
    { &hf_mms_selectAccess,
      { "selectAccess", "mms.selectAccess",
        FT_UINT32, BASE_DEC, VALS(mms_T_selectAccess_vals), 0,
        "mms.T_selectAccess", HFILL }},
    { &hf_mms_component,
      { "component", "mms.component",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.Identifier", HFILL }},
    { &hf_mms_index,
      { "index", "mms.index",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Unsigned32", HFILL }},
    { &hf_mms_indexRange,
      { "indexRange", "mms.indexRange",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.T_indexRange", HFILL }},
    { &hf_mms_lowIndex,
      { "lowIndex", "mms.lowIndex",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Unsigned32", HFILL }},
    { &hf_mms_allElements,
      { "allElements", "mms.allElements",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.NULL", HFILL }},
    { &hf_mms_specificationWithResult,
      { "specificationWithResult", "mms.specificationWithResult",
        FT_BOOLEAN, 8, NULL, 0,
        "mms.BOOLEAN", HFILL }},
    { &hf_mms_variableAccessSpecificatn,
      { "variableAccessSpecificatn", "mms.variableAccessSpecificatn",
        FT_UINT32, BASE_DEC, VALS(mms_VariableAccessSpecification_vals), 0,
        "mms.VariableAccessSpecification", HFILL }},
    { &hf_mms_listOfAccessResult,
      { "listOfAccessResult", "mms.listOfAccessResult",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.SEQUENCE_OF_AccessResult", HFILL }},
    { &hf_mms_listOfAccessResult_item,
      { "Item", "mms.listOfAccessResult_item",
        FT_UINT32, BASE_DEC, VALS(mms_AccessResult_vals), 0,
        "mms.AccessResult", HFILL }},
    { &hf_mms_listOfData,
      { "listOfData", "mms.listOfData",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.SEQUENCE_OF_Data", HFILL }},
    { &hf_mms_listOfData_item,
      { "Item", "mms.listOfData_item",
        FT_UINT32, BASE_DEC, VALS(mms_Data_vals), 0,
        "mms.Data", HFILL }},
    { &hf_mms_Write_Response_item,
      { "Item", "mms.Write_Response_item",
        FT_UINT32, BASE_DEC, VALS(mms_Write_Response_item_vals), 0,
        "mms.Write_Response_item", HFILL }},
    { &hf_mms_failure,
      { "failure", "mms.failure",
        FT_INT32, BASE_DEC, VALS(mms_DataAccessError_vals), 0,
        "mms.DataAccessError", HFILL }},
    { &hf_mms_success,
      { "success", "mms.success",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.NULL", HFILL }},
    { &hf_mms_variableAccessSpecification,
      { "variableAccessSpecification", "mms.variableAccessSpecification",
        FT_UINT32, BASE_DEC, VALS(mms_VariableAccessSpecification_vals), 0,
        "mms.VariableAccessSpecification", HFILL }},
    { &hf_mms_name,
      { "name", "mms.name",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "mms.ObjectName", HFILL }},
    { &hf_mms_address,
      { "address", "mms.address",
        FT_UINT32, BASE_DEC, VALS(mms_Address_vals), 0,
        "mms.Address", HFILL }},
    { &hf_mms_typeSpecification,
      { "typeSpecification", "mms.typeSpecification",
        FT_UINT32, BASE_DEC, VALS(mms_TypeSpecification_vals), 0,
        "mms.TypeSpecification", HFILL }},
    { &hf_mms_variableName,
      { "variableName", "mms.variableName",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "mms.ObjectName", HFILL }},
    { &hf_mms_scatteredAccessName,
      { "scatteredAccessName", "mms.scatteredAccessName",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "mms.ObjectName", HFILL }},
    { &hf_mms_scatteredAccessDescription,
      { "scatteredAccessDescription", "mms.scatteredAccessDescription",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.ScatteredAccessDescription", HFILL }},
    { &hf_mms_scopeOfDelete,
      { "scopeOfDelete", "mms.scopeOfDelete",
        FT_INT32, BASE_DEC, VALS(mms_T_scopeOfDelete_vals), 0,
        "mms.T_scopeOfDelete", HFILL }},
    { &hf_mms_listOfName,
      { "listOfName", "mms.listOfName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.SEQUENCE_OF_ObjectName", HFILL }},
    { &hf_mms_listOfName_item,
      { "Item", "mms.listOfName_item",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "mms.ObjectName", HFILL }},
    { &hf_mms_numberMatched,
      { "numberMatched", "mms.numberMatched",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Unsigned32", HFILL }},
    { &hf_mms_numberDeleted,
      { "numberDeleted", "mms.numberDeleted",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Unsigned32", HFILL }},
    { &hf_mms_variableListName,
      { "variableListName", "mms.variableListName",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "mms.ObjectName", HFILL }},
    { &hf_mms_listOfVariable,
      { "listOfVariable", "mms.listOfVariable",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.T_listOfVariable", HFILL }},
    { &hf_mms_listOfVariable_item,
      { "Item", "mms.listOfVariable_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.T_listOfVariable_item", HFILL }},
    { &hf_mms_variableSpecification,
      { "variableSpecification", "mms.variableSpecification",
        FT_UINT32, BASE_DEC, VALS(mms_VariableSpecification_vals), 0,
        "mms.VariableSpecification", HFILL }},
    { &hf_mms_alternateAccess,
      { "alternateAccess", "mms.alternateAccess",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.AlternateAccess", HFILL }},
    { &hf_mms_listOfVariable1,
      { "listOfVariable", "mms.listOfVariable",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.T_listOfVariable1", HFILL }},
    { &hf_mms_listOfVariable_item1,
      { "Item", "mms.listOfVariable_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.T_listOfVariable_item1", HFILL }},
    { &hf_mms_scopeOfDelete1,
      { "scopeOfDelete", "mms.scopeOfDelete",
        FT_INT32, BASE_DEC, VALS(mms_T_scopeOfDelete1_vals), 0,
        "mms.T_scopeOfDelete1", HFILL }},
    { &hf_mms_listOfVariableListName,
      { "listOfVariableListName", "mms.listOfVariableListName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.SEQUENCE_OF_ObjectName", HFILL }},
    { &hf_mms_listOfVariableListName_item,
      { "Item", "mms.listOfVariableListName_item",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "mms.ObjectName", HFILL }},
    { &hf_mms_scopeOfDelete2,
      { "scopeOfDelete", "mms.scopeOfDelete",
        FT_INT32, BASE_DEC, VALS(mms_T_scopeOfDelete2_vals), 0,
        "mms.T_scopeOfDelete2", HFILL }},
    { &hf_mms_listOfTypeName,
      { "listOfTypeName", "mms.listOfTypeName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.SEQUENCE_OF_ObjectName", HFILL }},
    { &hf_mms_listOfTypeName_item,
      { "Item", "mms.listOfTypeName_item",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "mms.ObjectName", HFILL }},
    { &hf_mms_success1,
      { "success", "mms.success",
        FT_UINT32, BASE_DEC, VALS(mms_Data_vals), 0,
        "mms.Data", HFILL }},
    { &hf_mms_array1,
      { "array", "mms.array",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.SEQUENCE_OF_Data", HFILL }},
    { &hf_mms_array_item,
      { "Item", "mms.array_item",
        FT_UINT32, BASE_DEC, VALS(mms_Data_vals), 0,
        "mms.Data", HFILL }},
    { &hf_mms_structure1,
      { "structure", "mms.structure",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.SEQUENCE_OF_Data", HFILL }},
    { &hf_mms_structure_item,
      { "Item", "mms.structure_item",
        FT_UINT32, BASE_DEC, VALS(mms_Data_vals), 0,
        "mms.Data", HFILL }},
    { &hf_mms_boolean1,
      { "boolean", "mms.boolean",
        FT_BOOLEAN, 8, NULL, 0,
        "mms.BOOLEAN", HFILL }},
    { &hf_mms_bit_string1,
      { "bit-string", "mms.bit_string",
        FT_BYTES, BASE_HEX, NULL, 0,
        "mms.BIT_STRING", HFILL }},
    { &hf_mms_integer1,
      { "integer", "mms.integer",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.INTEGER", HFILL }},
    { &hf_mms_unsigned1,
      { "unsigned", "mms.unsigned",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.INTEGER", HFILL }},
    { &hf_mms_floating_point,
      { "floating-point", "mms.floating_point",
        FT_BYTES, BASE_HEX, NULL, 0,
        "mms.FloatingPoint", HFILL }},
    { &hf_mms_octet_string1,
      { "octet-string", "mms.octet_string",
        FT_BYTES, BASE_HEX, NULL, 0,
        "mms.OCTET_STRING", HFILL }},
    { &hf_mms_visible_string1,
      { "visible-string", "mms.visible_string",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.VisibleString", HFILL }},
    { &hf_mms_binary_time1,
      { "binary-time", "mms.binary_time",
        FT_BYTES, BASE_HEX, NULL, 0,
        "mms.TimeOfDay", HFILL }},
    { &hf_mms_bcd1,
      { "bcd", "mms.bcd",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.INTEGER", HFILL }},
    { &hf_mms_booleanArray,
      { "booleanArray", "mms.booleanArray",
        FT_BYTES, BASE_HEX, NULL, 0,
        "mms.BIT_STRING", HFILL }},
    { &hf_mms_listOfVariable2,
      { "listOfVariable", "mms.listOfVariable",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.T_listOfVariable2", HFILL }},
    { &hf_mms_listOfVariable_item2,
      { "Item", "mms.listOfVariable_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.T_listOfVariable_item2", HFILL }},
    { &hf_mms_ScatteredAccessDescription_item,
      { "Item", "mms.ScatteredAccessDescription_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.ScatteredAccessDescription_item", HFILL }},
    { &hf_mms_variableDescription,
      { "variableDescription", "mms.variableDescription",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.T_variableDescription", HFILL }},
    { &hf_mms_invalidated,
      { "invalidated", "mms.invalidated",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.NULL", HFILL }},
    { &hf_mms_numericAddress,
      { "numericAddress", "mms.numericAddress",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Unsigned32", HFILL }},
    { &hf_mms_symbolicAddress,
      { "symbolicAddress", "mms.symbolicAddress",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.VisibleString", HFILL }},
    { &hf_mms_unconstrainedAddress,
      { "unconstrainedAddress", "mms.unconstrainedAddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "mms.OCTET_STRING", HFILL }},
    { &hf_mms_semaphoreName,
      { "semaphoreName", "mms.semaphoreName",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "mms.ObjectName", HFILL }},
    { &hf_mms_namedToken,
      { "namedToken", "mms.namedToken",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.Identifier", HFILL }},
    { &hf_mms_priority,
      { "priority", "mms.priority",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Priority", HFILL }},
    { &hf_mms_acceptableDelay,
      { "acceptableDelay", "mms.acceptableDelay",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Unsigned32", HFILL }},
    { &hf_mms_controlTimeOut,
      { "controlTimeOut", "mms.controlTimeOut",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Unsigned32", HFILL }},
    { &hf_mms_abortOnTimeOut,
      { "abortOnTimeOut", "mms.abortOnTimeOut",
        FT_BOOLEAN, 8, NULL, 0,
        "mms.BOOLEAN", HFILL }},
    { &hf_mms_relinquishIfConnectionLost,
      { "relinquishIfConnectionLost", "mms.relinquishIfConnectionLost",
        FT_BOOLEAN, 8, NULL, 0,
        "mms.BOOLEAN", HFILL }},
    { &hf_mms_applicationToPreempt,
      { "applicationToPreempt", "mms.applicationToPreempt",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.ApplicationReference", HFILL }},
    { &hf_mms_noResult,
      { "noResult", "mms.noResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.NULL", HFILL }},
    { &hf_mms_numbersOfTokens,
      { "numbersOfTokens", "mms.numbersOfTokens",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Unsigned16", HFILL }},
    { &hf_mms_class,
      { "class", "mms.class",
        FT_INT32, BASE_DEC, VALS(mms_T_class_vals), 0,
        "mms.T_class", HFILL }},
    { &hf_mms_numberOfTokens,
      { "numberOfTokens", "mms.numberOfTokens",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Unsigned16", HFILL }},
    { &hf_mms_numberOfOwnedTokens,
      { "numberOfOwnedTokens", "mms.numberOfOwnedTokens",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Unsigned16", HFILL }},
    { &hf_mms_numberOfHungTokens,
      { "numberOfHungTokens", "mms.numberOfHungTokens",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Unsigned16", HFILL }},
    { &hf_mms_nameToStartAfter,
      { "nameToStartAfter", "mms.nameToStartAfter",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.Identifier", HFILL }},
    { &hf_mms_listOfNamedTokens,
      { "listOfNamedTokens", "mms.listOfNamedTokens",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.T_listOfNamedTokens", HFILL }},
    { &hf_mms_listOfNamedTokens_item,
      { "Item", "mms.listOfNamedTokens_item",
        FT_UINT32, BASE_DEC, VALS(mms_T_listOfNamedTokens_item_vals), 0,
        "mms.T_listOfNamedTokens_item", HFILL }},
    { &hf_mms_freeNamedToken,
      { "freeNamedToken", "mms.freeNamedToken",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.Identifier", HFILL }},
    { &hf_mms_ownedNamedToken,
      { "ownedNamedToken", "mms.ownedNamedToken",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.Identifier", HFILL }},
    { &hf_mms_hungNamedToken,
      { "hungNamedToken", "mms.hungNamedToken",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.Identifier", HFILL }},
    { &hf_mms_state2,
      { "state", "mms.state",
        FT_INT32, BASE_DEC, VALS(mms_T_state_vals), 0,
        "mms.T_state", HFILL }},
    { &hf_mms_entryIdToStartAfter,
      { "entryIdToStartAfter", "mms.entryIdToStartAfter",
        FT_BYTES, BASE_HEX, NULL, 0,
        "mms.OCTET_STRING", HFILL }},
    { &hf_mms_listOfSemaphoreEntry,
      { "listOfSemaphoreEntry", "mms.listOfSemaphoreEntry",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.SEQUENCE_OF_SemaphoreEntry", HFILL }},
    { &hf_mms_listOfSemaphoreEntry_item,
      { "Item", "mms.listOfSemaphoreEntry_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.SemaphoreEntry", HFILL }},
    { &hf_mms_entryId,
      { "entryId", "mms.entryId",
        FT_BYTES, BASE_HEX, NULL, 0,
        "mms.OCTET_STRING", HFILL }},
    { &hf_mms_entryClass,
      { "entryClass", "mms.entryClass",
        FT_INT32, BASE_DEC, VALS(mms_T_entryClass_vals), 0,
        "mms.T_entryClass", HFILL }},
    { &hf_mms_applicationReference,
      { "applicationReference", "mms.applicationReference",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.ApplicationReference", HFILL }},
    { &hf_mms_remainingTimeOut,
      { "remainingTimeOut", "mms.remainingTimeOut",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Unsigned32", HFILL }},
    { &hf_mms_operatorStationName,
      { "operatorStationName", "mms.operatorStationName",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.Identifier", HFILL }},
    { &hf_mms_echo,
      { "echo", "mms.echo",
        FT_BOOLEAN, 8, NULL, 0,
        "mms.BOOLEAN", HFILL }},
    { &hf_mms_listOfPromptData,
      { "listOfPromptData", "mms.listOfPromptData",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.T_listOfPromptData", HFILL }},
    { &hf_mms_listOfPromptData_item,
      { "Item", "mms.listOfPromptData_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.VisibleString", HFILL }},
    { &hf_mms_inputTimeOut,
      { "inputTimeOut", "mms.inputTimeOut",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Unsigned32", HFILL }},
    { &hf_mms_listOfOutputData,
      { "listOfOutputData", "mms.listOfOutputData",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.T_listOfOutputData", HFILL }},
    { &hf_mms_listOfOutputData_item,
      { "Item", "mms.listOfOutputData_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.VisibleString", HFILL }},
    { &hf_mms_eventConditionName,
      { "eventConditionName", "mms.eventConditionName",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "mms.ObjectName", HFILL }},
    { &hf_mms_class1,
      { "class", "mms.class",
        FT_INT32, BASE_DEC, VALS(mms_EC_Class_vals), 0,
        "mms.EC_Class", HFILL }},
    { &hf_mms_prio_rity,
      { "prio-rity", "mms.prio_rity",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Priority", HFILL }},
    { &hf_mms_severity,
      { "severity", "mms.severity",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Unsigned8", HFILL }},
    { &hf_mms_alarmSummaryReports,
      { "alarmSummaryReports", "mms.alarmSummaryReports",
        FT_BOOLEAN, 8, NULL, 0,
        "mms.BOOLEAN", HFILL }},
    { &hf_mms_monitoredVariable,
      { "monitoredVariable", "mms.monitoredVariable",
        FT_UINT32, BASE_DEC, VALS(mms_VariableSpecification_vals), 0,
        "mms.VariableSpecification", HFILL }},
    { &hf_mms_evaluationInterval,
      { "evaluationInterval", "mms.evaluationInterval",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Unsigned32", HFILL }},
    { &hf_mms_specific,
      { "specific", "mms.specific",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.SEQUENCE_OF_ObjectName", HFILL }},
    { &hf_mms_specific_item,
      { "Item", "mms.specific_item",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "mms.ObjectName", HFILL }},
    { &hf_mms_aa_specific1,
      { "aa-specific", "mms.aa_specific",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.NULL", HFILL }},
    { &hf_mms_domain,
      { "domain", "mms.domain",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.Identifier", HFILL }},
    { &hf_mms_vmd,
      { "vmd", "mms.vmd",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.NULL", HFILL }},
    { &hf_mms_monitoredVariable1,
      { "monitoredVariable", "mms.monitoredVariable",
        FT_UINT32, BASE_DEC, VALS(mms_T_monitoredVariable_vals), 0,
        "mms.T_monitoredVariable", HFILL }},
    { &hf_mms_variableReference,
      { "variableReference", "mms.variableReference",
        FT_UINT32, BASE_DEC, VALS(mms_VariableSpecification_vals), 0,
        "mms.VariableSpecification", HFILL }},
    { &hf_mms_undefined,
      { "undefined", "mms.undefined",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.NULL", HFILL }},
    { &hf_mms_currentState,
      { "currentState", "mms.currentState",
        FT_INT32, BASE_DEC, VALS(mms_EC_State_vals), 0,
        "mms.EC_State", HFILL }},
    { &hf_mms_numberOfEventEnrollments,
      { "numberOfEventEnrollments", "mms.numberOfEventEnrollments",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Unsigned32", HFILL }},
    { &hf_mms_enabled,
      { "enabled", "mms.enabled",
        FT_BOOLEAN, 8, NULL, 0,
        "mms.BOOLEAN", HFILL }},
    { &hf_mms_timeOfLastTransitionToActive,
      { "timeOfLastTransitionToActive", "mms.timeOfLastTransitionToActive",
        FT_UINT32, BASE_DEC, VALS(mms_EventTime_vals), 0,
        "mms.EventTime", HFILL }},
    { &hf_mms_timeOfLastTransitionToIdle,
      { "timeOfLastTransitionToIdle", "mms.timeOfLastTransitionToIdle",
        FT_UINT32, BASE_DEC, VALS(mms_EventTime_vals), 0,
        "mms.EventTime", HFILL }},
    { &hf_mms_eventActionName,
      { "eventActionName", "mms.eventActionName",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "mms.ObjectName", HFILL }},
    { &hf_mms_eventEnrollmentName,
      { "eventEnrollmentName", "mms.eventEnrollmentName",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "mms.ObjectName", HFILL }},
    { &hf_mms_eventConditionTransition,
      { "eventConditionTransition", "mms.eventConditionTransition",
        FT_BYTES, BASE_HEX, NULL, 0,
        "mms.Transitions", HFILL }},
    { &hf_mms_alarmAcknowledgementRule,
      { "alarmAcknowledgementRule", "mms.alarmAcknowledgementRule",
        FT_INT32, BASE_DEC, VALS(mms_AlarmAckRule_vals), 0,
        "mms.AlarmAckRule", HFILL }},
    { &hf_mms_clientApplication,
      { "clientApplication", "mms.clientApplication",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.ApplicationReference", HFILL }},
    { &hf_mms_ec,
      { "ec", "mms.ec",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "mms.ObjectName", HFILL }},
    { &hf_mms_ea,
      { "ea", "mms.ea",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "mms.ObjectName", HFILL }},
    { &hf_mms_scopeOfRequest,
      { "scopeOfRequest", "mms.scopeOfRequest",
        FT_INT32, BASE_DEC, VALS(mms_T_scopeOfRequest_vals), 0,
        "mms.T_scopeOfRequest", HFILL }},
    { &hf_mms_eventEnrollmentNames,
      { "eventEnrollmentNames", "mms.eventEnrollmentNames",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.SEQUENCE_OF_ObjectName", HFILL }},
    { &hf_mms_eventEnrollmentNames_item,
      { "Item", "mms.eventEnrollmentNames_item",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "mms.ObjectName", HFILL }},
    { &hf_mms_continueAfter2,
      { "continueAfter", "mms.continueAfter",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "mms.ObjectName", HFILL }},
    { &hf_mms_eventConditionName1,
      { "eventConditionName", "mms.eventConditionName",
        FT_UINT32, BASE_DEC, VALS(mms_T_eventConditionName_vals), 0,
        "mms.T_eventConditionName", HFILL }},
    { &hf_mms_eventCondition,
      { "eventCondition", "mms.eventCondition",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "mms.ObjectName", HFILL }},
    { &hf_mms_eventActionName1,
      { "eventActionName", "mms.eventActionName",
        FT_UINT32, BASE_DEC, VALS(mms_T_eventActionName_vals), 0,
        "mms.T_eventActionName", HFILL }},
    { &hf_mms_eventAction,
      { "eventAction", "mms.eventAction",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "mms.ObjectName", HFILL }},
    { &hf_mms_enrollmentClass,
      { "enrollmentClass", "mms.enrollmentClass",
        FT_INT32, BASE_DEC, VALS(mms_EE_Class_vals), 0,
        "mms.EE_Class", HFILL }},
    { &hf_mms_duration,
      { "duration", "mms.duration",
        FT_INT32, BASE_DEC, VALS(mms_EE_Duration_vals), 0,
        "mms.EE_Duration", HFILL }},
    { &hf_mms_remainingAcceptableDelay,
      { "remainingAcceptableDelay", "mms.remainingAcceptableDelay",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Unsigned32", HFILL }},
    { &hf_mms_listOfEventEnrollment,
      { "listOfEventEnrollment", "mms.listOfEventEnrollment",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.SEQUENCE_OF_EventEnrollment", HFILL }},
    { &hf_mms_listOfEventEnrollment_item,
      { "Item", "mms.listOfEventEnrollment_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.EventEnrollment", HFILL }},
    { &hf_mms_eventConditionTransitions,
      { "eventConditionTransitions", "mms.eventConditionTransitions",
        FT_BYTES, BASE_HEX, NULL, 0,
        "mms.Transitions", HFILL }},
    { &hf_mms_notificationLost,
      { "notificationLost", "mms.notificationLost",
        FT_BOOLEAN, 8, NULL, 0,
        "mms.BOOLEAN", HFILL }},
    { &hf_mms_alarmAcknowledgmentRule,
      { "alarmAcknowledgmentRule", "mms.alarmAcknowledgmentRule",
        FT_INT32, BASE_DEC, VALS(mms_AlarmAckRule_vals), 0,
        "mms.AlarmAckRule", HFILL }},
    { &hf_mms_currentState1,
      { "currentState", "mms.currentState",
        FT_INT32, BASE_DEC, VALS(mms_EE_State_vals), 0,
        "mms.EE_State", HFILL }},
    { &hf_mms_currentState2,
      { "currentState", "mms.currentState",
        FT_UINT32, BASE_DEC, VALS(mms_T_currentState_vals), 0,
        "mms.T_currentState", HFILL }},
    { &hf_mms_state3,
      { "state", "mms.state",
        FT_INT32, BASE_DEC, VALS(mms_EE_State_vals), 0,
        "mms.EE_State", HFILL }},
    { &hf_mms_transitionTime,
      { "transitionTime", "mms.transitionTime",
        FT_UINT32, BASE_DEC, VALS(mms_EventTime_vals), 0,
        "mms.EventTime", HFILL }},
    { &hf_mms_acknowledgedState,
      { "acknowledgedState", "mms.acknowledgedState",
        FT_INT32, BASE_DEC, VALS(mms_EC_State_vals), 0,
        "mms.EC_State", HFILL }},
    { &hf_mms_timeOfAcknowledgedTransition,
      { "timeOfAcknowledgedTransition", "mms.timeOfAcknowledgedTransition",
        FT_UINT32, BASE_DEC, VALS(mms_EventTime_vals), 0,
        "mms.EventTime", HFILL }},
    { &hf_mms_enrollmentsOnly,
      { "enrollmentsOnly", "mms.enrollmentsOnly",
        FT_BOOLEAN, 8, NULL, 0,
        "mms.BOOLEAN", HFILL }},
    { &hf_mms_activeAlarmsOnly,
      { "activeAlarmsOnly", "mms.activeAlarmsOnly",
        FT_BOOLEAN, 8, NULL, 0,
        "mms.BOOLEAN", HFILL }},
    { &hf_mms_acknowledgmentFilter,
      { "acknowledgmentFilter", "mms.acknowledgmentFilter",
        FT_INT32, BASE_DEC, VALS(mms_T_acknowledgmentFilter_vals), 0,
        "mms.T_acknowledgmentFilter", HFILL }},
    { &hf_mms_severityFilter,
      { "severityFilter", "mms.severityFilter",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.T_severityFilter", HFILL }},
    { &hf_mms_mostSevere,
      { "mostSevere", "mms.mostSevere",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Unsigned8", HFILL }},
    { &hf_mms_leastSevere,
      { "leastSevere", "mms.leastSevere",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Unsigned8", HFILL }},
    { &hf_mms_listOfAlarmSummary,
      { "listOfAlarmSummary", "mms.listOfAlarmSummary",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.SEQUENCE_OF_AlarmSummary", HFILL }},
    { &hf_mms_listOfAlarmSummary_item,
      { "Item", "mms.listOfAlarmSummary_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.AlarmSummary", HFILL }},
    { &hf_mms_unacknowledgedState,
      { "unacknowledgedState", "mms.unacknowledgedState",
        FT_INT32, BASE_DEC, VALS(mms_T_unacknowledgedState_vals), 0,
        "mms.T_unacknowledgedState", HFILL }},
    { &hf_mms_acknowledgmentFilter1,
      { "acknowledgmentFilter", "mms.acknowledgmentFilter",
        FT_INT32, BASE_DEC, VALS(mms_T_acknowledgmentFilter1_vals), 0,
        "mms.T_acknowledgmentFilter1", HFILL }},
    { &hf_mms_severityFilter1,
      { "severityFilter", "mms.severityFilter",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.T_severityFilter1", HFILL }},
    { &hf_mms_listOfAlarmEnrollmentSummary,
      { "listOfAlarmEnrollmentSummary", "mms.listOfAlarmEnrollmentSummary",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.SEQUENCE_OF_AlarmEnrollmentSummary", HFILL }},
    { &hf_mms_listOfAlarmEnrollmentSummary_item,
      { "Item", "mms.listOfAlarmEnrollmentSummary_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.AlarmEnrollmentSummary", HFILL }},
    { &hf_mms_enrollementState,
      { "enrollementState", "mms.enrollementState",
        FT_INT32, BASE_DEC, VALS(mms_EE_State_vals), 0,
        "mms.EE_State", HFILL }},
    { &hf_mms_timeActiveAcknowledged,
      { "timeActiveAcknowledged", "mms.timeActiveAcknowledged",
        FT_UINT32, BASE_DEC, VALS(mms_EventTime_vals), 0,
        "mms.EventTime", HFILL }},
    { &hf_mms_timeIdleAcknowledged,
      { "timeIdleAcknowledged", "mms.timeIdleAcknowledged",
        FT_UINT32, BASE_DEC, VALS(mms_EventTime_vals), 0,
        "mms.EventTime", HFILL }},
    { &hf_mms_eventConditionName2,
      { "eventConditionName", "mms.eventConditionName",
        FT_UINT32, BASE_DEC, VALS(mms_T_eventConditionName1_vals), 0,
        "mms.T_eventConditionName1", HFILL }},
    { &hf_mms_actionResult,
      { "actionResult", "mms.actionResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.T_actionResult", HFILL }},
    { &hf_mms_eventActioName,
      { "eventActioName", "mms.eventActioName",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "mms.ObjectName", HFILL }},
    { &hf_mms_eventActionResult,
      { "eventActionResult", "mms.eventActionResult",
        FT_UINT32, BASE_DEC, VALS(mms_T_eventActionResult_vals), 0,
        "mms.T_eventActionResult", HFILL }},
    { &hf_mms_success2,
      { "success", "mms.success",
        FT_UINT32, BASE_DEC, VALS(mms_ConfirmedServiceResponse_vals), 0,
        "mms.ConfirmedServiceResponse", HFILL }},
    { &hf_mms_failure1,
      { "failure", "mms.failure",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.ServiceError", HFILL }},
    { &hf_mms_causingTransitions,
      { "causingTransitions", "mms.causingTransitions",
        FT_BYTES, BASE_HEX, NULL, 0,
        "mms.Transitions", HFILL }},
    { &hf_mms_timeOfDayT,
      { "timeOfDayT", "mms.timeOfDayT",
        FT_BYTES, BASE_HEX, NULL, 0,
        "mms.TimeOfDay", HFILL }},
    { &hf_mms_timeSequenceIdentifier,
      { "timeSequenceIdentifier", "mms.timeSequenceIdentifier",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Unsigned32", HFILL }},
    { &hf_mms_journalName,
      { "journalName", "mms.journalName",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "mms.ObjectName", HFILL }},
    { &hf_mms_rangeStartSpecification,
      { "rangeStartSpecification", "mms.rangeStartSpecification",
        FT_UINT32, BASE_DEC, VALS(mms_T_rangeStartSpecification_vals), 0,
        "mms.T_rangeStartSpecification", HFILL }},
    { &hf_mms_startingTime,
      { "startingTime", "mms.startingTime",
        FT_BYTES, BASE_HEX, NULL, 0,
        "mms.TimeOfDay", HFILL }},
    { &hf_mms_startingEntry,
      { "startingEntry", "mms.startingEntry",
        FT_BYTES, BASE_HEX, NULL, 0,
        "mms.OCTET_STRING", HFILL }},
    { &hf_mms_rangeStopSpecification,
      { "rangeStopSpecification", "mms.rangeStopSpecification",
        FT_UINT32, BASE_DEC, VALS(mms_T_rangeStopSpecification_vals), 0,
        "mms.T_rangeStopSpecification", HFILL }},
    { &hf_mms_endingTime,
      { "endingTime", "mms.endingTime",
        FT_BYTES, BASE_HEX, NULL, 0,
        "mms.TimeOfDay", HFILL }},
    { &hf_mms_numberOfEntries,
      { "numberOfEntries", "mms.numberOfEntries",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Integer32", HFILL }},
    { &hf_mms_listOfVariables,
      { "listOfVariables", "mms.listOfVariables",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.T_listOfVariables", HFILL }},
    { &hf_mms_listOfVariables_item,
      { "Item", "mms.listOfVariables_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.VisibleString", HFILL }},
    { &hf_mms_entryToStartAfter,
      { "entryToStartAfter", "mms.entryToStartAfter",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.T_entryToStartAfter", HFILL }},
    { &hf_mms_timeSpecification,
      { "timeSpecification", "mms.timeSpecification",
        FT_BYTES, BASE_HEX, NULL, 0,
        "mms.TimeOfDay", HFILL }},
    { &hf_mms_entrySpecification,
      { "entrySpecification", "mms.entrySpecification",
        FT_BYTES, BASE_HEX, NULL, 0,
        "mms.OCTET_STRING", HFILL }},
    { &hf_mms_listOfJournalEntry,
      { "listOfJournalEntry", "mms.listOfJournalEntry",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.SEQUENCE_OF_JournalEntry", HFILL }},
    { &hf_mms_listOfJournalEntry_item,
      { "Item", "mms.listOfJournalEntry_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.JournalEntry", HFILL }},
    { &hf_mms_entryIdentifier,
      { "entryIdentifier", "mms.entryIdentifier",
        FT_BYTES, BASE_HEX, NULL, 0,
        "mms.OCTET_STRING", HFILL }},
    { &hf_mms_originatingApplication,
      { "originatingApplication", "mms.originatingApplication",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.ApplicationReference", HFILL }},
    { &hf_mms_entryContent,
      { "entryContent", "mms.entryContent",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.EntryContent", HFILL }},
    { &hf_mms_listOfJournalEntry1,
      { "listOfJournalEntry", "mms.listOfJournalEntry",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.SEQUENCE_OF_EntryContent", HFILL }},
    { &hf_mms_listOfJournalEntry_item1,
      { "Item", "mms.listOfJournalEntry_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.EntryContent", HFILL }},
    { &hf_mms_limitSpecification,
      { "limitSpecification", "mms.limitSpecification",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.T_limitSpecification", HFILL }},
    { &hf_mms_limitingTime,
      { "limitingTime", "mms.limitingTime",
        FT_BYTES, BASE_HEX, NULL, 0,
        "mms.TimeOfDay", HFILL }},
    { &hf_mms_limitingEntry,
      { "limitingEntry", "mms.limitingEntry",
        FT_BYTES, BASE_HEX, NULL, 0,
        "mms.OCTET_STRING", HFILL }},
    { &hf_mms_currentEntries,
      { "currentEntries", "mms.currentEntries",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Unsigned32", HFILL }},
    { &hf_mms_occurenceTime,
      { "occurenceTime", "mms.occurenceTime",
        FT_BYTES, BASE_HEX, NULL, 0,
        "mms.TimeOfDay", HFILL }},
    { &hf_mms_additionalDetail,
      { "additionalDetail", "mms.additionalDetail",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.JOU_Additional_Detail", HFILL }},
    { &hf_mms_entryForm,
      { "entryForm", "mms.entryForm",
        FT_UINT32, BASE_DEC, VALS(mms_T_entryForm_vals), 0,
        "mms.T_entryForm", HFILL }},
    { &hf_mms_data,
      { "data", "mms.data",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.T_data", HFILL }},
    { &hf_mms_event,
      { "event", "mms.event",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.T_event", HFILL }},
    { &hf_mms_listOfVariables1,
      { "listOfVariables", "mms.listOfVariables",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.T_listOfVariables1", HFILL }},
    { &hf_mms_listOfVariables_item1,
      { "Item", "mms.listOfVariables_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.T_listOfVariables_item", HFILL }},
    { &hf_mms_variableTag,
      { "variableTag", "mms.variableTag",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.VisibleString", HFILL }},
    { &hf_mms_valueSpecification,
      { "valueSpecification", "mms.valueSpecification",
        FT_UINT32, BASE_DEC, VALS(mms_Data_vals), 0,
        "mms.Data", HFILL }},
    { &hf_mms_annotation,
      { "annotation", "mms.annotation",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.VisibleString", HFILL }},
    { &hf_mms_sourceFileServer,
      { "sourceFileServer", "mms.sourceFileServer",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.ApplicationReference", HFILL }},
    { &hf_mms_sourceFile,
      { "sourceFile", "mms.sourceFile",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.FileName", HFILL }},
    { &hf_mms_destinationFile,
      { "destinationFile", "mms.destinationFile",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.FileName", HFILL }},
    { &hf_mms_initialPosition,
      { "initialPosition", "mms.initialPosition",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Unsigned32", HFILL }},
    { &hf_mms_frsmID,
      { "frsmID", "mms.frsmID",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Integer32", HFILL }},
    { &hf_mms_fileAttributes,
      { "fileAttributes", "mms.fileAttributes",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.FileAttributes", HFILL }},
    { &hf_mms_fileData,
      { "fileData", "mms.fileData",
        FT_BYTES, BASE_HEX, NULL, 0,
        "mms.OCTET_STRING", HFILL }},
    { &hf_mms_currentFileName,
      { "currentFileName", "mms.currentFileName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.FileName", HFILL }},
    { &hf_mms_newFileName,
      { "newFileName", "mms.newFileName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.FileName", HFILL }},
    { &hf_mms_fileSpecification,
      { "fileSpecification", "mms.fileSpecification",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.FileName", HFILL }},
    { &hf_mms_continueAfter3,
      { "continueAfter", "mms.continueAfter",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.FileName", HFILL }},
    { &hf_mms_listOfDirectoryEntry,
      { "listOfDirectoryEntry", "mms.listOfDirectoryEntry",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.SEQUENCE_OF_DirectoryEntry", HFILL }},
    { &hf_mms_listOfDirectoryEntry_item,
      { "Item", "mms.listOfDirectoryEntry_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "mms.DirectoryEntry", HFILL }},
    { &hf_mms_filename,
      { "filename", "mms.filename",
        FT_UINT32, BASE_DEC, NULL, 0,
        "mms.FileName", HFILL }},
    { &hf_mms_sizeOfFile,
      { "sizeOfFile", "mms.sizeOfFile",
        FT_INT32, BASE_DEC, NULL, 0,
        "mms.Unsigned32", HFILL }},
    { &hf_mms_lastModified,
      { "lastModified", "mms.lastModified",
        FT_STRING, BASE_NONE, NULL, 0,
        "mms.GeneralizedTime", HFILL }},
    { &hf_mms_ParameterSupportOptions_str1,
      { "str1", "mms.str1",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_mms_ParameterSupportOptions_str2,
      { "str2", "mms.str2",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_mms_ParameterSupportOptions_vnam,
      { "vnam", "mms.vnam",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_mms_ParameterSupportOptions_valt,
      { "valt", "mms.valt",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_mms_ParameterSupportOptions_vadr,
      { "vadr", "mms.vadr",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_mms_ParameterSupportOptions_vsca,
      { "vsca", "mms.vsca",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_mms_ParameterSupportOptions_tpy,
      { "tpy", "mms.tpy",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_mms_ParameterSupportOptions_vlis,
      { "vlis", "mms.vlis",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_mms_ParameterSupportOptions_real,
      { "real", "mms.real",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_mms_ParameterSupportOptions_cei,
      { "cei", "mms.cei",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_status,
      { "status", "mms.status",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_getNameList,
      { "getNameList", "mms.getNameList",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_identify,
      { "identify", "mms.identify",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_rename,
      { "rename", "mms.rename",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_read,
      { "read", "mms.read",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_write,
      { "write", "mms.write",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_getVariableAccessAttributes,
      { "getVariableAccessAttributes", "mms.getVariableAccessAttributes",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_defineNamedVariable,
      { "defineNamedVariable", "mms.defineNamedVariable",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_defineScatteredAccess,
      { "defineScatteredAccess", "mms.defineScatteredAccess",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_getScatteredAccessAttributes,
      { "getScatteredAccessAttributes", "mms.getScatteredAccessAttributes",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_deleteVariableAccess,
      { "deleteVariableAccess", "mms.deleteVariableAccess",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_defineNamedVariableList,
      { "defineNamedVariableList", "mms.defineNamedVariableList",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_getNamedVariableListAttributes,
      { "getNamedVariableListAttributes", "mms.getNamedVariableListAttributes",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_deleteNamedVariableList,
      { "deleteNamedVariableList", "mms.deleteNamedVariableList",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_defineNamedType,
      { "defineNamedType", "mms.defineNamedType",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_getNamedTypeAttributes,
      { "getNamedTypeAttributes", "mms.getNamedTypeAttributes",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_deleteNamedType,
      { "deleteNamedType", "mms.deleteNamedType",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_input,
      { "input", "mms.input",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_output,
      { "output", "mms.output",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_takeControl,
      { "takeControl", "mms.takeControl",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_relinquishControl,
      { "relinquishControl", "mms.relinquishControl",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_defineSemaphore,
      { "defineSemaphore", "mms.defineSemaphore",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_deleteSemaphore,
      { "deleteSemaphore", "mms.deleteSemaphore",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_reportSemaphoreStatus,
      { "reportSemaphoreStatus", "mms.reportSemaphoreStatus",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_reportPoolSemaphoreStatus,
      { "reportPoolSemaphoreStatus", "mms.reportPoolSemaphoreStatus",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_reportSemaphoreEntryStatus,
      { "reportSemaphoreEntryStatus", "mms.reportSemaphoreEntryStatus",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_initiateDownloadSequence,
      { "initiateDownloadSequence", "mms.initiateDownloadSequence",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_downloadSegment,
      { "downloadSegment", "mms.downloadSegment",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_terminateDownloadSequence,
      { "terminateDownloadSequence", "mms.terminateDownloadSequence",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_initiateUploadSequence,
      { "initiateUploadSequence", "mms.initiateUploadSequence",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_uploadSegment,
      { "uploadSegment", "mms.uploadSegment",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_terminateUploadSequence,
      { "terminateUploadSequence", "mms.terminateUploadSequence",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_requestDomainDownload,
      { "requestDomainDownload", "mms.requestDomainDownload",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_requestDomainUpload,
      { "requestDomainUpload", "mms.requestDomainUpload",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_loadDomainContent,
      { "loadDomainContent", "mms.loadDomainContent",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_storeDomainContent,
      { "storeDomainContent", "mms.storeDomainContent",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_deleteDomain,
      { "deleteDomain", "mms.deleteDomain",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_getDomainAttributes,
      { "getDomainAttributes", "mms.getDomainAttributes",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_createProgramInvocation,
      { "createProgramInvocation", "mms.createProgramInvocation",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_deleteProgramInvocation,
      { "deleteProgramInvocation", "mms.deleteProgramInvocation",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_start,
      { "start", "mms.start",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_stop,
      { "stop", "mms.stop",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_resume,
      { "resume", "mms.resume",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_reset,
      { "reset", "mms.reset",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_kill,
      { "kill", "mms.kill",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_getProgramInvocationAttributes,
      { "getProgramInvocationAttributes", "mms.getProgramInvocationAttributes",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_obtainFile,
      { "obtainFile", "mms.obtainFile",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_defineEventCondition,
      { "defineEventCondition", "mms.defineEventCondition",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_deleteEventCondition,
      { "deleteEventCondition", "mms.deleteEventCondition",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_getEventConditionAttributes,
      { "getEventConditionAttributes", "mms.getEventConditionAttributes",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_reportEventConditionStatus,
      { "reportEventConditionStatus", "mms.reportEventConditionStatus",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_alterEventConditionMonitoring,
      { "alterEventConditionMonitoring", "mms.alterEventConditionMonitoring",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_triggerEvent,
      { "triggerEvent", "mms.triggerEvent",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_defineEventAction,
      { "defineEventAction", "mms.defineEventAction",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_deleteEventAction,
      { "deleteEventAction", "mms.deleteEventAction",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_getEventActionAttributes,
      { "getEventActionAttributes", "mms.getEventActionAttributes",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_reportActionStatus,
      { "reportActionStatus", "mms.reportActionStatus",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_defineEventEnrollment,
      { "defineEventEnrollment", "mms.defineEventEnrollment",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_deleteEventEnrollment,
      { "deleteEventEnrollment", "mms.deleteEventEnrollment",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_alterEventEnrollment,
      { "alterEventEnrollment", "mms.alterEventEnrollment",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_reportEventEnrollmentStatus,
      { "reportEventEnrollmentStatus", "mms.reportEventEnrollmentStatus",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_getEventEnrollmentAttributes,
      { "getEventEnrollmentAttributes", "mms.getEventEnrollmentAttributes",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_acknowledgeEventNotification,
      { "acknowledgeEventNotification", "mms.acknowledgeEventNotification",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_getAlarmSummary,
      { "getAlarmSummary", "mms.getAlarmSummary",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_getAlarmEnrollmentSummary,
      { "getAlarmEnrollmentSummary", "mms.getAlarmEnrollmentSummary",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_readJournal,
      { "readJournal", "mms.readJournal",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_writeJournal,
      { "writeJournal", "mms.writeJournal",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_initializeJournal,
      { "initializeJournal", "mms.initializeJournal",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_reportJournalStatus,
      { "reportJournalStatus", "mms.reportJournalStatus",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_createJournal,
      { "createJournal", "mms.createJournal",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_deleteJournal,
      { "deleteJournal", "mms.deleteJournal",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_getCapabilityList,
      { "getCapabilityList", "mms.getCapabilityList",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_fileOpen,
      { "fileOpen", "mms.fileOpen",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_fileRead,
      { "fileRead", "mms.fileRead",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_fileClose,
      { "fileClose", "mms.fileClose",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_fileRename,
      { "fileRename", "mms.fileRename",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_fileDelete,
      { "fileDelete", "mms.fileDelete",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_fileDirectory,
      { "fileDirectory", "mms.fileDirectory",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_unsolicitedStatus,
      { "unsolicitedStatus", "mms.unsolicitedStatus",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_informationReport,
      { "informationReport", "mms.informationReport",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_eventNotification,
      { "eventNotification", "mms.eventNotification",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_attachToEventCondition,
      { "attachToEventCondition", "mms.attachToEventCondition",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_attachToSemaphore,
      { "attachToSemaphore", "mms.attachToSemaphore",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_conclude,
      { "conclude", "mms.conclude",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_mms_ServiceSupportOptions_cancel,
      { "cancel", "mms.cancel",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_mms_Transitions_idle_to_disabled,
      { "idle-to-disabled", "mms.idle-to-disabled",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_mms_Transitions_active_to_disabled,
      { "active-to-disabled", "mms.active-to-disabled",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_mms_Transitions_disabled_to_idle,
      { "disabled-to-idle", "mms.disabled-to-idle",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_mms_Transitions_active_to_idle,
      { "active-to-idle", "mms.active-to-idle",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_mms_Transitions_disabled_to_active,
      { "disabled-to-active", "mms.disabled-to-active",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_mms_Transitions_idle_to_active,
      { "idle-to-active", "mms.idle-to-active",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_mms_Transitions_any_to_deleted,
      { "any-to-deleted", "mms.any-to-deleted",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},

/*--- End of included file: packet-mms-hfarr.c ---*/
#line 95 "packet-mms-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_mms,

/*--- Included file: packet-mms-ettarr.c ---*/
#line 1 "packet-mms-ettarr.c"
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
    &ett_mms_T_extendedObjectClass1,
    &ett_mms_GetCapabilityList_Request,
    &ett_mms_GetCapabilityList_Response,
    &ett_mms_T_listOfCapabilities,
    &ett_mms_InitiateDownloadSequence_Request,
    &ett_mms_T_listOfCapabilities1,
    &ett_mms_DownloadSegment_Response,
    &ett_mms_T_loadData,
    &ett_mms_TerminateDownloadSequence_Request,
    &ett_mms_InitiateUploadSequence_Response,
    &ett_mms_T_listOfCapabilities2,
    &ett_mms_UploadSegment_Response,
    &ett_mms_T_loadData1,
    &ett_mms_RequestDomainDownload_Request,
    &ett_mms_T_listOfCapabilities3,
    &ett_mms_RequestDomainUpload_Request,
    &ett_mms_LoadDomainContent_Request,
    &ett_mms_T_listOfCapabilities4,
    &ett_mms_StoreDomainContent_Request,
    &ett_mms_GetDomainAttributes_Response,
    &ett_mms_T_listOfCapabilities5,
    &ett_mms_CreateProgramInvocation_Request,
    &ett_mms_Start_Request,
    &ett_mms_T_executionArgument,
    &ett_mms_Stop_Request,
    &ett_mms_Resume_Request,
    &ett_mms_T_executionArgument1,
    &ett_mms_Reset_Request,
    &ett_mms_Kill_Request,
    &ett_mms_GetProgramInvocationAttributes_Response,
    &ett_mms_T_executionArgument2,
    &ett_mms_TypeSpecification,
    &ett_mms_T_array,
    &ett_mms_T_structure,
    &ett_mms_T_components,
    &ett_mms_T_components_item,
    &ett_mms_AlternateAccess,
    &ett_mms_AlternateAccess_item,
    &ett_mms_T_named,
    &ett_mms_AlternateAccessSelection,
    &ett_mms_T_selectAccess,
    &ett_mms_T_indexRange,
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
    &ett_mms_T_listOfVariable1,
    &ett_mms_T_listOfVariable_item1,
    &ett_mms_DeleteNamedVariableList_Request,
    &ett_mms_DeleteNamedVariableList_Response,
    &ett_mms_DefineNamedType_Request,
    &ett_mms_GetNamedTypeAttributes_Response,
    &ett_mms_DeleteNamedType_Request,
    &ett_mms_DeleteNamedType_Response,
    &ett_mms_AccessResult,
    &ett_mms_Data,
    &ett_mms_VariableAccessSpecification,
    &ett_mms_T_listOfVariable2,
    &ett_mms_T_listOfVariable_item2,
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
    &ett_mms_T_severityFilter1,
    &ett_mms_GetAlarmEnrollmentSummary_Response,
    &ett_mms_SEQUENCE_OF_AlarmEnrollmentSummary,
    &ett_mms_AlarmEnrollmentSummary,
    &ett_mms_EventNotification,
    &ett_mms_T_eventConditionName1,
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
    &ett_mms_T_listOfVariables1,
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
#line 101 "packet-mms-template.c"
  };

  /* Register protocol */
  proto_mms = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("mms", dissect_mms, proto_mms);
  /* Register fields and subtrees */
  proto_register_field_array(proto_mms, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_mms --- */
void proto_reg_handoff_mms(void) {
	register_ber_oid_dissector("1.0.9506.2.3", dissect_mms, proto_mms,"MMS");
	register_ber_oid_dissector("1.0.9506.2.1", dissect_mms, proto_mms,"mms-abstract-syntax-version1(1)");

}
