/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-mms.c                                                               */
/* asn2wrs.py -b -q -L -p mms -c ./mms.cnf -s ./packet-mms-template -D . -O ../.. mms.asn */

/* packet-mms_asn1.c
 *
 * Ronnie Sahlberg 2005
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/asn1.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/conversation.h>

#include "packet-ber.h"
#include "packet-acse.h"
#include "packet-mms.h"

#define PNAME  "MMS"
#define PSNAME "MMS"
#define PFNAME "mms"

void proto_register_mms(void);
void proto_reg_handoff_mms(void);

static bool use_iec61850_mapping = true;

/* Initialize the protocol and registered fields */
static int proto_mms;

/* Conversation */
static int hf_mms_response_in;
static int hf_mms_response_to;
static int hf_mms_response_time;

/* IEC 61850-8-1 filters */
static int hf_mms_iec61850_rptid;
static int hf_mms_iec61850_reported_optflds;
static int hf_mms_iec61850_seqnum;
static int hf_mms_iec61850_timeofentry;
static int hf_mms_iec61850_datset;
static int hf_mms_iec61850_bufovfl;
static int hf_mms_iec61850_confrev;
static int hf_mms_iec61850_inclusion_bitstring;
static int hf_mms_iec61850_ctlModel;

static int hf_mms_iec61850_QualityC0;
static int hf_mms_iec61850_Quality20;
static int hf_mms_iec61850_Quality10;
static int hf_mms_iec61850_Quality8;
static int hf_mms_iec61850_Quality4;
static int hf_mms_iec61850_Quality2;
static int hf_mms_iec61850_Quality1;
static int hf_mms_iec61850_Quality0080;
static int hf_mms_iec61850_Quality0040;
static int hf_mms_iec61850_Quality0020;
static int hf_mms_iec61850_Quality0010;
static int hf_mms_iec61850_Quality0008;
static int hf_mms_iec61850_quality_bitstring;
static int hf_mms_iec61850_timequality80;
static int hf_mms_iec61850_timequality40;
static int hf_mms_iec61850_timequality20;
static int hf_mms_iec61850_timequality1F;
static int hf_mms_iec61850_check_bitstring;
static int hf_mms_iec61850_check_b1;
static int hf_mms_iec61850_check_b0;
static int hf_mms_iec61850_orcategory;
static int hf_mms_iec61850_beh$stval;
static int hf_mms_iec61850_mod$stval;
static int hf_mms_iec61850_health$stval;
static int hf_mms_iec61850_ctlval;
static int hf_mms_iec61850_origin;
static int hf_mms_iec61850_origin_orcat;
static int hf_mms_iec61850_origin_orident;
static int hf_mms_iec61850_ctlNum;
static int hf_mms_iec61850_T;
static int hf_mms_iec61850_test;

static int hf_mms_confirmed_RequestPDU;           /* Confirmed_RequestPDU */
static int hf_mms_confirmed_ResponsePDU;          /* Confirmed_ResponsePDU */
static int hf_mms_confirmed_ErrorPDU;             /* Confirmed_ErrorPDU */
static int hf_mms_unconfirmed_PDU;                /* Unconfirmed_PDU */
static int hf_mms_rejectPDU;                      /* RejectPDU */
static int hf_mms_cancel_RequestPDU;              /* Cancel_RequestPDU */
static int hf_mms_cancel_ResponsePDU;             /* Cancel_ResponsePDU */
static int hf_mms_cancel_ErrorPDU;                /* Cancel_ErrorPDU */
static int hf_mms_initiate_RequestPDU;            /* Initiate_RequestPDU */
static int hf_mms_initiate_ResponsePDU;           /* Initiate_ResponsePDU */
static int hf_mms_initiate_ErrorPDU;              /* Initiate_ErrorPDU */
static int hf_mms_conclude_RequestPDU;            /* Conclude_RequestPDU */
static int hf_mms_conclude_ResponsePDU;           /* Conclude_ResponsePDU */
static int hf_mms_conclude_ErrorPDU;              /* Conclude_ErrorPDU */
static int hf_mms_invokeID;                       /* Unsigned32 */
static int hf_mms_listOfModifier;                 /* SEQUENCE_OF_Modifier */
static int hf_mms_listOfModifier_item;            /* Modifier */
static int hf_mms_confirmedServiceRequest;        /* ConfirmedServiceRequest */
static int hf_mms_cs_request_detail;              /* CS_Request_Detail */
static int hf_mms_unconfirmedService;             /* UnconfirmedService */
static int hf_mms_confirmedServiceResponse;       /* ConfirmedServiceResponse */
static int hf_mms_modifierPosition;               /* Unsigned32 */
static int hf_mms_serviceError;                   /* ServiceError */
static int hf_mms_informationReport;              /* InformationReport */
static int hf_mms_unsolicitedStatus;              /* UnsolicitedStatus */
static int hf_mms_eventNotification;              /* EventNotification */
static int hf_mms_attach_To_Event_Condition;      /* AttachToEventCondition */
static int hf_mms_attach_To_Semaphore;            /* AttachToSemaphore */
static int hf_mms_status;                         /* Status_Request */
static int hf_mms_getNameList;                    /* GetNameList_Request */
static int hf_mms_identify;                       /* Identify_Request */
static int hf_mms_rename;                         /* Rename_Request */
static int hf_mms_read;                           /* Read_Request */
static int hf_mms_write;                          /* Write_Request */
static int hf_mms_getVariableAccessAttributes;    /* GetVariableAccessAttributes_Request */
static int hf_mms_defineNamedVariable;            /* DefineNamedVariable_Request */
static int hf_mms_defineScatteredAccess;          /* DefineScatteredAccess_Request */
static int hf_mms_getScatteredAccessAttributes;   /* GetScatteredAccessAttributes_Request */
static int hf_mms_deleteVariableAccess;           /* DeleteVariableAccess_Request */
static int hf_mms_defineNamedVariableList;        /* DefineNamedVariableList_Request */
static int hf_mms_getNamedVariableListAttributes;  /* GetNamedVariableListAttributes_Request */
static int hf_mms_deleteNamedVariableList;        /* DeleteNamedVariableList_Request */
static int hf_mms_defineNamedType;                /* DefineNamedType_Request */
static int hf_mms_getNamedTypeAttributes;         /* GetNamedTypeAttributes_Request */
static int hf_mms_deleteNamedType;                /* DeleteNamedType_Request */
static int hf_mms_input;                          /* Input_Request */
static int hf_mms_output;                         /* Output_Request */
static int hf_mms_takeControl;                    /* TakeControl_Request */
static int hf_mms_relinquishControl;              /* RelinquishControl_Request */
static int hf_mms_defineSemaphore;                /* DefineSemaphore_Request */
static int hf_mms_deleteSemaphore;                /* DeleteSemaphore_Request */
static int hf_mms_reportSemaphoreStatus;          /* ReportSemaphoreStatus_Request */
static int hf_mms_reportPoolSemaphoreStatus;      /* ReportPoolSemaphoreStatus_Request */
static int hf_mms_reportSemaphoreEntryStatus;     /* ReportSemaphoreEntryStatus_Request */
static int hf_mms_initiateDownloadSequence;       /* InitiateDownloadSequence_Request */
static int hf_mms_downloadSegment;                /* DownloadSegment_Request */
static int hf_mms_terminateDownloadSequence;      /* TerminateDownloadSequence_Request */
static int hf_mms_initiateUploadSequence;         /* InitiateUploadSequence_Request */
static int hf_mms_uploadSegment;                  /* UploadSegment_Request */
static int hf_mms_terminateUploadSequence;        /* TerminateUploadSequence_Request */
static int hf_mms_requestDomainDownload;          /* RequestDomainDownload_Request */
static int hf_mms_requestDomainUpload;            /* RequestDomainUpload_Request */
static int hf_mms_loadDomainContent;              /* LoadDomainContent_Request */
static int hf_mms_storeDomainContent;             /* StoreDomainContent_Request */
static int hf_mms_deleteDomain;                   /* DeleteDomain_Request */
static int hf_mms_getDomainAttributes;            /* GetDomainAttributes_Request */
static int hf_mms_createProgramInvocation;        /* CreateProgramInvocation_Request */
static int hf_mms_deleteProgramInvocation;        /* DeleteProgramInvocation_Request */
static int hf_mms_start;                          /* Start_Request */
static int hf_mms_stop;                           /* Stop_Request */
static int hf_mms_resume;                         /* Resume_Request */
static int hf_mms_reset;                          /* Reset_Request */
static int hf_mms_kill;                           /* Kill_Request */
static int hf_mms_getProgramInvocationAttributes;  /* GetProgramInvocationAttributes_Request */
static int hf_mms_obtainFile;                     /* ObtainFile_Request */
static int hf_mms_defineEventCondition;           /* DefineEventCondition_Request */
static int hf_mms_confirmedServiceRequest_deleteEventCondition;  /* DeleteEventCondition_Request */
static int hf_mms_getEventConditionAttributes;    /* GetEventConditionAttributes_Request */
static int hf_mms_reportEventConditionStatus;     /* ReportEventConditionStatus_Request */
static int hf_mms_alterEventConditionMonitoring;  /* AlterEventConditionMonitoring_Request */
static int hf_mms_triggerEvent;                   /* TriggerEvent_Request */
static int hf_mms_defineEventAction;              /* DefineEventAction_Request */
static int hf_mms_confirmedServiceRequest_deleteEventAction;  /* DeleteEventAction_Request */
static int hf_mms_getEventActionAttributes;       /* GetEventActionAttributes_Request */
static int hf_mms_reportEventActionStatus;        /* ReportEventActionStatus_Request */
static int hf_mms_defineEventEnrollment;          /* DefineEventEnrollment_Request */
static int hf_mms_confirmedServiceRequest_deleteEventEnrollment;  /* DeleteEventEnrollment_Request */
static int hf_mms_alterEventEnrollment;           /* AlterEventEnrollment_Request */
static int hf_mms_reportEventEnrollmentStatus;    /* ReportEventEnrollmentStatus_Request */
static int hf_mms_getEventEnrollmentAttributes;   /* GetEventEnrollmentAttributes_Request */
static int hf_mms_acknowledgeEventNotification;   /* AcknowledgeEventNotification_Request */
static int hf_mms_getAlarmSummary;                /* GetAlarmSummary_Request */
static int hf_mms_getAlarmEnrollmentSummary;      /* GetAlarmEnrollmentSummary_Request */
static int hf_mms_readJournal;                    /* ReadJournal_Request */
static int hf_mms_writeJournal;                   /* WriteJournal_Request */
static int hf_mms_initializeJournal;              /* InitializeJournal_Request */
static int hf_mms_reportJournalStatus;            /* ReportJournalStatus_Request */
static int hf_mms_createJournal;                  /* CreateJournal_Request */
static int hf_mms_deleteJournal;                  /* DeleteJournal_Request */
static int hf_mms_getCapabilityList;              /* GetCapabilityList_Request */
static int hf_mms_fileOpen;                       /* FileOpen_Request */
static int hf_mms_fileRead;                       /* FileRead_Request */
static int hf_mms_fileClose;                      /* FileClose_Request */
static int hf_mms_fileRename;                     /* FileRename_Request */
static int hf_mms_fileDelete;                     /* FileDelete_Request */
static int hf_mms_fileDirectory;                  /* FileDirectory_Request */
static int hf_mms_foo;                            /* INTEGER */
static int hf_mms_status_01;                      /* Status_Response */
static int hf_mms_getNameList_01;                 /* GetNameList_Response */
static int hf_mms_identify_01;                    /* Identify_Response */
static int hf_mms_rename_01;                      /* Rename_Response */
static int hf_mms_read_01;                        /* Read_Response */
static int hf_mms_write_01;                       /* Write_Response */
static int hf_mms_getVariableAccessAttributes_01;  /* GetVariableAccessAttributes_Response */
static int hf_mms_defineNamedVariable_01;         /* DefineNamedVariable_Response */
static int hf_mms_defineScatteredAccess_01;       /* DefineScatteredAccess_Response */
static int hf_mms_getScatteredAccessAttributes_01;  /* GetScatteredAccessAttributes_Response */
static int hf_mms_deleteVariableAccess_01;        /* DeleteVariableAccess_Response */
static int hf_mms_defineNamedVariableList_01;     /* DefineNamedVariableList_Response */
static int hf_mms_getNamedVariableListAttributes_01;  /* GetNamedVariableListAttributes_Response */
static int hf_mms_deleteNamedVariableList_01;     /* DeleteNamedVariableList_Response */
static int hf_mms_defineNamedType_01;             /* DefineNamedType_Response */
static int hf_mms_getNamedTypeAttributes_01;      /* GetNamedTypeAttributes_Response */
static int hf_mms_deleteNamedType_01;             /* DeleteNamedType_Response */
static int hf_mms_input_01;                       /* Input_Response */
static int hf_mms_output_01;                      /* Output_Response */
static int hf_mms_takeControl_01;                 /* TakeControl_Response */
static int hf_mms_relinquishControl_01;           /* RelinquishControl_Response */
static int hf_mms_defineSemaphore_01;             /* DefineSemaphore_Response */
static int hf_mms_deleteSemaphore_01;             /* DeleteSemaphore_Response */
static int hf_mms_reportSemaphoreStatus_01;       /* ReportSemaphoreStatus_Response */
static int hf_mms_reportPoolSemaphoreStatus_01;   /* ReportPoolSemaphoreStatus_Response */
static int hf_mms_reportSemaphoreEntryStatus_01;  /* ReportSemaphoreEntryStatus_Response */
static int hf_mms_initiateDownloadSequence_01;    /* InitiateDownloadSequence_Response */
static int hf_mms_downloadSegment_01;             /* DownloadSegment_Response */
static int hf_mms_terminateDownloadSequence_01;   /* TerminateDownloadSequence_Response */
static int hf_mms_initiateUploadSequence_01;      /* InitiateUploadSequence_Response */
static int hf_mms_uploadSegment_01;               /* UploadSegment_Response */
static int hf_mms_terminateUploadSequence_01;     /* TerminateUploadSequence_Response */
static int hf_mms_requestDomainDownLoad;          /* RequestDomainDownload_Response */
static int hf_mms_requestDomainUpload_01;         /* RequestDomainUpload_Response */
static int hf_mms_loadDomainContent_01;           /* LoadDomainContent_Response */
static int hf_mms_storeDomainContent_01;          /* StoreDomainContent_Response */
static int hf_mms_deleteDomain_01;                /* DeleteDomain_Response */
static int hf_mms_getDomainAttributes_01;         /* GetDomainAttributes_Response */
static int hf_mms_createProgramInvocation_01;     /* CreateProgramInvocation_Response */
static int hf_mms_deleteProgramInvocation_01;     /* DeleteProgramInvocation_Response */
static int hf_mms_start_01;                       /* Start_Response */
static int hf_mms_stop_01;                        /* Stop_Response */
static int hf_mms_resume_01;                      /* Resume_Response */
static int hf_mms_reset_01;                       /* Reset_Response */
static int hf_mms_kill_01;                        /* Kill_Response */
static int hf_mms_getProgramInvocationAttributes_01;  /* GetProgramInvocationAttributes_Response */
static int hf_mms_obtainFile_01;                  /* ObtainFile_Response */
static int hf_mms_fileOpen_01;                    /* FileOpen_Response */
static int hf_mms_defineEventCondition_01;        /* DefineEventCondition_Response */
static int hf_mms_confirmedServiceResponse_deleteEventCondition;  /* DeleteEventCondition_Response */
static int hf_mms_getEventConditionAttributes_01;  /* GetEventConditionAttributes_Response */
static int hf_mms_reportEventConditionStatus_01;  /* ReportEventConditionStatus_Response */
static int hf_mms_alterEventConditionMonitoring_01;  /* AlterEventConditionMonitoring_Response */
static int hf_mms_triggerEvent_01;                /* TriggerEvent_Response */
static int hf_mms_defineEventAction_01;           /* DefineEventAction_Response */
static int hf_mms_confirmedServiceRequest_deleteEventAction_01;  /* DeleteEventAction_Response */
static int hf_mms_getEventActionAttributes_01;    /* GetEventActionAttributes_Response */
static int hf_mms_reportActionStatus;             /* ReportEventActionStatus_Response */
static int hf_mms_defineEventEnrollment_01;       /* DefineEventEnrollment_Response */
static int hf_mms_confirmedServiceResponse_deleteEventEnrollment;  /* DeleteEventEnrollment_Response */
static int hf_mms_alterEventEnrollment_01;        /* AlterEventEnrollment_Response */
static int hf_mms_reportEventEnrollmentStatus_01;  /* ReportEventEnrollmentStatus_Response */
static int hf_mms_getEventEnrollmentAttributes_01;  /* GetEventEnrollmentAttributes_Response */
static int hf_mms_acknowledgeEventNotification_01;  /* AcknowledgeEventNotification_Response */
static int hf_mms_getAlarmSummary_01;             /* GetAlarmSummary_Response */
static int hf_mms_getAlarmEnrollmentSummary_01;   /* GetAlarmEnrollmentSummary_Response */
static int hf_mms_readJournal_01;                 /* ReadJournal_Response */
static int hf_mms_writeJournal_01;                /* WriteJournal_Response */
static int hf_mms_initializeJournal_01;           /* InitializeJournal_Response */
static int hf_mms_reportJournalStatus_01;         /* ReportJournalStatus_Response */
static int hf_mms_createJournal_01;               /* CreateJournal_Response */
static int hf_mms_deleteJournal_01;               /* DeleteJournal_Response */
static int hf_mms_getCapabilityList_01;           /* GetCapabilityList_Response */
static int hf_mms_fileRead_01;                    /* FileRead_Response */
static int hf_mms_fileClose_01;                   /* FileClose_Response */
static int hf_mms_fileRename_01;                  /* FileRename_Response */
static int hf_mms_fileDelete_01;                  /* FileDelete_Response */
static int hf_mms_fileDirectory_01;               /* FileDirectory_Response */
static int hf_mms_FileName_item;                  /* GraphicString */
static int hf_mms_vmd_specific;                   /* Identifier */
static int hf_mms_domain_specific;                /* T_domain_specific */
static int hf_mms_domainId;                       /* Identifier */
static int hf_mms_objectName_domain_specific_itemId;  /* ObjectName_domain_specific_itemid */
static int hf_mms_aa_specific;                    /* Identifier */
static int hf_mms_ap_title;                       /* T_ap_title */
static int hf_mms_ap_invocation_id;               /* T_ap_invocation_id */
static int hf_mms_ae_qualifier;                   /* T_ae_qualifier */
static int hf_mms_ae_invocation_id;               /* T_ae_invocation_id */
static int hf_mms_localDetailCalling;             /* Integer32 */
static int hf_mms_proposedMaxServOutstandingCalling;  /* Integer16 */
static int hf_mms_proposedMaxServOutstandingCalled;  /* Integer16 */
static int hf_mms_proposedDataStructureNestingLevel;  /* Integer8 */
static int hf_mms_mmsInitRequestDetail;           /* InitRequestDetail */
static int hf_mms_proposedVersionNumber;          /* Integer16 */
static int hf_mms_proposedParameterCBB;           /* ParameterSupportOptions */
static int hf_mms_servicesSupportedCalling;       /* ServiceSupportOptions */
static int hf_mms_localDetailCalled;              /* Integer32 */
static int hf_mms_negociatedMaxServOutstandingCalling;  /* Integer16 */
static int hf_mms_negociatedMaxServOutstandingCalled;  /* Integer16 */
static int hf_mms_negociatedDataStructureNestingLevel;  /* Integer8 */
static int hf_mms_mmsInitResponseDetail;          /* InitResponseDetail */
static int hf_mms_negociatedVersionNumber;        /* Integer16 */
static int hf_mms_negociatedParameterCBB;         /* ParameterSupportOptions */
static int hf_mms_servicesSupportedCalled;        /* ServiceSupportOptions */
static int hf_mms_originalInvokeID;               /* Unsigned32 */
static int hf_mms_errorClass;                     /* T_errorClass */
static int hf_mms_vmd_state;                      /* T_vmd_state */
static int hf_mms_application_reference;          /* T_application_reference */
static int hf_mms_definition;                     /* T_definition */
static int hf_mms_resource;                       /* T_resource */
static int hf_mms_service;                        /* T_service */
static int hf_mms_service_preempt;                /* T_service_preempt */
static int hf_mms_time_resolution;                /* T_time_resolution */
static int hf_mms_access;                         /* T_access */
static int hf_mms_initiate;                       /* T_initiate */
static int hf_mms_conclude;                       /* T_conclude */
static int hf_mms_cancel;                         /* T_cancel */
static int hf_mms_file;                           /* T_file */
static int hf_mms_others;                         /* INTEGER */
static int hf_mms_additionalCode;                 /* INTEGER */
static int hf_mms_additionalDescription;          /* VisibleString */
static int hf_mms_serviceSpecificInformation;     /* T_serviceSpecificInformation */
static int hf_mms_obtainFile_02;                  /* ObtainFile_Error */
static int hf_mms_start_02;                       /* Start_Error */
static int hf_mms_stop_02;                        /* Stop_Error */
static int hf_mms_resume_02;                      /* Resume_Error */
static int hf_mms_reset_02;                       /* Reset_Error */
static int hf_mms_deleteVariableAccess_02;        /* DeleteVariableAccess_Error */
static int hf_mms_deleteNamedVariableList_02;     /* DeleteNamedVariableList_Error */
static int hf_mms_deleteNamedType_02;             /* DeleteNamedType_Error */
static int hf_mms_defineEventEnrollment_Error;    /* DefineEventEnrollment_Error */
static int hf_mms_fileRename_02;                  /* FileRename_Error */
static int hf_mms_additionalService;              /* AdditionalService_Error */
static int hf_mms_changeAccessControl;            /* ChangeAccessControl_Error */
static int hf_mms_defineEcl;                      /* DefineEventConditionList_Error */
static int hf_mms_addECLReference;                /* AddEventConditionListReference_Error */
static int hf_mms_removeECLReference;             /* RemoveEventConditionListReference_Error */
static int hf_mms_initiateUC;                     /* InitiateUnitControl_Error */
static int hf_mms_startUC;                        /* StartUnitControl_Error */
static int hf_mms_stopUC;                         /* StopUnitControl_Error */
static int hf_mms_deleteUC;                       /* DeleteUnitControl_Error */
static int hf_mms_loadUCFromFile;                 /* LoadUnitControlFromFile_Error */
static int hf_mms_eventCondition;                 /* ObjectName */
static int hf_mms_eventConditionList;             /* ObjectName */
static int hf_mms_domain;                         /* Identifier */
static int hf_mms_programInvocation;              /* Identifier */
static int hf_mms_programInvocationName;          /* Identifier */
static int hf_mms_programInvocationState;         /* ProgramInvocationState */
static int hf_mms_none;                           /* NULL */
static int hf_mms_rejectReason;                   /* T_rejectReason */
static int hf_mms_confirmed_requestPDU;           /* T_confirmed_requestPDU */
static int hf_mms_confirmed_responsePDU;          /* T_confirmed_responsePDU */
static int hf_mms_confirmed_errorPDU;             /* T_confirmed_errorPDU */
static int hf_mms_unconfirmedPDU;                 /* T_unconfirmedPDU */
static int hf_mms_pdu_error;                      /* T_pdu_error */
static int hf_mms_cancel_requestPDU;              /* T_cancel_requestPDU */
static int hf_mms_cancel_responsePDU;             /* T_cancel_responsePDU */
static int hf_mms_cancel_errorPDU;                /* T_cancel_errorPDU */
static int hf_mms_conclude_requestPDU;            /* T_conclude_requestPDU */
static int hf_mms_conclude_responsePDU;           /* T_conclude_responsePDU */
static int hf_mms_conclude_errorPDU;              /* T_conclude_errorPDU */
static int hf_mms_vmdLogicalStatus;               /* T_vmdLogicalStatus */
static int hf_mms_vmdPhysicalStatus;              /* T_vmdPhysicalStatus */
static int hf_mms_localDetail;                    /* BIT_STRING_SIZE_0_128 */
static int hf_mms_vmdSpecific;                    /* NULL */
static int hf_mms_domainSpecific;                 /* Identifier */
static int hf_mms_aaSpecific;                     /* NULL */
static int hf_mms_extendedObjectClass;            /* T_extendedObjectClass */
static int hf_mms_objectClass;                    /* ObjectClass */
static int hf_mms_objectScope;                    /* ObjectScope */
static int hf_mms_getNameList_Request_continueAfter;  /* Identifier */
static int hf_mms_listOfIdentifier;               /* SEQUENCE_OF_Identifier */
static int hf_mms_listOfIdentifier_item;          /* Identifier */
static int hf_mms_moreFollows;                    /* BOOLEAN */
static int hf_mms_vendorName;                     /* VisibleString */
static int hf_mms_modelName;                      /* VisibleString */
static int hf_mms_revision;                       /* VisibleString */
static int hf_mms_listOfAbstractSyntaxes;         /* T_listOfAbstractSyntaxes */
static int hf_mms_listOfAbstractSyntaxes_item;    /* OBJECT_IDENTIFIER */
static int hf_mms_extendedObjectClass_01;         /* T_extendedObjectClass_01 */
static int hf_mms_objectClass_01;                 /* T_objectClass */
static int hf_mms_currentName;                    /* ObjectName */
static int hf_mms_newIdentifier;                  /* Identifier */
static int hf_mms_getCapabilityList_Request_continueAfter;  /* VisibleString */
static int hf_mms_listOfCapabilities;             /* T_listOfCapabilities */
static int hf_mms_listOfCapabilities_item;        /* VisibleString */
static int hf_mms_domainName;                     /* Identifier */
static int hf_mms_listOfCapabilities_01;          /* T_listOfCapabilities_01 */
static int hf_mms_sharable;                       /* BOOLEAN */
static int hf_mms_loadData;                       /* T_loadData */
static int hf_mms_non_coded;                      /* OCTET_STRING */
static int hf_mms_coded;                          /* EXTERNALt */
static int hf_mms_discard;                        /* ServiceError */
static int hf_mms_ulsmID;                         /* Integer32 */
static int hf_mms_listOfCapabilities_02;          /* T_listOfCapabilities_02 */
static int hf_mms_loadData_01;                    /* T_loadData_01 */
static int hf_mms_listOfCapabilities_03;          /* T_listOfCapabilities_03 */
static int hf_mms_fileName;                       /* FileName */
static int hf_mms_listOfCapabilities_04;          /* T_listOfCapabilities_04 */
static int hf_mms_thirdParty;                     /* ApplicationReference */
static int hf_mms_filenName;                      /* FileName */
static int hf_mms_listOfCapabilities_05;          /* T_listOfCapabilities_05 */
static int hf_mms_getDomainAttributes_Response_state;  /* DomainState */
static int hf_mms_mmsDeletable;                   /* BOOLEAN */
static int hf_mms_listOfProgramInvocations;       /* SEQUENCE_OF_Identifier */
static int hf_mms_listOfProgramInvocations_item;  /* Identifier */
static int hf_mms_uploadInProgress;               /* Integer8 */
static int hf_mms_listOfDomainName;               /* SEQUENCE_OF_Identifier */
static int hf_mms_listOfDomainName_item;          /* Identifier */
static int hf_mms_reusable;                       /* BOOLEAN */
static int hf_mms_monitorType;                    /* BOOLEAN */
static int hf_mms_executionArgument;              /* T_executionArgument */
static int hf_mms_simpleString;                   /* VisibleString */
static int hf_mms_encodedString;                  /* EXTERNALt */
static int hf_mms_executionArgument_01;           /* T_executionArgument_01 */
static int hf_mms_getProgramInvocationAttributes_Response_state;  /* ProgramInvocationState */
static int hf_mms_listOfDomainNames;              /* SEQUENCE_OF_Identifier */
static int hf_mms_listOfDomainNames_item;         /* Identifier */
static int hf_mms_monitor;                        /* BOOLEAN */
static int hf_mms_startArgument;                  /* VisibleString */
static int hf_mms_executionArgument_02;           /* T_executionArgument_02 */
static int hf_mms_typeName;                       /* ObjectName */
static int hf_mms_array;                          /* T_array */
static int hf_mms_packed;                         /* BOOLEAN */
static int hf_mms_numberOfElements;               /* Unsigned32 */
static int hf_mms_elementType;                    /* TypeSpecification */
static int hf_mms_structure;                      /* T_structure */
static int hf_mms_components;                     /* T_components */
static int hf_mms_components_item;                /* T_components_item */
static int hf_mms_componentName;                  /* Identifier */
static int hf_mms_componentType;                  /* TypeSpecification */
static int hf_mms_boolean;                        /* NULL */
static int hf_mms_typeSpecification_bit_string;   /* Integer32 */
static int hf_mms_integer;                        /* Unsigned8 */
static int hf_mms_unsigned;                       /* Unsigned8 */
static int hf_mms_typeSpecification_octet_string;  /* Integer32 */
static int hf_mms_typeSpecification_visible_string;  /* Integer32 */
static int hf_mms_generalized_time;               /* NULL */
static int hf_mms_typeSpecification_binary_time;  /* BOOLEAN */
static int hf_mms_bcd;                            /* Unsigned8 */
static int hf_mms_objId;                          /* NULL */
static int hf_mms_AlternateAccess_item;           /* AlternateAccess_item */
static int hf_mms_unnamed;                        /* AlternateAccessSelection */
static int hf_mms_named;                          /* T_named */
static int hf_mms_accesst;                        /* AlternateAccessSelection */
static int hf_mms_selectAlternateAccess;          /* T_selectAlternateAccess */
static int hf_mms_accessSelection;                /* T_accessSelection */
static int hf_mms_component;                      /* Identifier */
static int hf_mms_index;                          /* Unsigned32 */
static int hf_mms_indexRange;                     /* T_indexRange */
static int hf_mms_lowIndex;                       /* Unsigned32 */
static int hf_mms_allElements;                    /* NULL */
static int hf_mms_alternateAccess;                /* AlternateAccess */
static int hf_mms_selectAccess;                   /* T_selectAccess */
static int hf_mms_indexRange_01;                  /* T_indexRange_01 */
static int hf_mms_nmberOfElements;                /* Unsigned32 */
static int hf_mms_specificationWithResult;        /* BOOLEAN */
static int hf_mms_variableAccessSpecificatn;      /* VariableAccessSpecification */
static int hf_mms_listOfAccessResult;             /* SEQUENCE_OF_AccessResult */
static int hf_mms_listOfAccessResult_item;        /* AccessResult */
static int hf_mms_listOfData;                     /* T_listOfData */
static int hf_mms_listOfData_item;                /* Data */
static int hf_mms_Write_Response_item;            /* Write_Response_item */
static int hf_mms_failure;                        /* DataAccessError */
static int hf_mms_success;                        /* NULL */
static int hf_mms_variableAccessSpecification;    /* VariableAccessSpecification */
static int hf_mms_listOfAccessResult_01;          /* T_listOfAccessResult */
static int hf_mms_name;                           /* ObjectName */
static int hf_mms_address;                        /* Address */
static int hf_mms_typeSpecification;              /* TypeSpecification */
static int hf_mms_variableName;                   /* ObjectName */
static int hf_mms_scatteredAccessName;            /* ObjectName */
static int hf_mms_scatteredAccessDescription;     /* ScatteredAccessDescription */
static int hf_mms_scopeOfDelete;                  /* T_scopeOfDelete */
static int hf_mms_listOfName;                     /* SEQUENCE_OF_ObjectName */
static int hf_mms_listOfName_item;                /* ObjectName */
static int hf_mms_numberMatched;                  /* Unsigned32 */
static int hf_mms_numberDeleted;                  /* Unsigned32 */
static int hf_mms_variableListName;               /* ObjectName */
static int hf_mms_listOfVariable;                 /* T_listOfVariable */
static int hf_mms_listOfVariable_item;            /* T_listOfVariable_item */
static int hf_mms_variableSpecification;          /* VariableSpecification */
static int hf_mms_listOfVariable_01;              /* T_listOfVariable_01 */
static int hf_mms_listOfVariable_item_01;         /* T_listOfVariable_item_01 */
static int hf_mms_scopeOfDelete_01;               /* T_scopeOfDelete_01 */
static int hf_mms_listOfVariableListName;         /* SEQUENCE_OF_ObjectName */
static int hf_mms_listOfVariableListName_item;    /* ObjectName */
static int hf_mms_scopeOfDelete_02;               /* T_scopeOfDelete_02 */
static int hf_mms_listOfTypeName;                 /* SEQUENCE_OF_ObjectName */
static int hf_mms_listOfTypeName_item;            /* ObjectName */
static int hf_mms_success_01;                     /* Data */
static int hf_mms_array_01;                       /* SEQUENCE_OF_Data */
static int hf_mms_array_item;                     /* Data */
static int hf_mms_structure_01;                   /* T_structure_01 */
static int hf_mms_structure_item;                 /* Data */
static int hf_mms_boolean_01;                     /* T_boolean */
static int hf_mms_data_bit_string;                /* T_data_bit_string */
static int hf_mms_integer_01;                     /* T_integer */
static int hf_mms_unsigned_01;                    /* T_unsigned */
static int hf_mms_floating_point;                 /* FloatingPoint */
static int hf_mms_data_octet_string;              /* T_data_octet_string */
static int hf_mms_data_visible_string;            /* T_data_visible_string */
static int hf_mms_data_binary_time;               /* T_data_binary_time */
static int hf_mms_bcd_01;                         /* INTEGER */
static int hf_mms_booleanArray;                   /* BIT_STRING */
static int hf_mms_objId_01;                       /* OBJECT_IDENTIFIER */
static int hf_mms_mMSString;                      /* MMSString */
static int hf_mms_utc_time;                       /* UtcTime */
static int hf_mms_listOfVariable_02;              /* T_listOfVariable_02 */
static int hf_mms_listOfVariable_item_02;         /* T_listOfVariable_item_02 */
static int hf_mms_ScatteredAccessDescription_item;  /* ScatteredAccessDescription_item */
static int hf_mms_variableDescription;            /* T_variableDescription */
static int hf_mms_invalidated;                    /* NULL */
static int hf_mms_numericAddress;                 /* Unsigned32 */
static int hf_mms_symbolicAddress;                /* VisibleString */
static int hf_mms_unconstrainedAddress;           /* OCTET_STRING */
static int hf_mms_semaphoreName;                  /* ObjectName */
static int hf_mms_namedToken;                     /* Identifier */
static int hf_mms_priority;                       /* Priority */
static int hf_mms_acceptableDelay;                /* Unsigned32 */
static int hf_mms_controlTimeOut;                 /* Unsigned32 */
static int hf_mms_abortOnTimeOut;                 /* BOOLEAN */
static int hf_mms_relinquishIfConnectionLost;     /* BOOLEAN */
static int hf_mms_applicationToPreempt;           /* ApplicationReference */
static int hf_mms_noResult;                       /* NULL */
static int hf_mms_numbersOfTokens;                /* Unsigned16 */
static int hf_mms_class;                          /* T_class */
static int hf_mms_numberOfTokens;                 /* Unsigned16 */
static int hf_mms_numberOfOwnedTokens;            /* Unsigned16 */
static int hf_mms_numberOfHungTokens;             /* Unsigned16 */
static int hf_mms_nameToStartAfter;               /* Identifier */
static int hf_mms_listOfNamedTokens;              /* T_listOfNamedTokens */
static int hf_mms_listOfNamedTokens_item;         /* T_listOfNamedTokens_item */
static int hf_mms_freeNamedToken;                 /* Identifier */
static int hf_mms_ownedNamedToken;                /* Identifier */
static int hf_mms_hungNamedToken;                 /* Identifier */
static int hf_mms_reportSemaphoreEntryStatus_Request_state;  /* T_reportSemaphoreEntryStatus_Request_state */
static int hf_mms_entryIdToStartAfter;            /* OCTET_STRING */
static int hf_mms_listOfSemaphoreEntry;           /* SEQUENCE_OF_SemaphoreEntry */
static int hf_mms_listOfSemaphoreEntry_item;      /* SemaphoreEntry */
static int hf_mms_entryId;                        /* OCTET_STRING */
static int hf_mms_entryClass;                     /* T_entryClass */
static int hf_mms_applicationReference;           /* ApplicationReference */
static int hf_mms_remainingTimeOut;               /* Unsigned32 */
static int hf_mms_operatorStationName;            /* Identifier */
static int hf_mms_echo;                           /* BOOLEAN */
static int hf_mms_listOfPromptData;               /* T_listOfPromptData */
static int hf_mms_listOfPromptData_item;          /* VisibleString */
static int hf_mms_inputTimeOut;                   /* Unsigned32 */
static int hf_mms_listOfOutputData;               /* T_listOfOutputData */
static int hf_mms_listOfOutputData_item;          /* VisibleString */
static int hf_mms_eventConditionName;             /* ObjectName */
static int hf_mms_class_01;                       /* EC_Class */
static int hf_mms_prio_rity;                      /* Priority */
static int hf_mms_severity;                       /* Unsigned8 */
static int hf_mms_alarmSummaryReports;            /* BOOLEAN */
static int hf_mms_monitoredVariable;              /* VariableSpecification */
static int hf_mms_evaluationInterval;             /* Unsigned32 */
static int hf_mms_specific;                       /* SEQUENCE_OF_ObjectName */
static int hf_mms_specific_item;                  /* ObjectName */
static int hf_mms_aa_specific_01;                 /* NULL */
static int hf_mms_vmd;                            /* NULL */
static int hf_mms_monitoredVariable_01;           /* T_monitoredVariable */
static int hf_mms_variableReference;              /* VariableSpecification */
static int hf_mms_undefined;                      /* NULL */
static int hf_mms_currentState;                   /* EC_State */
static int hf_mms_numberOfEventEnrollments;       /* Unsigned32 */
static int hf_mms_enabled;                        /* BOOLEAN */
static int hf_mms_timeOfLastTransitionToActive;   /* EventTime */
static int hf_mms_timeOfLastTransitionToIdle;     /* EventTime */
static int hf_mms_eventActionName;                /* ObjectName */
static int hf_mms_eventEnrollmentName;            /* ObjectName */
static int hf_mms_eventConditionTransition;       /* Transitions */
static int hf_mms_alarmAcknowledgementRule;       /* AlarmAckRule */
static int hf_mms_clientApplication;              /* ApplicationReference */
static int hf_mms_ec;                             /* ObjectName */
static int hf_mms_ea;                             /* ObjectName */
static int hf_mms_scopeOfRequest;                 /* T_scopeOfRequest */
static int hf_mms_eventEnrollmentNames;           /* SEQUENCE_OF_ObjectName */
static int hf_mms_eventEnrollmentNames_item;      /* ObjectName */
static int hf_mms_getEventEnrollmentAttributes_Request_continueAfter;  /* ObjectName */
static int hf_mms_eventConditionName_01;          /* T_eventConditionName */
static int hf_mms_eventActionName_01;             /* T_eventActionName */
static int hf_mms_eventAction;                    /* ObjectName */
static int hf_mms_enrollmentClass;                /* EE_Class */
static int hf_mms_duration;                       /* EE_Duration */
static int hf_mms_remainingAcceptableDelay;       /* Unsigned32 */
static int hf_mms_listOfEventEnrollment;          /* SEQUENCE_OF_EventEnrollment */
static int hf_mms_listOfEventEnrollment_item;     /* EventEnrollment */
static int hf_mms_eventConditionTransitions;      /* Transitions */
static int hf_mms_notificationLost;               /* BOOLEAN */
static int hf_mms_alarmAcknowledgmentRule;        /* AlarmAckRule */
static int hf_mms_currentState_01;                /* EE_State */
static int hf_mms_currentState_02;                /* T_currentState */
static int hf_mms_alterEventEnrollment_Response_currentState_state;  /* EE_State */
static int hf_mms_transitionTime;                 /* EventTime */
static int hf_mms_acknowledgedState;              /* EC_State */
static int hf_mms_timeOfAcknowledgedTransition;   /* EventTime */
static int hf_mms_enrollmentsOnly;                /* BOOLEAN */
static int hf_mms_activeAlarmsOnly;               /* BOOLEAN */
static int hf_mms_acknowledgmentFilter;           /* T_acknowledgmentFilter */
static int hf_mms_severityFilter;                 /* T_severityFilter */
static int hf_mms_mostSevere;                     /* Unsigned8 */
static int hf_mms_leastSevere;                    /* Unsigned8 */
static int hf_mms_continueAfter;                  /* ObjectName */
static int hf_mms_listOfAlarmSummary;             /* SEQUENCE_OF_AlarmSummary */
static int hf_mms_listOfAlarmSummary_item;        /* AlarmSummary */
static int hf_mms_unacknowledgedState;            /* T_unacknowledgedState */
static int hf_mms_acknowledgmentFilter_01;        /* T_acknowledgmentFilter_01 */
static int hf_mms_severityFilter_01;              /* T_severityFilter_01 */
static int hf_mms_getAlarmEnrollmentSummary_Request_continueAfter;  /* ObjectName */
static int hf_mms_listOfAlarmEnrollmentSummary;   /* SEQUENCE_OF_AlarmEnrollmentSummary */
static int hf_mms_listOfAlarmEnrollmentSummary_item;  /* AlarmEnrollmentSummary */
static int hf_mms_enrollementState;               /* EE_State */
static int hf_mms_timeActiveAcknowledged;         /* EventTime */
static int hf_mms_timeIdleAcknowledged;           /* EventTime */
static int hf_mms_eventConditionName_02;          /* T_eventConditionName_01 */
static int hf_mms_actionResult;                   /* T_actionResult */
static int hf_mms_eventActioName;                 /* ObjectName */
static int hf_mms_eventActionResult;              /* T_eventActionResult */
static int hf_mms_success_02;                     /* ConfirmedServiceResponse */
static int hf_mms_failure_01;                     /* ServiceError */
static int hf_mms_causingTransitions;             /* Transitions */
static int hf_mms_timeOfDayT;                     /* TimeOfDay */
static int hf_mms_timeSequenceIdentifier;         /* Unsigned32 */
static int hf_mms_journalName;                    /* ObjectName */
static int hf_mms_rangeStartSpecification;        /* T_rangeStartSpecification */
static int hf_mms_startingTime;                   /* TimeOfDay */
static int hf_mms_startingEntry;                  /* OCTET_STRING */
static int hf_mms_rangeStopSpecification;         /* T_rangeStopSpecification */
static int hf_mms_endingTime;                     /* TimeOfDay */
static int hf_mms_numberOfEntries;                /* Integer32 */
static int hf_mms_listOfVariables;                /* T_listOfVariables */
static int hf_mms_listOfVariables_item;           /* VisibleString */
static int hf_mms_entryToStartAfter;              /* T_entryToStartAfter */
static int hf_mms_timeSpecification;              /* TimeOfDay */
static int hf_mms_entrySpecification;             /* OCTET_STRING */
static int hf_mms_listOfJournalEntry;             /* SEQUENCE_OF_JournalEntry */
static int hf_mms_listOfJournalEntry_item;        /* JournalEntry */
static int hf_mms_entryIdentifier;                /* OCTET_STRING */
static int hf_mms_originatingApplication;         /* ApplicationReference */
static int hf_mms_entryContent;                   /* EntryContent */
static int hf_mms_listOfJournalEntry_01;          /* SEQUENCE_OF_EntryContent */
static int hf_mms_listOfJournalEntry_item_01;     /* EntryContent */
static int hf_mms_limitSpecification;             /* T_limitSpecification */
static int hf_mms_limitingTime;                   /* TimeOfDay */
static int hf_mms_limitingEntry;                  /* OCTET_STRING */
static int hf_mms_currentEntries;                 /* Unsigned32 */
static int hf_mms_occurenceTime;                  /* TimeOfDay */
static int hf_mms_additionalDetail;               /* JOU_Additional_Detail */
static int hf_mms_entryForm;                      /* T_entryForm */
static int hf_mms_data;                           /* T_data */
static int hf_mms_event;                          /* T_event */
static int hf_mms_listOfVariables_01;             /* T_listOfVariables_01 */
static int hf_mms_listOfVariables_item_01;        /* T_listOfVariables_item */
static int hf_mms_variableTag;                    /* VisibleString */
static int hf_mms_valueSpecification;             /* Data */
static int hf_mms_annotation;                     /* VisibleString */
static int hf_mms_sourceFileServer;               /* ApplicationReference */
static int hf_mms_sourceFile;                     /* FileName */
static int hf_mms_destinationFile;                /* FileName */
static int hf_mms_initialPosition;                /* Unsigned32 */
static int hf_mms_frsmID;                         /* Integer32 */
static int hf_mms_fileAttributes;                 /* FileAttributes */
static int hf_mms_fileData;                       /* OCTET_STRING */
static int hf_mms_currentFileName;                /* FileName */
static int hf_mms_newFileName;                    /* FileName */
static int hf_mms_fileSpecification;              /* FileName */
static int hf_mms_fileDirectory_Request_continueAfter;  /* FileName */
static int hf_mms_listOfDirectoryEntry;           /* SEQUENCE_OF_DirectoryEntry */
static int hf_mms_listOfDirectoryEntry_item;      /* DirectoryEntry */
static int hf_mms_filename;                       /* FileName */
static int hf_mms_sizeOfFile;                     /* Unsigned32 */
static int hf_mms_lastModified;                   /* GeneralizedTime */
/* named bits */
static int hf_mms_ReportedOptFlds_reserved;
static int hf_mms_ReportedOptFlds_sequence_number;
static int hf_mms_ReportedOptFlds_report_time_stamp;
static int hf_mms_ReportedOptFlds_reason_for_inclusion;
static int hf_mms_ReportedOptFlds_data_set_name;
static int hf_mms_ReportedOptFlds_data_reference;
static int hf_mms_ReportedOptFlds_buffer_overflow;
static int hf_mms_ReportedOptFlds_entryID;
static int hf_mms_ReportedOptFlds_conf_revision;
static int hf_mms_ReportedOptFlds_segmentation;
static int hf_mms_ParameterSupportOptions_str1;
static int hf_mms_ParameterSupportOptions_str2;
static int hf_mms_ParameterSupportOptions_vnam;
static int hf_mms_ParameterSupportOptions_valt;
static int hf_mms_ParameterSupportOptions_vadr;
static int hf_mms_ParameterSupportOptions_vsca;
static int hf_mms_ParameterSupportOptions_tpy;
static int hf_mms_ParameterSupportOptions_vlis;
static int hf_mms_ParameterSupportOptions_real;
static int hf_mms_ParameterSupportOptions_spare_bit9;
static int hf_mms_ParameterSupportOptions_cei;
static int hf_mms_ServiceSupportOptions_status;
static int hf_mms_ServiceSupportOptions_getNameList;
static int hf_mms_ServiceSupportOptions_identify;
static int hf_mms_ServiceSupportOptions_rename;
static int hf_mms_ServiceSupportOptions_read;
static int hf_mms_ServiceSupportOptions_write;
static int hf_mms_ServiceSupportOptions_getVariableAccessAttributes;
static int hf_mms_ServiceSupportOptions_defineNamedVariable;
static int hf_mms_ServiceSupportOptions_defineScatteredAccess;
static int hf_mms_ServiceSupportOptions_getScatteredAccessAttributes;
static int hf_mms_ServiceSupportOptions_deleteVariableAccess;
static int hf_mms_ServiceSupportOptions_defineNamedVariableList;
static int hf_mms_ServiceSupportOptions_getNamedVariableListAttributes;
static int hf_mms_ServiceSupportOptions_deleteNamedVariableList;
static int hf_mms_ServiceSupportOptions_defineNamedType;
static int hf_mms_ServiceSupportOptions_getNamedTypeAttributes;
static int hf_mms_ServiceSupportOptions_deleteNamedType;
static int hf_mms_ServiceSupportOptions_input;
static int hf_mms_ServiceSupportOptions_output;
static int hf_mms_ServiceSupportOptions_takeControl;
static int hf_mms_ServiceSupportOptions_relinquishControl;
static int hf_mms_ServiceSupportOptions_defineSemaphore;
static int hf_mms_ServiceSupportOptions_deleteSemaphore;
static int hf_mms_ServiceSupportOptions_reportSemaphoreStatus;
static int hf_mms_ServiceSupportOptions_reportPoolSemaphoreStatus;
static int hf_mms_ServiceSupportOptions_reportSemaphoreEntryStatus;
static int hf_mms_ServiceSupportOptions_initiateDownloadSequence;
static int hf_mms_ServiceSupportOptions_downloadSegment;
static int hf_mms_ServiceSupportOptions_terminateDownloadSequence;
static int hf_mms_ServiceSupportOptions_initiateUploadSequence;
static int hf_mms_ServiceSupportOptions_uploadSegment;
static int hf_mms_ServiceSupportOptions_terminateUploadSequence;
static int hf_mms_ServiceSupportOptions_requestDomainDownload;
static int hf_mms_ServiceSupportOptions_requestDomainUpload;
static int hf_mms_ServiceSupportOptions_loadDomainContent;
static int hf_mms_ServiceSupportOptions_storeDomainContent;
static int hf_mms_ServiceSupportOptions_deleteDomain;
static int hf_mms_ServiceSupportOptions_getDomainAttributes;
static int hf_mms_ServiceSupportOptions_createProgramInvocation;
static int hf_mms_ServiceSupportOptions_deleteProgramInvocation;
static int hf_mms_ServiceSupportOptions_start;
static int hf_mms_ServiceSupportOptions_stop;
static int hf_mms_ServiceSupportOptions_resume;
static int hf_mms_ServiceSupportOptions_reset;
static int hf_mms_ServiceSupportOptions_kill;
static int hf_mms_ServiceSupportOptions_getProgramInvocationAttributes;
static int hf_mms_ServiceSupportOptions_obtainFile;
static int hf_mms_ServiceSupportOptions_defineEventCondition;
static int hf_mms_ServiceSupportOptions_deleteEventCondition;
static int hf_mms_ServiceSupportOptions_getEventConditionAttributes;
static int hf_mms_ServiceSupportOptions_reportEventConditionStatus;
static int hf_mms_ServiceSupportOptions_alterEventConditionMonitoring;
static int hf_mms_ServiceSupportOptions_triggerEvent;
static int hf_mms_ServiceSupportOptions_defineEventAction;
static int hf_mms_ServiceSupportOptions_deleteEventAction;
static int hf_mms_ServiceSupportOptions_getEventActionAttributes;
static int hf_mms_ServiceSupportOptions_reportActionStatus;
static int hf_mms_ServiceSupportOptions_defineEventEnrollment;
static int hf_mms_ServiceSupportOptions_deleteEventEnrollment;
static int hf_mms_ServiceSupportOptions_alterEventEnrollment;
static int hf_mms_ServiceSupportOptions_reportEventEnrollmentStatus;
static int hf_mms_ServiceSupportOptions_getEventEnrollmentAttributes;
static int hf_mms_ServiceSupportOptions_acknowledgeEventNotification;
static int hf_mms_ServiceSupportOptions_getAlarmSummary;
static int hf_mms_ServiceSupportOptions_getAlarmEnrollmentSummary;
static int hf_mms_ServiceSupportOptions_readJournal;
static int hf_mms_ServiceSupportOptions_writeJournal;
static int hf_mms_ServiceSupportOptions_initializeJournal;
static int hf_mms_ServiceSupportOptions_reportJournalStatus;
static int hf_mms_ServiceSupportOptions_createJournal;
static int hf_mms_ServiceSupportOptions_deleteJournal;
static int hf_mms_ServiceSupportOptions_getCapabilityList;
static int hf_mms_ServiceSupportOptions_fileOpen;
static int hf_mms_ServiceSupportOptions_fileRead;
static int hf_mms_ServiceSupportOptions_fileClose;
static int hf_mms_ServiceSupportOptions_fileRename;
static int hf_mms_ServiceSupportOptions_fileDelete;
static int hf_mms_ServiceSupportOptions_fileDirectory;
static int hf_mms_ServiceSupportOptions_unsolicitedStatus;
static int hf_mms_ServiceSupportOptions_informationReport;
static int hf_mms_ServiceSupportOptions_eventNotification;
static int hf_mms_ServiceSupportOptions_attachToEventCondition;
static int hf_mms_ServiceSupportOptions_attachToSemaphore;
static int hf_mms_ServiceSupportOptions_conclude;
static int hf_mms_ServiceSupportOptions_cancel;
static int hf_mms_Transitions_idle_to_disabled;
static int hf_mms_Transitions_active_to_disabled;
static int hf_mms_Transitions_disabled_to_idle;
static int hf_mms_Transitions_active_to_idle;
static int hf_mms_Transitions_disabled_to_active;
static int hf_mms_Transitions_idle_to_active;
static int hf_mms_Transitions_any_to_deleted;

/* Initialize the subtree pointers */
static int ett_mms;
static int ett_mms_iec61850_quality_bitstring;
static int ett_mms_iec61850_check_bitstring;
static int ett_mms_ReportedOptFlds;
static int ett_mms_MMSpdu;
static int ett_mms_Confirmed_RequestPDU;
static int ett_mms_SEQUENCE_OF_Modifier;
static int ett_mms_Unconfirmed_PDU;
static int ett_mms_Confirmed_ResponsePDU;
static int ett_mms_Confirmed_ErrorPDU;
static int ett_mms_UnconfirmedService;
static int ett_mms_Modifier;
static int ett_mms_ConfirmedServiceRequest;
static int ett_mms_CS_Request_Detail;
static int ett_mms_ConfirmedServiceResponse;
static int ett_mms_FileName;
static int ett_mms_ObjectName;
static int ett_mms_T_domain_specific;
static int ett_mms_ApplicationReference;
static int ett_mms_Initiate_RequestPDU;
static int ett_mms_InitRequestDetail;
static int ett_mms_Initiate_ResponsePDU;
static int ett_mms_InitResponseDetail;
static int ett_mms_ParameterSupportOptions;
static int ett_mms_ServiceSupportOptions;
static int ett_mms_Cancel_ErrorPDU;
static int ett_mms_ServiceError;
static int ett_mms_T_errorClass;
static int ett_mms_T_serviceSpecificInformation;
static int ett_mms_AdditionalService_Error;
static int ett_mms_RemoveEventConditionListReference_Error;
static int ett_mms_InitiateUnitControl_Error;
static int ett_mms_StartUnitControl_Error;
static int ett_mms_StopUnitControl_Error;
static int ett_mms_DeleteUnitControl_Error;
static int ett_mms_LoadUnitControlFromFile_Error;
static int ett_mms_RejectPDU;
static int ett_mms_T_rejectReason;
static int ett_mms_Status_Response;
static int ett_mms_ObjectScope;
static int ett_mms_GetNameList_Request;
static int ett_mms_T_extendedObjectClass;
static int ett_mms_GetNameList_Response;
static int ett_mms_SEQUENCE_OF_Identifier;
static int ett_mms_Identify_Response;
static int ett_mms_T_listOfAbstractSyntaxes;
static int ett_mms_Rename_Request;
static int ett_mms_T_extendedObjectClass_01;
static int ett_mms_GetCapabilityList_Request;
static int ett_mms_GetCapabilityList_Response;
static int ett_mms_T_listOfCapabilities;
static int ett_mms_InitiateDownloadSequence_Request;
static int ett_mms_T_listOfCapabilities_01;
static int ett_mms_DownloadSegment_Response;
static int ett_mms_T_loadData;
static int ett_mms_TerminateDownloadSequence_Request;
static int ett_mms_InitiateUploadSequence_Response;
static int ett_mms_T_listOfCapabilities_02;
static int ett_mms_UploadSegment_Response;
static int ett_mms_T_loadData_01;
static int ett_mms_RequestDomainDownload_Request;
static int ett_mms_T_listOfCapabilities_03;
static int ett_mms_RequestDomainUpload_Request;
static int ett_mms_LoadDomainContent_Request;
static int ett_mms_T_listOfCapabilities_04;
static int ett_mms_StoreDomainContent_Request;
static int ett_mms_GetDomainAttributes_Response;
static int ett_mms_T_listOfCapabilities_05;
static int ett_mms_CreateProgramInvocation_Request;
static int ett_mms_Start_Request;
static int ett_mms_T_executionArgument;
static int ett_mms_Stop_Request;
static int ett_mms_Resume_Request;
static int ett_mms_T_executionArgument_01;
static int ett_mms_Reset_Request;
static int ett_mms_Kill_Request;
static int ett_mms_GetProgramInvocationAttributes_Response;
static int ett_mms_T_executionArgument_02;
static int ett_mms_TypeSpecification;
static int ett_mms_T_array;
static int ett_mms_T_structure;
static int ett_mms_T_components;
static int ett_mms_T_components_item;
static int ett_mms_AlternateAccess;
static int ett_mms_AlternateAccess_item;
static int ett_mms_T_named;
static int ett_mms_AlternateAccessSelection;
static int ett_mms_T_selectAlternateAccess;
static int ett_mms_T_accessSelection;
static int ett_mms_T_indexRange;
static int ett_mms_T_selectAccess;
static int ett_mms_T_indexRange_01;
static int ett_mms_Read_Request;
static int ett_mms_Read_Response;
static int ett_mms_SEQUENCE_OF_AccessResult;
static int ett_mms_Write_Request;
static int ett_mms_T_listOfData;
static int ett_mms_Write_Response;
static int ett_mms_Write_Response_item;
static int ett_mms_InformationReport;
static int ett_mms_T_listOfAccessResult;
static int ett_mms_GetVariableAccessAttributes_Request;
static int ett_mms_GetVariableAccessAttributes_Response;
static int ett_mms_DefineNamedVariable_Request;
static int ett_mms_DefineScatteredAccess_Request;
static int ett_mms_GetScatteredAccessAttributes_Response;
static int ett_mms_DeleteVariableAccess_Request;
static int ett_mms_SEQUENCE_OF_ObjectName;
static int ett_mms_DeleteVariableAccess_Response;
static int ett_mms_DefineNamedVariableList_Request;
static int ett_mms_T_listOfVariable;
static int ett_mms_T_listOfVariable_item;
static int ett_mms_GetNamedVariableListAttributes_Response;
static int ett_mms_T_listOfVariable_01;
static int ett_mms_T_listOfVariable_item_01;
static int ett_mms_DeleteNamedVariableList_Request;
static int ett_mms_DeleteNamedVariableList_Response;
static int ett_mms_DefineNamedType_Request;
static int ett_mms_GetNamedTypeAttributes_Response;
static int ett_mms_DeleteNamedType_Request;
static int ett_mms_DeleteNamedType_Response;
static int ett_mms_AccessResult;
static int ett_mms_Data;
static int ett_mms_SEQUENCE_OF_Data;
static int ett_mms_T_structure_01;
static int ett_mms_VariableAccessSpecification;
static int ett_mms_T_listOfVariable_02;
static int ett_mms_T_listOfVariable_item_02;
static int ett_mms_ScatteredAccessDescription;
static int ett_mms_ScatteredAccessDescription_item;
static int ett_mms_VariableSpecification;
static int ett_mms_T_variableDescription;
static int ett_mms_Address;
static int ett_mms_TakeControl_Request;
static int ett_mms_TakeControl_Response;
static int ett_mms_RelinquishControl_Request;
static int ett_mms_DefineSemaphore_Request;
static int ett_mms_ReportSemaphoreStatus_Response;
static int ett_mms_ReportPoolSemaphoreStatus_Request;
static int ett_mms_ReportPoolSemaphoreStatus_Response;
static int ett_mms_T_listOfNamedTokens;
static int ett_mms_T_listOfNamedTokens_item;
static int ett_mms_ReportSemaphoreEntryStatus_Request;
static int ett_mms_ReportSemaphoreEntryStatus_Response;
static int ett_mms_SEQUENCE_OF_SemaphoreEntry;
static int ett_mms_AttachToSemaphore;
static int ett_mms_SemaphoreEntry;
static int ett_mms_Input_Request;
static int ett_mms_T_listOfPromptData;
static int ett_mms_Output_Request;
static int ett_mms_T_listOfOutputData;
static int ett_mms_DefineEventCondition_Request;
static int ett_mms_DeleteEventCondition_Request;
static int ett_mms_GetEventConditionAttributes_Response;
static int ett_mms_T_monitoredVariable;
static int ett_mms_ReportEventConditionStatus_Response;
static int ett_mms_AlterEventConditionMonitoring_Request;
static int ett_mms_TriggerEvent_Request;
static int ett_mms_DefineEventAction_Request;
static int ett_mms_DeleteEventAction_Request;
static int ett_mms_GetEventActionAttributes_Response;
static int ett_mms_DefineEventEnrollment_Request;
static int ett_mms_DeleteEventEnrollment_Request;
static int ett_mms_GetEventEnrollmentAttributes_Request;
static int ett_mms_EventEnrollment;
static int ett_mms_T_eventConditionName;
static int ett_mms_T_eventActionName;
static int ett_mms_GetEventEnrollmentAttributes_Response;
static int ett_mms_SEQUENCE_OF_EventEnrollment;
static int ett_mms_ReportEventEnrollmentStatus_Response;
static int ett_mms_AlterEventEnrollment_Request;
static int ett_mms_AlterEventEnrollment_Response;
static int ett_mms_T_currentState;
static int ett_mms_AcknowledgeEventNotification_Request;
static int ett_mms_GetAlarmSummary_Request;
static int ett_mms_T_severityFilter;
static int ett_mms_GetAlarmSummary_Response;
static int ett_mms_SEQUENCE_OF_AlarmSummary;
static int ett_mms_AlarmSummary;
static int ett_mms_GetAlarmEnrollmentSummary_Request;
static int ett_mms_T_severityFilter_01;
static int ett_mms_GetAlarmEnrollmentSummary_Response;
static int ett_mms_SEQUENCE_OF_AlarmEnrollmentSummary;
static int ett_mms_AlarmEnrollmentSummary;
static int ett_mms_EventNotification;
static int ett_mms_T_eventConditionName_01;
static int ett_mms_T_actionResult;
static int ett_mms_T_eventActionResult;
static int ett_mms_AttachToEventCondition;
static int ett_mms_EventTime;
static int ett_mms_Transitions;
static int ett_mms_ReadJournal_Request;
static int ett_mms_T_rangeStartSpecification;
static int ett_mms_T_rangeStopSpecification;
static int ett_mms_T_listOfVariables;
static int ett_mms_T_entryToStartAfter;
static int ett_mms_ReadJournal_Response;
static int ett_mms_SEQUENCE_OF_JournalEntry;
static int ett_mms_JournalEntry;
static int ett_mms_WriteJournal_Request;
static int ett_mms_SEQUENCE_OF_EntryContent;
static int ett_mms_InitializeJournal_Request;
static int ett_mms_T_limitSpecification;
static int ett_mms_ReportJournalStatus_Response;
static int ett_mms_CreateJournal_Request;
static int ett_mms_DeleteJournal_Request;
static int ett_mms_EntryContent;
static int ett_mms_T_entryForm;
static int ett_mms_T_data;
static int ett_mms_T_event;
static int ett_mms_T_listOfVariables_01;
static int ett_mms_T_listOfVariables_item;
static int ett_mms_ObtainFile_Request;
static int ett_mms_FileOpen_Request;
static int ett_mms_FileOpen_Response;
static int ett_mms_FileRead_Response;
static int ett_mms_FileRename_Request;
static int ett_mms_FileDirectory_Request;
static int ett_mms_FileDirectory_Response;
static int ett_mms_SEQUENCE_OF_DirectoryEntry;
static int ett_mms_DirectoryEntry;
static int ett_mms_FileAttributes;

static expert_field ei_mms_mal_timeofday_encoding;
static expert_field ei_mms_mal_utctime_encoding;
static expert_field ei_mms_zero_pdu;

/*****************************************************************************/
/* Packet private data                                                       */
/* For this dissector, all access to actx->private_data should be made       */
/* through this API, which ensures that they will not overwrite each other!! */
/*****************************************************************************/

#define BUFFER_SIZE_PRE 10
#define BUFFER_SIZE_MORE 1024

typedef enum _iec61850_8_1_vmd_specific {
    IEC61850_8_1_NOT_SET = 0,
    IEC61850_8_1_RPT
} iec61850_8_1_vmd_specific;

typedef enum _itemid_type {
    IEC61850_ITEM_ID_NOT_SET = 0,
    IEC61850_ITEM_ID_CTLMODEL,
    IEC61850_ITEM_ID_Q,
    IEC61850_ITEM_ID_OPER,
    IEC61850_ITEM_ID_CHECK,
    IEC61850_ITEM_ID_OR_CAT,
    IEC61850_ITEM_ID_BEH$STVAL,
    IEC61850_ITEM_ID_MOD$STVAL,
    IEC61850_ITEM_ID_HEALTH$STVAL,
    IEC61850_ITEM_ID_$BR$_OR_$RP$,
    IEC61850_ITEM_ID_$SBOW
} itemid_type;

typedef struct _mms_transaction_t {
    uint32_t req_frame;
    uint32_t rep_frame;
    nstime_t req_time;
    /* Request info*/
    itemid_type itemid;    /* Numeric representation of ItemId substring */
    int conf_serv_pdu_type_req;
} mms_transaction_t;

typedef struct _mms_conv_info_t {
    wmem_map_t* pdus;
} mms_conv_info_t;

typedef struct mms_private_data_t
{
    char preCinfo[BUFFER_SIZE_PRE];
    char moreCinfo[BUFFER_SIZE_MORE];
} mms_private_data_t;

#define MMS_CONFIRMED_REQUEST_PDU        0
#define MMS_CONFIRMED_RESPONSE_PDU       1
#define MMS_CONFIRMED_ERROR_PDU          2
#define MMS_UNCONFIRMED_PDU              3
#define MMS_REJECT_PDU                   4
#define MMS_CANCEL_REQUEST_PDU           5
#define MMS_CANCEL_RESPONSE_PDU          6
#define MMS_CANCEL_ERROR_PDU             7
#define MMS_INITIATE_REQUEST_PDU         8
#define MMS_INITIATE_RESPONSE_PDU        9
#define MMS_INITIATE_ERROR_PDU          10
#define MMS_CONCLUDE_REQUEST_PDU        11
#define MMS_CONCLUDE_RESPONSE_PDU       12
#define MMS_CONCLUDE_ERROR_PDU          13

#define MMS_CONFIRMEDSERVICE_STATUS    0
#define MMS_CONFIRMEDSERVICE_GETNAMELIST    1
#define MMS_CONFIRMEDSERVICE_IDENTIFY    2
#define MMS_CONFIRMEDSERVICE_RENAME    3
#define MMS_CONFIRMEDSERVICE_READ    4
#define MMS_CONFIRMEDSERVICE_WRITE    5
#define MMS_CONFIRMEDSERVICE_GETVARIABLEACCESSATTRIBUTES    6
#define MMS_CONFIRMEDSERVICE_DEFINENAMEDVARIABLE    7
#define MMS_CONFIRMEDSERVICE_DEFINESCATTEREDACCESS    8
#define MMS_CONFIRMEDSERVICE_GETSCATTEREDACCESSATTRIBUTES    9
#define MMS_CONFIRMEDSERVICE_DELETEVARIABLEACCESS    10
#define MMS_CONFIRMEDSERVICE_DEFINENAMEDVARIABLELIST    11
#define MMS_CONFIRMEDSERVICE_GETNAMEDVARIABLELISTATTRIBUTES    12
#define MMS_CONFIRMEDSERVICE_DELETENAMEDVARIABLELIST    13
#define MMS_CONFIRMEDSERVICE_DEFINENAMEDTYPE    14
#define MMS_CONFIRMEDSERVICE_GETNAMEDTYPEATTRIBUTES    15
#define MMS_CONFIRMEDSERVICE_DELETENAMEDTYPE    16
#define MMS_CONFIRMEDSERVICE_INPUT    17
#define MMS_CONFIRMEDSERVICE_OUTPUT    18
#define MMS_CONFIRMEDSERVICE_TAKECONTROL    19
#define MMS_CONFIRMEDSERVICE_RELINQUISHCONTROL    20
#define MMS_CONFIRMEDSERVICE_DEFINESEMAPHORE    21
#define MMS_CONFIRMEDSERVICE_DELETESEMAPHORE    22
#define MMS_CONFIRMEDSERVICE_REPORTSEMAPHORESTATUS    23
#define MMS_CONFIRMEDSERVICE_REPORTPOOLSEMAPHORESTATUS    24
#define MMS_CONFIRMEDSERVICE_REPORTSEMAPHOREENTRYSTATUS    25
#define MMS_CONFIRMEDSERVICE_INITIATEDOWNLOADSEQUENCE    26
#define MMS_CONFIRMEDSERVICE_DOWNLOADSEGMENT    27
#define MMS_CONFIRMEDSERVICE_TERMINATEDOWNLOADSEQUENCE    28
#define MMS_CONFIRMEDSERVICE_INITIATEUPLOADSEQUENCE    29
#define MMS_CONFIRMEDSERVICE_UPLOADSEGMENT    30
#define MMS_CONFIRMEDSERVICE_TERMINATEUPLOADSEQUENCE    31
#define MMS_CONFIRMEDSERVICE_REQUESTDOMAINDOWNLOAD    32
#define MMS_CONFIRMEDSERVICE_REQUESTDOMAINUPLOAD    33
#define MMS_CONFIRMEDSERVICE_LOADDOMAINCONTENT    34
#define MMS_CONFIRMEDSERVICE_STOREDOMAINCONTENT    35
#define MMS_CONFIRMEDSERVICE_DELETEDOMAIN    36
#define MMS_CONFIRMEDSERVICE_GETDOMAINATTRIBUTES    37
#define MMS_CONFIRMEDSERVICE_CREATEPROGRAMINVOCATION    38
#define MMS_CONFIRMEDSERVICE_DELETEPROGRAMINVOCATION    39
#define MMS_CONFIRMEDSERVICE_START    40
#define MMS_CONFIRMEDSERVICE_STOP    41
#define MMS_CONFIRMEDSERVICE_RESUME    42
#define MMS_CONFIRMEDSERVICE_RESET    43
#define MMS_CONFIRMEDSERVICE_KILL    44
#define MMS_CONFIRMEDSERVICE_GETPROGRAMINVOCATIONATTRIBUTES    45
#define MMS_CONFIRMEDSERVICE_OBTAINFILE    46
#define MMS_CONFIRMEDSERVICE_DEFINEEVENTCONDITION    47
#define MMS_CONFIRMEDSERVICE_DELETEEVENTCONDITION    48
#define MMS_CONFIRMEDSERVICE_GETEVENTCONDITIONATTRIBUTES    49
#define MMS_CONFIRMEDSERVICE_REPORTEVENTCONDITIONSTATUS    50
#define MMS_CONFIRMEDSERVICE_ALTEREVENTCONDITIONMONITORING    51
#define MMS_CONFIRMEDSERVICE_TRIGGEREVENT    52
#define MMS_CONFIRMEDSERVICE_DEFINEEVENTACTION    53
#define MMS_CONFIRMEDSERVICE_DELETEEVENTACTION    54
#define MMS_CONFIRMEDSERVICE_GETEVENTACTIONATTRIBUTES    55
#define MMS_CONFIRMEDSERVICE_REPORTEVENTACTIONSTATUS    56
#define MMS_CONFIRMEDSERVICE_DEFINEEVENTENROLLMENT    57
#define MMS_CONFIRMEDSERVICE_DELETEEVENTENROLLMENT    58
#define MMS_CONFIRMEDSERVICE_ALTEREVENTENROLLMENT    59
#define MMS_CONFIRMEDSERVICE_REPORTEVENTENROLLMENTSTATUS    60
#define MMS_CONFIRMEDSERVICE_GETEVENTENROLLMENTATTRIBUTES    61
#define MMS_CONFIRMEDSERVICE_ACKNOWLEDGEEVENTNOTIFICATION    62
#define MMS_CONFIRMEDSERVICE_GETALARMSUMMARY    63
#define MMS_CONFIRMEDSERVICE_GETALARMENROLLMENTSUMMARY    64
#define MMS_CONFIRMEDSERVICE_READJOURNAL    65
#define MMS_CONFIRMEDSERVICE_WRITEJOURNAL    66
#define MMS_CONFIRMEDSERVICE_INITIALIZEJOURNAL    67
#define MMS_CONFIRMEDSERVICE_REPORTJOURNALSTATUS    68
#define MMS_CONFIRMEDSERVICE_CREATEJOURNAL    69
#define MMS_CONFIRMEDSERVICE_DELETEJOURNAL    70
#define MMS_CONFIRMEDSERVICE_GETCAPABILITYLIST    71
#define MMS_CONFIRMEDSERVICE_FILEOPEN    72
#define MMS_FILEREAD    73
#define MMS_FILECLOSE    74
#define MMS_FILERENAME    75
#define MMS_FILEDELETE    76
#define MMS_FILEDIRECTORY    77

#define MMS_OBJECTCLASS_NAMMEDVARIABLE 0
#define MMS_OBJECTCLASS_NAMEDVARIABLELIST 2
#define MMS_OBJECTCLASS_DOMAIN 9

#define MMS_OBJECTSCOPE_VMDSPECIFIC 0
#define MMS_OBJECTSCOPE_DOMAINSPECIFIC 1

#define MMS_IEC_61850_CONF_SERV_PDU_NOT_SET 0
#define MMS_IEC_61850_CONF_SERV_PDU_GET_SERV_DIR 1
#define MMS_IEC_61850_CONF_SERV_PDU_GETLOGICALDEVICEDIRECTORY 2
#define MMS_IEC_61850_CONF_SERV_PDU_GETDATASETDIRECTORY 3
#define MMS_IEC_61850_CONF_SERV_PDU_GETDATADIRECTORY 4
#define MMS_IEC_61850_CONF_SERV_PDU_SELECTWITHVALUE 5
#define MMS_IEC_61850_CONF_SERV_PDU_READ 6
#define MMS_IEC_61850_CONF_SERV_PDU_WRITE 7

typedef struct mms_actx_private_data_t
{
    int mms_pdu_type;                               /* MMSpdu type taken from MMSpdu CHOICE branch_taken */
    int invokeid;
    iec61850_8_1_vmd_specific vmd_specific;         /* Numeric representation of decode vmd_specific strings */
    int listOfAccessResult_cnt;                     /* Position in the list, 1 count */
    int data_cnt;                                   /* Number of times data occurred(depth)*/
    uint16_t reported_optflds;                       /* Bitmap over included fields */
    proto_item* pdu_item;                           /* The item to append PDU info to */
    int confirmedservice_type;                      /* Requested service */
    int objectclass;
    int objectscope;
    mms_transaction_t* mms_trans_p;                 /* Pointer to the transaction record */
    char* itemid_str;
    int success;                                    /* If variable access succeeded or not */
} mms_actx_private_data_t;


static const value_string mms_iec6150_cntmodel_vals[] = {
    {0, "status-only"},
    {1, "direct-with-normal-security"},
    {2, "sbo-with-normal-security"},
    {3, "direct-with-enhanced-security"},
    {4, "sbo-with-enhanced-security"},
    {0, NULL}
};

static const value_string mms_iec6150_validity_vals[] = {
    {0, "Good"},
    {1, "Invalid"},
    {2, "Reserved"},
    {3, "Questionable"},
    {0, NULL}
};

static const value_string mms_iec6150_source_vals[] = {
    {0, "Process"},
    {1, "Substituted"},
    {0, NULL}
};

static const value_string mms_iec6150_timeaccuracy_vals[] = {
    {0,  "0 bits accuracy"},
    {1,  "1 bits accuracy"},
    {2,  "2 bits accuracy"},
    {3,  "3 bits accuracy"},
    {4,  "4 bits accuracy"},
    {5,  "5 bits accuracy"},
    {6,  "6 bits accuracy"},
    {7,  "7 bits accuracy"},
    {8,  "8 bits accuracy"},
    {9,  "9 bits accuracy"},
    {10, "10 bits accuracy"},
    {11, "11 bits accuracy"},
    {12, "12 bits accuracy"},
    {13, "13 bits accuracy"},
    {14, "14 bits accuracy"},
    {15, "15 bits accuracy"},
    {16, "16 bits accuracy"},
    {17, "17 bits accuracy"},
    {18, "18 bits accuracy"},
    {19, "19 bits accuracy"},
    {20, "20 bits accuracy"},
    {21, "21 bits accuracy"},
    {22, "22 bits accuracy"},
    {23, "23 bits accuracy"},
    {24, "24 bits accuracy"},
    {25, "25 bits accuracy"},
    {26, "26 bits accuracy"},
    {27, "27 bits accuracy"},
    {28, "28 bits accuracy"},
    {29, "29 bits accuracy"},
    {30, "Invalid"},
    {31, "Unspecified"},
    {0, NULL}
};

static const value_string mms_iec6150_orcategory_vals[] = {
    {0, "not-supported"},
    {1, "bay-control"},
    {2, "station-control"},
    {3, "remote-control"},
    {4, "automatic-bay"},
    {5, "automatic-station"},
    {6, "automatic-station"},
    {7, "maintenance"},
    {8, "process"},
    {0, NULL}
};

static const value_string mms_iec6150_beh_vals[] = {
    {0,"Uninitialised"},
    {1, "on"},
    {2, "blocked"},
    {3, "test"},
    {4, "test/blocked"},
    {5, "off"},
    {0, NULL}
};

static const value_string mms_iec6150_health_vals[] = {
    {0,"Uninitialised"},
    {1,"Ok"},
    {2,"Warning"},
    {3,"Alarm"},
    {0, NULL}
};

/* Helper function to get or create the private data struct */
static
mms_private_data_t* mms_get_private_data(asn1_ctx_t* actx)
{
    packet_info* pinfo = actx->pinfo;
    mms_private_data_t* private_data = (mms_private_data_t*)p_get_proto_data(pinfo->pool, pinfo, proto_mms, pinfo->curr_layer_num);
    if (private_data != NULL) {
        return private_data;
    } else {
        private_data = wmem_new0(pinfo->pool, mms_private_data_t);
        p_add_proto_data(pinfo->pool, pinfo, proto_mms, pinfo->curr_layer_num, private_data);
        return private_data;
    }
}

/* Helper function to test presence of private data struct */
static bool
mms_has_private_data(asn1_ctx_t* actx)
{
    packet_info* pinfo = actx->pinfo;
    return (p_get_proto_data(pinfo->pool, pinfo, proto_mms, pinfo->curr_layer_num) != NULL);
}

static void
private_data_add_preCinfo(asn1_ctx_t* actx, uint32_t val)
{
    mms_private_data_t* private_data = (mms_private_data_t*)mms_get_private_data(actx);
    snprintf(private_data->preCinfo, BUFFER_SIZE_PRE, "%02d ", val);
}

static char*
private_data_get_preCinfo(asn1_ctx_t* actx)
{
    mms_private_data_t* private_data = (mms_private_data_t*)mms_get_private_data(actx);
    return private_data->preCinfo;
}

static void
private_data_add_moreCinfo_id(asn1_ctx_t* actx, tvbuff_t* tvb)
{
    mms_private_data_t* private_data = (mms_private_data_t*)mms_get_private_data(actx);
    (void)g_strlcat(private_data->moreCinfo, " ", BUFFER_SIZE_MORE);
    (void)g_strlcat(private_data->moreCinfo, tvb_get_string_enc(actx->pinfo->pool, tvb,
        0, tvb_reported_length(tvb), ENC_ASCII | ENC_NA), BUFFER_SIZE_MORE);
}

static void
private_data_add_moreCinfo_float(asn1_ctx_t* actx, tvbuff_t* tvb)
{
    mms_private_data_t* private_data = (mms_private_data_t*)mms_get_private_data(actx);
    snprintf(private_data->moreCinfo, BUFFER_SIZE_MORE,
        " %f", tvb_get_ieee_float(tvb, 1, ENC_BIG_ENDIAN));
}

static char*
private_data_get_moreCinfo(asn1_ctx_t* actx)
{
    mms_private_data_t* private_data = (mms_private_data_t*)mms_get_private_data(actx);
    return private_data->moreCinfo;
}

/*****************************************************************************/


/*--- Cyclic dependencies ---*/

/* TypeSpecification -> TypeSpecification/array -> TypeSpecification */
/* TypeSpecification -> TypeSpecification/structure -> TypeSpecification/structure/components -> TypeSpecification/structure/components/_item -> TypeSpecification */
static int dissect_mms_TypeSpecification(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* VariableSpecification -> ScatteredAccessDescription -> ScatteredAccessDescription/_item -> VariableSpecification */
static int dissect_mms_VariableSpecification(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* AlternateAccess -> AlternateAccess/_item -> AlternateAccessSelection -> AlternateAccessSelection/selectAlternateAccess -> AlternateAccess */
static int dissect_mms_AlternateAccess(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* Data -> Data/array -> Data */
/* Data -> Data/structure -> Data */
static int dissect_mms_Data(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);



static int * const ReportedOptFlds_bits[] = {
  &hf_mms_ReportedOptFlds_reserved,
  &hf_mms_ReportedOptFlds_sequence_number,
  &hf_mms_ReportedOptFlds_report_time_stamp,
  &hf_mms_ReportedOptFlds_reason_for_inclusion,
  &hf_mms_ReportedOptFlds_data_set_name,
  &hf_mms_ReportedOptFlds_data_reference,
  &hf_mms_ReportedOptFlds_buffer_overflow,
  &hf_mms_ReportedOptFlds_entryID,
  &hf_mms_ReportedOptFlds_conf_revision,
  &hf_mms_ReportedOptFlds_segmentation,
  NULL
};

static int
dissect_mms_ReportedOptFlds(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    tvbuff_t *parameter_tvb = NULL;
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    ReportedOptFlds_bits, 10, hf_index, ett_mms_ReportedOptFlds,
                                    &parameter_tvb);

    mms_actx_private_data_t *mms_priv = (mms_actx_private_data_t *)actx->private_data;
    if(mms_priv && parameter_tvb){
        mms_priv->reported_optflds = tvb_get_ntohs(parameter_tvb,0);
    }


  return offset;
}



static int
dissect_mms_Unsigned32(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    uint32_t  val;
    conversation_t *conversation;
    mms_conv_info_t *mms_info;
    mms_transaction_t *mms_trans;

  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &val);

    if (hf_index == hf_mms_invokeID){
        mms_actx_private_data_t* mms_priv = (mms_actx_private_data_t*)actx->private_data;
        if(mms_priv){
            mms_priv->invokeid=val;
            private_data_add_preCinfo(actx, val);
            conversation = find_or_create_conversation(actx->pinfo);

            mms_info = (mms_conv_info_t *)conversation_get_proto_data(conversation, proto_mms);
            if (!mms_info) {
                /*
                 * No.  Attach that information to the conversation, and add
                 * it to the list of information structures.
                 */
                mms_info = wmem_new(wmem_file_scope(), mms_conv_info_t);
                mms_info->pdus=wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);

                conversation_add_proto_data(conversation, proto_mms, mms_info);
            }
            /* Request or response? */
            bool is_request;

            switch(mms_priv->mms_pdu_type){
                case 0:
                    /* Confirmed-RequestPDU */
                    is_request = true;
                    break;
                case 1:
                    /* confirmed-ResponsePDU */
                    is_request = false;
                    break;
                case 2:
                    /* Confirmed-ErrorPDU */
                    is_request = false;
                    break;
                default:
                    is_request = false;
                    break;
            }

            if (!PINFO_FD_VISITED(actx->pinfo)) {
                if (is_request==true) {
                    /* This is a request */
                    mms_trans=wmem_new0(wmem_file_scope(), mms_transaction_t);
                    mms_trans->req_frame = actx->pinfo->num;
                    mms_trans->req_time = actx->pinfo->fd->abs_ts;
                    wmem_map_insert(mms_info->pdus, GUINT_TO_POINTER(mms_priv->invokeid), (void *)mms_trans);
                } else {
                    mms_trans=(mms_transaction_t *)wmem_map_lookup(mms_info->pdus, GUINT_TO_POINTER(mms_priv->invokeid));
                    if (mms_trans) {
                        mms_trans->rep_frame = actx->pinfo->num;
                    }
                }
            } else {
                mms_trans=(mms_transaction_t *)wmem_map_lookup(mms_info->pdus, GUINT_TO_POINTER(mms_priv->invokeid));
            }
            if (!mms_trans) {
                /* create a "fake" mms_trans structure */
                mms_trans=wmem_new0(actx->pinfo->pool, mms_transaction_t);
                mms_trans->req_frame = 0;
                mms_trans->rep_frame = 0;
                mms_trans->req_time = actx->pinfo->fd->abs_ts;
            }
            mms_priv->mms_trans_p = mms_trans;

            /* print state tracking in the tree */
            if (is_request) {
                    /* This is a request */
                    if (mms_trans->rep_frame) {
                            proto_item *it;

                            it = proto_tree_add_uint(actx->subtree.top_tree, hf_mms_response_in, tvb, 0, 0, mms_trans->rep_frame);
                            proto_item_set_generated(it);
                    }
            } else {
                /* This is a reply */
                if (mms_trans->req_frame) {
                        proto_item *it;
                        nstime_t ns;

                        it = proto_tree_add_uint(actx->subtree.top_tree, hf_mms_response_to, tvb, 0, 0, mms_trans->req_frame);
                        proto_item_set_generated(it);

                        nstime_delta(&ns, &actx->pinfo->fd->abs_ts, &mms_trans->req_time);
                        it = proto_tree_add_time(actx->subtree.top_tree, hf_mms_response_time, tvb, 0, 0, &ns);
                        proto_item_set_generated(it);
                }
            }
        }
    }


  return offset;
}



static int
dissect_mms_Identifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    tvbuff_t *parameter_tvb = NULL;
    mms_actx_private_data_t *mms_priv = (mms_actx_private_data_t *)actx->private_data;

  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_VisibleString,
                                            actx, tree, tvb, offset, hf_index,
                                            &parameter_tvb);

    if (parameter_tvb) {
        if (hf_index == hf_mms_domainId) {
                private_data_add_moreCinfo_id(actx,parameter_tvb);
        }
        if ((mms_priv) && ((hf_index == hf_mms_objectName_domain_specific_itemId)||
                (hf_index ==hf_mms_listOfIdentifier_item))) {
            private_data_add_moreCinfo_id(actx,parameter_tvb);
            if((mms_priv->mms_trans_p)&&(parameter_tvb)){
                mms_priv->itemid_str = tvb_get_string_enc(actx->pinfo->pool, parameter_tvb, 0, tvb_reported_length(parameter_tvb), ENC_ASCII|ENC_NA);
                if(g_str_has_suffix(mms_priv->itemid_str,"$ctlModel")){
                    mms_priv->mms_trans_p->itemid = IEC61850_ITEM_ID_CTLMODEL;
                }else  if(g_str_has_suffix(mms_priv->itemid_str,"$q")){
                    mms_priv->mms_trans_p->itemid = IEC61850_ITEM_ID_Q;
                }else if(g_str_has_suffix(mms_priv->itemid_str,"$Oper")){
                    mms_priv->mms_trans_p->itemid = IEC61850_ITEM_ID_OPER;
                 }else if((g_str_has_suffix(mms_priv->itemid_str,"$Oper$Check")) || (g_str_has_suffix(mms_priv->itemid_str,"$SBOw$Check"))){
                     mms_priv->mms_trans_p->itemid = IEC61850_ITEM_ID_CHECK;
                 }else if(g_str_has_suffix(mms_priv->itemid_str,"$orCat")){
                     mms_priv->mms_trans_p->itemid = IEC61850_ITEM_ID_OR_CAT;
                 }else if(g_str_has_suffix(mms_priv->itemid_str,"Beh$stVal")){
                    mms_priv->mms_trans_p->itemid = IEC61850_ITEM_ID_BEH$STVAL;
                 }else if(g_str_has_suffix(mms_priv->itemid_str,"Mod$stVal")){
                    mms_priv->mms_trans_p->itemid = IEC61850_ITEM_ID_MOD$STVAL;
                 }else if(g_str_has_suffix(mms_priv->itemid_str,"Health$stVal")){
                    mms_priv->mms_trans_p->itemid = IEC61850_ITEM_ID_HEALTH$STVAL;
                 }else if((g_strrstr(mms_priv->itemid_str,"$BR$") || g_strrstr(mms_priv->itemid_str,"$RP$"))){ //GetBRCBValues,GetURCBValues,)
                    mms_priv->mms_trans_p->itemid = IEC61850_ITEM_ID_$BR$_OR_$RP$;
                 }else if(g_str_has_suffix(mms_priv->itemid_str,"$SBOw")){
                    mms_priv->mms_trans_p->itemid = IEC61850_ITEM_ID_$SBOW;
                    mms_priv->mms_trans_p->conf_serv_pdu_type_req = MMS_IEC_61850_CONF_SERV_PDU_SELECTWITHVALUE;
                 }
            }
        }

        if ((mms_priv) && (hf_index == hf_mms_vmd_specific)){
            const char *vmd_specific_str = tvb_get_string_enc(actx->pinfo->pool, parameter_tvb, 0, tvb_reported_length(parameter_tvb), ENC_ASCII|ENC_NA);
            if (strcmp(vmd_specific_str, "RPT") == 0) {
                    mms_priv->vmd_specific = IEC61850_8_1_RPT;
            }
        }
    }


  return offset;
}



static int
dissect_mms_ObjectName_domain_specific_itemid(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Identifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t T_domain_specific_sequence[] = {
  { &hf_mms_domainId        , BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_mms_Identifier },
  { &hf_mms_objectName_domain_specific_itemId, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_mms_ObjectName_domain_specific_itemid },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_domain_specific(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_ObjectName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ObjectName_choice, hf_index, ett_mms_ObjectName,
                                 NULL);

  return offset;
}


static int * const Transitions_bits[] = {
  &hf_mms_Transitions_idle_to_disabled,
  &hf_mms_Transitions_active_to_disabled,
  &hf_mms_Transitions_disabled_to_idle,
  &hf_mms_Transitions_active_to_idle,
  &hf_mms_Transitions_disabled_to_active,
  &hf_mms_Transitions_idle_to_active,
  &hf_mms_Transitions_any_to_deleted,
  NULL
};

static int
dissect_mms_Transitions(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    Transitions_bits, 7, hf_index, ett_mms_Transitions,
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
dissect_mms_AttachToEventCondition(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttachToEventCondition_sequence, hf_index, ett_mms_AttachToEventCondition);

  return offset;
}



static int
dissect_mms_Unsigned8(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_mms_Priority(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Unsigned8(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_mms_BOOLEAN(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_AttachToSemaphore(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_Modifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Modifier_choice, hf_index, ett_mms_Modifier,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Modifier_sequence_of[1] = {
  { &hf_mms_listOfModifier_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_Modifier },
};

static int
dissect_mms_SEQUENCE_OF_Modifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Modifier_sequence_of, hf_index, ett_mms_SEQUENCE_OF_Modifier);

  return offset;
}



static int
dissect_mms_Status_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const value_string mms_ObjectClass_vals[] = {
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
dissect_mms_ObjectClass(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    uint32_t  val;

  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &val);

        mms_actx_private_data_t *mms_priv = (mms_actx_private_data_t *)actx->private_data;
        if(mms_priv){
            mms_priv->objectclass = val;
        }


  return offset;
}


static const value_string mms_T_extendedObjectClass_vals[] = {
  {   0, "objectClass" },
  { 0, NULL }
};

static const ber_choice_t T_extendedObjectClass_choice[] = {
  {   0, &hf_mms_objectClass     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_ObjectClass },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_extendedObjectClass(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_extendedObjectClass_choice, hf_index, ett_mms_T_extendedObjectClass,
                                 NULL);

  return offset;
}



static int
dissect_mms_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string mms_ObjectScope_vals[] = {
  {   0, "vmdSpecific" },
  {   1, "domainSpecific" },
  {   2, "aaSpecific" },
  { 0, NULL }
};

static const ber_choice_t ObjectScope_choice[] = {
  {   0, &hf_mms_vmdSpecific     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_NULL },
  {   1, &hf_mms_domainSpecific  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  {   2, &hf_mms_aaSpecific      , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_ObjectScope(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    int  val;

  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ObjectScope_choice, hf_index, ett_mms_ObjectScope,
                                 &val);

        mms_actx_private_data_t *mms_priv = (mms_actx_private_data_t *)actx->private_data;
        if(mms_priv){
            mms_priv->objectscope = val;
        }


  return offset;
}


static const ber_sequence_t GetNameList_Request_sequence[] = {
  { &hf_mms_extendedObjectClass, BER_CLASS_CON, 0, 0, dissect_mms_T_extendedObjectClass },
  { &hf_mms_objectScope     , BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectScope },
  { &hf_mms_getNameList_Request_continueAfter, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_GetNameList_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetNameList_Request_sequence, hf_index, ett_mms_GetNameList_Request);

  return offset;
}



static int
dissect_mms_Identify_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string mms_T_objectClass_vals[] = {
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
dissect_mms_T_objectClass(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string mms_T_extendedObjectClass_01_vals[] = {
  {   0, "objectClass" },
  { 0, NULL }
};

static const ber_choice_t T_extendedObjectClass_01_choice[] = {
  {   0, &hf_mms_objectClass_01  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_T_objectClass },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_extendedObjectClass_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_Rename_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Rename_Request_sequence, hf_index, ett_mms_Rename_Request);

  return offset;
}



static int
dissect_mms_VisibleString(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_VisibleString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_mms_OCTET_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_Address(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_array(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_components_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_components_item_sequence, hf_index, ett_mms_T_components_item);

  return offset;
}


static const ber_sequence_t T_components_sequence_of[1] = {
  { &hf_mms_components_item , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_mms_T_components_item },
};

static int
dissect_mms_T_components(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_structure(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_structure_sequence, hf_index, ett_mms_T_structure);

  return offset;
}



static int
dissect_mms_Integer32(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
  {   4, &hf_mms_typeSpecification_bit_string, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_mms_Integer32 },
  {   5, &hf_mms_integer         , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned8 },
  {   6, &hf_mms_unsigned        , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned8 },
  {   9, &hf_mms_typeSpecification_octet_string, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_mms_Integer32 },
  {  10, &hf_mms_typeSpecification_visible_string, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_mms_Integer32 },
  {  11, &hf_mms_generalized_time, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_mms_NULL },
  {  12, &hf_mms_typeSpecification_binary_time, BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  {  13, &hf_mms_bcd             , BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned8 },
  {  15, &hf_mms_objId           , BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_mms_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_TypeSpecification(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  // TypeSpecification -> TypeSpecification/array -> TypeSpecification
  actx->pinfo->dissection_depth += 2;
  increment_dissection_depth(actx->pinfo);
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 TypeSpecification_choice, hf_index, ett_mms_TypeSpecification,
                                 NULL);

  actx->pinfo->dissection_depth -= 2;
  decrement_dissection_depth(actx->pinfo);
  return offset;
}


static const ber_sequence_t T_variableDescription_sequence[] = {
  { &hf_mms_address         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_Address },
  { &hf_mms_typeSpecification, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_TypeSpecification },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_variableDescription(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_indexRange(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_accessSelection(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_selectAlternateAccess(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_indexRange_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_selectAccess(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_AlternateAccessSelection(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_named(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_AlternateAccess_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AlternateAccess_item_choice, hf_index, ett_mms_AlternateAccess_item,
                                 NULL);

  return offset;
}


static const ber_sequence_t AlternateAccess_sequence_of[1] = {
  { &hf_mms_AlternateAccess_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_AlternateAccess_item },
};

static int
dissect_mms_AlternateAccess(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  // AlternateAccess -> AlternateAccess/_item -> AlternateAccessSelection -> AlternateAccessSelection/selectAlternateAccess -> AlternateAccess
  actx->pinfo->dissection_depth += 4;
  increment_dissection_depth(actx->pinfo);
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      AlternateAccess_sequence_of, hf_index, ett_mms_AlternateAccess);

  actx->pinfo->dissection_depth -= 4;
  decrement_dissection_depth(actx->pinfo);
  return offset;
}


static const ber_sequence_t ScatteredAccessDescription_item_sequence[] = {
  { &hf_mms_componentName   , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { &hf_mms_variableSpecification, BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_mms_VariableSpecification },
  { &hf_mms_alternateAccess , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_AlternateAccess },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_ScatteredAccessDescription_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ScatteredAccessDescription_item_sequence, hf_index, ett_mms_ScatteredAccessDescription_item);

  return offset;
}


static const ber_sequence_t ScatteredAccessDescription_sequence_of[1] = {
  { &hf_mms_ScatteredAccessDescription_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_mms_ScatteredAccessDescription_item },
};

static int
dissect_mms_ScatteredAccessDescription(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_VariableSpecification(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  // VariableSpecification -> ScatteredAccessDescription -> ScatteredAccessDescription/_item -> VariableSpecification
  actx->pinfo->dissection_depth += 3;
  increment_dissection_depth(actx->pinfo);
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 VariableSpecification_choice, hf_index, ett_mms_VariableSpecification,
                                 NULL);

  actx->pinfo->dissection_depth -= 3;
  decrement_dissection_depth(actx->pinfo);
  return offset;
}


static const ber_sequence_t T_listOfVariable_item_02_sequence[] = {
  { &hf_mms_variableSpecification, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_VariableSpecification },
  { &hf_mms_alternateAccess , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_AlternateAccess },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_listOfVariable_item_02(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_listOfVariable_item_02_sequence, hf_index, ett_mms_T_listOfVariable_item_02);

  return offset;
}


static const ber_sequence_t T_listOfVariable_02_sequence_of[1] = {
  { &hf_mms_listOfVariable_item_02, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_mms_T_listOfVariable_item_02 },
};

static int
dissect_mms_T_listOfVariable_02(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_VariableAccessSpecification(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_Read_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Read_Request_sequence, hf_index, ett_mms_Read_Request);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Data_sequence_of[1] = {
  { &hf_mms_array_item      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_Data },
};

static int
dissect_mms_SEQUENCE_OF_Data(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Data_sequence_of, hf_index, ett_mms_SEQUENCE_OF_Data);

  return offset;
}


static const ber_sequence_t T_structure_01_sequence_of[1] = {
  { &hf_mms_structure_item  , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_Data },
};

static int
dissect_mms_T_structure_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    mms_actx_private_data_t *mms_priv = (mms_actx_private_data_t *)actx->private_data;
    if((mms_priv)&& (mms_priv->mms_trans_p)){
        if(mms_priv->mms_trans_p->conf_serv_pdu_type_req == MMS_IEC_61850_CONF_SERV_PDU_SELECTWITHVALUE){
            if(mms_priv->data_cnt == 3){
                /* IEC 61850-8-1 origin, if we hgave a struct here Tm was not there */
                hf_index = hf_mms_iec61850_origin;
                mms_priv->data_cnt++;
            }else if(mms_priv->data_cnt == 4){
                /* IEC 61850-8-1 origin, if we hgave a struct here Tm was not there */
                hf_index = hf_mms_iec61850_origin;
            }
        }
    }
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_structure_01_sequence_of, hf_index, ett_mms_T_structure_01);



  return offset;
}



static int
dissect_mms_T_boolean(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    mms_actx_private_data_t *mms_priv = (mms_actx_private_data_t *)actx->private_data;
    if((mms_priv) && (mms_priv->mms_trans_p)){
        if(mms_priv->vmd_specific == IEC61850_8_1_RPT ){
            if(mms_priv->listOfAccessResult_cnt == 6){
                /* IEC 61850-8-1 BufOvfl */
                hf_index = hf_mms_iec61850_bufovfl;
            }
        }else if(mms_priv->mms_trans_p->conf_serv_pdu_type_req == MMS_IEC_61850_CONF_SERV_PDU_SELECTWITHVALUE){
            if(mms_priv->data_cnt == 2){
                /* IEC 61850-8-1 ctlVal */
                hf_index = hf_mms_iec61850_ctlval;
            }else if(mms_priv->data_cnt == 9){
                /* IEC 61850-8-1 Test */
                hf_index = hf_mms_iec61850_test;
            }
        }
    }
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);



  return offset;
}



static int
dissect_mms_T_data_bit_string(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

static int* const quality_field_bits_oct1[] = {
    &hf_mms_iec61850_QualityC0,
    &hf_mms_iec61850_Quality20,
    &hf_mms_iec61850_Quality10,
    &hf_mms_iec61850_Quality8,
    &hf_mms_iec61850_Quality4,
    &hf_mms_iec61850_Quality2,
    &hf_mms_iec61850_Quality1,
    NULL
};

static int* const quality_field_bits_oct2[] = {
    &hf_mms_iec61850_Quality0080,
    &hf_mms_iec61850_Quality0040,
    &hf_mms_iec61850_Quality0020,
    &hf_mms_iec61850_Quality0010,
    &hf_mms_iec61850_Quality0008,
    NULL
};

static int * const mms_iec61850_chec_bits[] = {
    &hf_mms_iec61850_check_b1,
    &hf_mms_iec61850_check_b0,
    NULL
};
    tvbuff_t *parameter_tvb = NULL;
    proto_tree *sub_tree;

    mms_actx_private_data_t *mms_priv = (mms_actx_private_data_t *)actx->private_data;
    if((mms_priv)&&(mms_priv->mms_trans_p)){
        if(mms_priv->vmd_specific == IEC61850_8_1_RPT ){
            if(mms_priv->listOfAccessResult_cnt == 2){
                    /* IEC 61850-8-1 Reported OptFlds */
                    return dissect_mms_ReportedOptFlds(implicit_tag, tvb, offset, actx, tree, hf_mms_iec61850_reported_optflds);
            }else{
                if(mms_priv->listOfAccessResult_cnt == 11){
                    hf_index = hf_mms_iec61850_inclusion_bitstring;
                }
            }
        }else if (mms_priv->mms_trans_p->itemid == IEC61850_ITEM_ID_Q){
            hf_index = hf_mms_iec61850_quality_bitstring;
        }else if (mms_priv->mms_trans_p->itemid == IEC61850_ITEM_ID_CHECK){
            hf_index = hf_mms_iec61850_check_bitstring;
        }else if(mms_priv->mms_trans_p->conf_serv_pdu_type_req == MMS_IEC_61850_CONF_SERV_PDU_SELECTWITHVALUE){
            if(mms_priv->data_cnt == 10){
                hf_index = hf_mms_iec61850_check_bitstring;
            }
        }
    }

  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
                                    &parameter_tvb);


    if((mms_priv)&&(parameter_tvb) && (mms_priv->mms_trans_p)){
        if(mms_priv->mms_trans_p->itemid == IEC61850_ITEM_ID_Q){
            sub_tree = proto_item_add_subtree(actx->created_item, ett_mms_iec61850_quality_bitstring);
            proto_tree_add_bitmask_list(sub_tree, parameter_tvb, 0, 1, quality_field_bits_oct1, ENC_NA);
            proto_tree_add_bitmask_list(sub_tree, parameter_tvb, 1, 1, quality_field_bits_oct2, ENC_NA);
        }else if (mms_priv->mms_trans_p->itemid == IEC61850_ITEM_ID_CHECK){
            sub_tree = proto_item_add_subtree(actx->created_item, ett_mms_iec61850_check_bitstring);
            proto_tree_add_bitmask_list(sub_tree, parameter_tvb, 0, 1, mms_iec61850_chec_bits, ENC_NA);
        }else if(mms_priv->mms_trans_p->conf_serv_pdu_type_req == MMS_IEC_61850_CONF_SERV_PDU_SELECTWITHVALUE){
            if(mms_priv->data_cnt == 10){
                sub_tree = proto_item_add_subtree(actx->created_item, ett_mms_iec61850_check_bitstring);
                proto_tree_add_bitmask_list(sub_tree, parameter_tvb, 0, 1, mms_iec61850_chec_bits, ENC_NA);
            }
        }
    }


  return offset;
}



static int
dissect_mms_T_integer(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    mms_actx_private_data_t *mms_priv = (mms_actx_private_data_t *)actx->private_data;
    if((mms_priv) && (mms_priv->mms_trans_p)){
        if(mms_priv->mms_trans_p->itemid == IEC61850_ITEM_ID_CTLMODEL){
            hf_index = hf_mms_iec61850_ctlModel;
        }else if(mms_priv->mms_trans_p->itemid == IEC61850_ITEM_ID_OR_CAT){
            hf_index = hf_mms_iec61850_orcategory;
        }else if(mms_priv->mms_trans_p->itemid == IEC61850_ITEM_ID_BEH$STVAL){
            hf_index = hf_mms_iec61850_beh$stval;
        }else if(mms_priv->mms_trans_p->itemid == IEC61850_ITEM_ID_MOD$STVAL){
            hf_index = hf_mms_iec61850_beh$stval;
        }else if(mms_priv->mms_trans_p->itemid == IEC61850_ITEM_ID_HEALTH$STVAL){
            hf_index = hf_mms_iec61850_health$stval;
        }else if(mms_priv->mms_trans_p->conf_serv_pdu_type_req == MMS_IEC_61850_CONF_SERV_PDU_SELECTWITHVALUE){
            if(mms_priv->data_cnt == 5){
                /* IEC 61850-8-1 Origin Catagory */
                hf_index = hf_mms_iec61850_origin_orcat;
            }
        }
    }

  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);



  return offset;
}



static int
dissect_mms_T_unsigned(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    mms_actx_private_data_t *mms_priv = (mms_actx_private_data_t *)actx->private_data;
    if((mms_priv) && (mms_priv->mms_trans_p)){
        if(mms_priv->vmd_specific == IEC61850_8_1_RPT ){
            if(mms_priv->listOfAccessResult_cnt == 3){
                    /* IEC 61850-8-1 SeqNum */
                    hf_index = hf_mms_iec61850_seqnum;
            }else if(mms_priv->listOfAccessResult_cnt == 8){
                    /* IEC 61850-8-1 ConfRev */
                    hf_index = hf_mms_iec61850_confrev;
            }
        }
        if(mms_priv->mms_trans_p->conf_serv_pdu_type_req == MMS_IEC_61850_CONF_SERV_PDU_SELECTWITHVALUE){
            if(mms_priv->data_cnt == 7){
                hf_index = hf_mms_iec61850_ctlNum;
            }
        }
    }
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);



  return offset;
}



static int
dissect_mms_FloatingPoint(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

        private_data_add_moreCinfo_float(actx, tvb);


  return offset;
}



static int
dissect_mms_T_data_octet_string(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    mms_actx_private_data_t *mms_priv = (mms_actx_private_data_t *)actx->private_data;
    if((mms_priv)&& (mms_priv->mms_trans_p)){
        if(mms_priv->mms_trans_p->conf_serv_pdu_type_req == MMS_IEC_61850_CONF_SERV_PDU_SELECTWITHVALUE){
            if(mms_priv->data_cnt == 6){
                hf_index = hf_mms_iec61850_origin_orident;
            }
        }
    }
      offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);



  return offset;
}



static int
dissect_mms_T_data_visible_string(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

    mms_actx_private_data_t *mms_priv = (mms_actx_private_data_t *)actx->private_data;
    if(mms_priv){
        if(mms_priv->vmd_specific == IEC61850_8_1_RPT ){
            if(mms_priv->listOfAccessResult_cnt == 1){
                    /* IEC 61850-8-1 RptID */
                    hf_index = hf_mms_iec61850_rptid;
            }else if(mms_priv->listOfAccessResult_cnt == 5){
                    /* IEC 61850-8-1 DatSet */
                    hf_index = hf_mms_iec61850_datset;
            }
        }
    }
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_VisibleString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);



  return offset;
}



static int
dissect_mms_TimeOfDay(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

        uint32_t  len;
        uint32_t  milliseconds;
        uint16_t  days;
        char *	ptime;
        nstime_t ts;

        len = tvb_reported_length_remaining(tvb, offset);

        if(len == 4)
        {
                milliseconds = tvb_get_ntohl(tvb, offset);
                ptime = signed_time_msecs_to_str(actx->pinfo->pool, milliseconds);

                if(hf_index > 0)
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

                ptime = abs_time_to_str(actx->pinfo->pool, &ts, ABSOLUTE_TIME_UTC, true);
                if(hf_index > 0)
                {
                        proto_tree_add_string(tree, hf_index, tvb, offset, len, ptime);
                }

                return offset;
        }

        proto_tree_add_expert_format(tree, actx->pinfo, &ei_mms_mal_timeofday_encoding,
                        tvb, offset, len, "BER Error: malformed TimeOfDay encoding, length must be 4 or 6 bytes");
        if(hf_index > 0)
        {
                proto_tree_add_string(tree, hf_index, tvb, offset, len, "????");
        }


  return offset;
}



static int
dissect_mms_T_data_binary_time(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    mms_actx_private_data_t *mms_priv = (mms_actx_private_data_t *)actx->private_data;
    if(mms_priv){
        if(mms_priv->vmd_specific == IEC61850_8_1_RPT ){
            if(mms_priv->listOfAccessResult_cnt == 4){
                    /* IEC 61850-8-1 TimeOfEntry */
                    hf_index = hf_mms_iec61850_timeofentry;
            }
        }
    }
  offset = dissect_mms_TimeOfDay(implicit_tag, tvb, offset, actx, tree, hf_index);



  return offset;
}



static int
dissect_mms_INTEGER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_mms_BIT_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
                                    NULL);

  return offset;
}



static int
dissect_mms_OBJECT_IDENTIFIER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_mms_MMSString(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_mms_UtcTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

        uint32_t  len;
        uint32_t  seconds;
        uint32_t  fraction;
        uint32_t  nanoseconds;
        nstime_t  ts;
        char *   ptime;

    static int * const TimeQuality_bits[] = {
        &hf_mms_iec61850_timequality80,
        &hf_mms_iec61850_timequality40,
        &hf_mms_iec61850_timequality20,
        &hf_mms_iec61850_timequality1F,
        NULL
    };
        len = tvb_reported_length_remaining(tvb, offset);

        if(len != 8)
        {
                /* The octet format shall be (using ASN.1 bstring notation):
                 *  ‘ssssssssssssssssssssssssssssssssffffffffffffffffffffffffqqqqqqqq’B
                 *  q stands for TimeQuality, i.e. reserved to represent TimeQuality based upon the referencing standard.
                 */
                proto_tree_add_expert_format(tree, actx->pinfo, &ei_mms_mal_utctime_encoding,
                                tvb, offset, len, "BER Error: malformed IEC61850 UTCTime encoding, length must be 8 bytes");
                if(hf_index > 0)
                {
                        proto_tree_add_string(tree, hf_index, tvb, offset, len, "????");
                }
                return offset;
        }

        seconds = tvb_get_ntohl(tvb, offset);
        fraction = tvb_get_ntoh24(tvb, offset+4) * 0x100; /* Only 3 bytes are recommended */
        nanoseconds = (uint32_t )( ((uint64_t)fraction * UINT64_C(1000000000)) / UINT64_C(0x100000000) ) ;

        ts.secs = seconds;
        ts.nsecs = nanoseconds;

        ptime = abs_time_to_str(actx->pinfo->pool, &ts, ABSOLUTE_TIME_UTC, true);

        if(hf_index > 0)
        {
            mms_actx_private_data_t* mms_priv = (mms_actx_private_data_t*)actx->private_data;
            if((mms_priv)&& (mms_priv->mms_trans_p)){
                if(mms_priv->mms_trans_p->conf_serv_pdu_type_req == MMS_IEC_61850_CONF_SERV_PDU_SELECTWITHVALUE){
                    if(mms_priv->data_cnt == 8){
                        hf_index = hf_mms_iec61850_T;
                    }
                }
            }
            proto_tree_add_string(tree, hf_index, tvb, offset, len, ptime);
            proto_tree_add_bitmask_list(tree, tvb, offset+7, 1, TimeQuality_bits, ENC_BIG_ENDIAN);
        }




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
  {   2, &hf_mms_structure_01    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_T_structure_01 },
  {   3, &hf_mms_boolean_01      , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_mms_T_boolean },
  {   4, &hf_mms_data_bit_string , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_mms_T_data_bit_string },
  {   5, &hf_mms_integer_01      , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_mms_T_integer },
  {   6, &hf_mms_unsigned_01     , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_mms_T_unsigned },
  {   7, &hf_mms_floating_point  , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_mms_FloatingPoint },
  {   9, &hf_mms_data_octet_string, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_mms_T_data_octet_string },
  {  10, &hf_mms_data_visible_string, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_mms_T_data_visible_string },
  {  12, &hf_mms_data_binary_time, BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_mms_T_data_binary_time },
  {  13, &hf_mms_bcd_01          , BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_mms_INTEGER },
  {  14, &hf_mms_booleanArray    , BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_mms_BIT_STRING },
  {  15, &hf_mms_objId_01        , BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_mms_OBJECT_IDENTIFIER },
  {  16, &hf_mms_mMSString       , BER_CLASS_CON, 16, BER_FLAGS_IMPLTAG, dissect_mms_MMSString },
  {  17, &hf_mms_utc_time        , BER_CLASS_CON, 17, BER_FLAGS_IMPLTAG, dissect_mms_UtcTime },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_Data(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  // Data -> Data/array -> Data
  actx->pinfo->dissection_depth += 2;
  increment_dissection_depth(actx->pinfo);
    mms_actx_private_data_t *mms_priv = (mms_actx_private_data_t *)actx->private_data;
    if(mms_priv){
        mms_priv->data_cnt += 1;
    }

  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Data_choice, hf_index, ett_mms_Data,
                                 NULL);



  actx->pinfo->dissection_depth -= 2;
  decrement_dissection_depth(actx->pinfo);
  return offset;
}


static const ber_sequence_t T_listOfData_sequence_of[1] = {
  { &hf_mms_listOfData_item , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_Data },
};

static int
dissect_mms_T_listOfData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    mms_actx_private_data_t *mms_priv = (mms_actx_private_data_t *)actx->private_data;
    if(mms_priv){
        mms_priv->data_cnt = 0;
     }
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_listOfData_sequence_of, hf_index, ett_mms_T_listOfData);

    if(mms_priv){
        mms_priv->data_cnt = 0;
     }


  return offset;
}


static const ber_sequence_t Write_Request_sequence[] = {
  { &hf_mms_variableAccessSpecificatn, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_VariableAccessSpecification },
  { &hf_mms_listOfData      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_T_listOfData },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_Write_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_GetVariableAccessAttributes_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_DefineNamedVariable_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_DefineScatteredAccess_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DefineScatteredAccess_Request_sequence, hf_index, ett_mms_DefineScatteredAccess_Request);

  return offset;
}



static int
dissect_mms_GetScatteredAccessAttributes_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_scopeOfDelete(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ObjectName_sequence_of[1] = {
  { &hf_mms_listOfName_item , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
};

static int
dissect_mms_SEQUENCE_OF_ObjectName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_DeleteVariableAccess_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_listOfVariable_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_listOfVariable_item_sequence, hf_index, ett_mms_T_listOfVariable_item);

  return offset;
}


static const ber_sequence_t T_listOfVariable_sequence_of[1] = {
  { &hf_mms_listOfVariable_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_mms_T_listOfVariable_item },
};

static int
dissect_mms_T_listOfVariable(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_DefineNamedVariableList_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DefineNamedVariableList_Request_sequence, hf_index, ett_mms_DefineNamedVariableList_Request);

  return offset;
}



static int
dissect_mms_GetNamedVariableListAttributes_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_scopeOfDelete_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_DeleteNamedVariableList_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_DefineNamedType_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DefineNamedType_Request_sequence, hf_index, ett_mms_DefineNamedType_Request);

  return offset;
}



static int
dissect_mms_GetNamedTypeAttributes_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_scopeOfDelete_02(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_DeleteNamedType_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DeleteNamedType_Request_sequence, hf_index, ett_mms_DeleteNamedType_Request);

  return offset;
}


static const ber_sequence_t T_listOfPromptData_sequence_of[1] = {
  { &hf_mms_listOfPromptData_item, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_mms_VisibleString },
};

static int
dissect_mms_T_listOfPromptData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_Input_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Input_Request_sequence, hf_index, ett_mms_Input_Request);

  return offset;
}


static const ber_sequence_t T_listOfOutputData_sequence_of[1] = {
  { &hf_mms_listOfOutputData_item, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_mms_VisibleString },
};

static int
dissect_mms_T_listOfOutputData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_Output_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Output_Request_sequence, hf_index, ett_mms_Output_Request);

  return offset;
}



static int
dissect_mms_T_ap_title(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
        offset=dissect_acse_AP_title(false, tvb, offset, actx, tree, hf_mms_ap_title);


  return offset;
}



static int
dissect_mms_T_ap_invocation_id(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
        offset=dissect_acse_AP_invocation_identifier(false, tvb, offset, actx, tree, hf_mms_ap_invocation_id);


  return offset;
}



static int
dissect_mms_T_ae_qualifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
        offset=dissect_acse_AE_qualifier(false, tvb, offset, actx, tree, hf_mms_ae_qualifier);


  return offset;
}



static int
dissect_mms_T_ae_invocation_id(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
        offset=dissect_acse_AE_invocation_identifier(false, tvb, offset, actx, tree, hf_mms_ae_invocation_id);


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
dissect_mms_ApplicationReference(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_TakeControl_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_RelinquishControl_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RelinquishControl_Request_sequence, hf_index, ett_mms_RelinquishControl_Request);

  return offset;
}



static int
dissect_mms_Unsigned16(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_DefineSemaphore_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DefineSemaphore_Request_sequence, hf_index, ett_mms_DefineSemaphore_Request);

  return offset;
}



static int
dissect_mms_DeleteSemaphore_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_ObjectName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_mms_ReportSemaphoreStatus_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_ObjectName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t ReportPoolSemaphoreStatus_Request_sequence[] = {
  { &hf_mms_semaphoreName   , BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { &hf_mms_nameToStartAfter, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_ReportPoolSemaphoreStatus_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReportPoolSemaphoreStatus_Request_sequence, hf_index, ett_mms_ReportPoolSemaphoreStatus_Request);

  return offset;
}


static const value_string mms_T_reportSemaphoreEntryStatus_Request_state_vals[] = {
  {   0, "queued" },
  {   1, "owner" },
  {   2, "hung" },
  { 0, NULL }
};


static int
dissect_mms_T_reportSemaphoreEntryStatus_Request_state(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t ReportSemaphoreEntryStatus_Request_sequence[] = {
  { &hf_mms_semaphoreName   , BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { &hf_mms_reportSemaphoreEntryStatus_Request_state, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_T_reportSemaphoreEntryStatus_Request_state },
  { &hf_mms_entryIdToStartAfter, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_ReportSemaphoreEntryStatus_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReportSemaphoreEntryStatus_Request_sequence, hf_index, ett_mms_ReportSemaphoreEntryStatus_Request);

  return offset;
}


static const ber_sequence_t T_listOfCapabilities_01_sequence_of[1] = {
  { &hf_mms_listOfCapabilities_item, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_mms_VisibleString },
};

static int
dissect_mms_T_listOfCapabilities_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_InitiateDownloadSequence_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InitiateDownloadSequence_Request_sequence, hf_index, ett_mms_InitiateDownloadSequence_Request);

  return offset;
}



static int
dissect_mms_DownloadSegment_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_vmd_state(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_application_reference(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_definition(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_resource(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_service(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_service_preempt(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_time_resolution(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_access(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_initiate(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_conclude(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_cancel(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_file(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_errorClass(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_ObtainFile_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_ProgramInvocationState(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_mms_Start_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_ProgramInvocationState(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_mms_Stop_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_ProgramInvocationState(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_mms_Resume_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_ProgramInvocationState(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_mms_Reset_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_ProgramInvocationState(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_mms_DeleteVariableAccess_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Unsigned32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_mms_DeleteNamedVariableList_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Unsigned32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_mms_DeleteNamedType_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Unsigned32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_mms_DefineEventEnrollment_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_ObjectName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string mms_FileRename_Error_vals[] = {
  {   0, "source-file" },
  {   1, "destination-file" },
  { 0, NULL }
};


static int
dissect_mms_FileRename_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_mms_DefineEventConditionList_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_ObjectName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_mms_AddEventConditionListReference_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_ObjectName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string mms_RemoveEventConditionListReference_Error_vals[] = {
  {   0, "eventCondition" },
  {   1, "eventConditionList" },
  { 0, NULL }
};

static const ber_choice_t RemoveEventConditionListReference_Error_choice[] = {
  {   0, &hf_mms_eventCondition  , BER_CLASS_CON, 0, 0, dissect_mms_ObjectName },
  {   1, &hf_mms_eventConditionList, BER_CLASS_CON, 1, 0, dissect_mms_ObjectName },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_RemoveEventConditionListReference_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RemoveEventConditionListReference_Error_choice, hf_index, ett_mms_RemoveEventConditionListReference_Error,
                                 NULL);

  return offset;
}


static const value_string mms_InitiateUnitControl_Error_vals[] = {
  {   0, "domain" },
  {   1, "programInvocation" },
  { 0, NULL }
};

static const ber_choice_t InitiateUnitControl_Error_choice[] = {
  {   0, &hf_mms_domain          , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  {   1, &hf_mms_programInvocation, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_InitiateUnitControl_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 InitiateUnitControl_Error_choice, hf_index, ett_mms_InitiateUnitControl_Error,
                                 NULL);

  return offset;
}


static const ber_sequence_t StartUnitControl_Error_sequence[] = {
  { &hf_mms_programInvocationName, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { &hf_mms_programInvocationState, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_ProgramInvocationState },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_StartUnitControl_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   StartUnitControl_Error_sequence, hf_index, ett_mms_StartUnitControl_Error);

  return offset;
}


static const ber_sequence_t StopUnitControl_Error_sequence[] = {
  { &hf_mms_programInvocationName, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { &hf_mms_programInvocationState, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_ProgramInvocationState },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_StopUnitControl_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   StopUnitControl_Error_sequence, hf_index, ett_mms_StopUnitControl_Error);

  return offset;
}


static const value_string mms_DeleteUnitControl_Error_vals[] = {
  {   0, "domain" },
  {   1, "programInvocation" },
  { 0, NULL }
};

static const ber_choice_t DeleteUnitControl_Error_choice[] = {
  {   0, &hf_mms_domain          , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  {   1, &hf_mms_programInvocation, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_DeleteUnitControl_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 DeleteUnitControl_Error_choice, hf_index, ett_mms_DeleteUnitControl_Error,
                                 NULL);

  return offset;
}


static const value_string mms_LoadUnitControlFromFile_Error_vals[] = {
  {   0, "none" },
  {   1, "domain" },
  {   2, "programInvocation" },
  { 0, NULL }
};

static const ber_choice_t LoadUnitControlFromFile_Error_choice[] = {
  {   0, &hf_mms_none            , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_NULL },
  {   1, &hf_mms_domain          , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  {   2, &hf_mms_programInvocation, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_LoadUnitControlFromFile_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 LoadUnitControlFromFile_Error_choice, hf_index, ett_mms_LoadUnitControlFromFile_Error,
                                 NULL);

  return offset;
}


static const value_string mms_AdditionalService_Error_vals[] = {
  {   0, "defineEcl" },
  {   1, "addECLReference" },
  {   2, "removeECLReference" },
  {   3, "initiateUC" },
  {   4, "startUC" },
  {   5, "stopUC" },
  {   6, "deleteUC" },
  {   7, "loadUCFromFile" },
  { 0, NULL }
};

static const ber_choice_t AdditionalService_Error_choice[] = {
  {   0, &hf_mms_defineEcl       , BER_CLASS_CON, 0, 0, dissect_mms_DefineEventConditionList_Error },
  {   1, &hf_mms_addECLReference , BER_CLASS_CON, 1, 0, dissect_mms_AddEventConditionListReference_Error },
  {   2, &hf_mms_removeECLReference, BER_CLASS_CON, 2, 0, dissect_mms_RemoveEventConditionListReference_Error },
  {   3, &hf_mms_initiateUC      , BER_CLASS_CON, 3, 0, dissect_mms_InitiateUnitControl_Error },
  {   4, &hf_mms_startUC         , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_mms_StartUnitControl_Error },
  {   5, &hf_mms_stopUC          , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_mms_StopUnitControl_Error },
  {   6, &hf_mms_deleteUC        , BER_CLASS_CON, 6, 0, dissect_mms_DeleteUnitControl_Error },
  {   7, &hf_mms_loadUCFromFile  , BER_CLASS_CON, 7, 0, dissect_mms_LoadUnitControlFromFile_Error },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_AdditionalService_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AdditionalService_Error_choice, hf_index, ett_mms_AdditionalService_Error,
                                 NULL);

  return offset;
}



static int
dissect_mms_ChangeAccessControl_Error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Unsigned32(implicit_tag, tvb, offset, actx, tree, hf_index);

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
  {  10, "additionalService" },
  {  11, "changeAccessControl" },
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
  {  10, &hf_mms_additionalService, BER_CLASS_CON, 10, 0, dissect_mms_AdditionalService_Error },
  {  11, &hf_mms_changeAccessControl, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_mms_ChangeAccessControl_Error },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_serviceSpecificInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_ServiceError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_TerminateDownloadSequence_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TerminateDownloadSequence_Request_sequence, hf_index, ett_mms_TerminateDownloadSequence_Request);

  return offset;
}



static int
dissect_mms_InitiateUploadSequence_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Identifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_mms_UploadSegment_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Integer32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_mms_TerminateUploadSequence_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Integer32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t T_listOfCapabilities_03_sequence_of[1] = {
  { &hf_mms_listOfCapabilities_item, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_mms_VisibleString },
};

static int
dissect_mms_T_listOfCapabilities_03(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_listOfCapabilities_03_sequence_of, hf_index, ett_mms_T_listOfCapabilities_03);

  return offset;
}



static int
dissect_mms_GraphicString(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GraphicString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t FileName_sequence_of[1] = {
  { &hf_mms_FileName_item   , BER_CLASS_UNI, BER_UNI_TAG_GraphicString, BER_FLAGS_NOOWNTAG, dissect_mms_GraphicString },
};

static int
dissect_mms_FileName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_RequestDomainDownload_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_RequestDomainUpload_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RequestDomainUpload_Request_sequence, hf_index, ett_mms_RequestDomainUpload_Request);

  return offset;
}


static const ber_sequence_t T_listOfCapabilities_04_sequence_of[1] = {
  { &hf_mms_listOfCapabilities_item, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_mms_VisibleString },
};

static int
dissect_mms_T_listOfCapabilities_04(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_LoadDomainContent_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_StoreDomainContent_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   StoreDomainContent_Request_sequence, hf_index, ett_mms_StoreDomainContent_Request);

  return offset;
}



static int
dissect_mms_DeleteDomain_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Identifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_mms_GetDomainAttributes_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Identifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Identifier_sequence_of[1] = {
  { &hf_mms_listOfIdentifier_item, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_mms_Identifier },
};

static int
dissect_mms_SEQUENCE_OF_Identifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_CreateProgramInvocation_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CreateProgramInvocation_Request_sequence, hf_index, ett_mms_CreateProgramInvocation_Request);

  return offset;
}



static int
dissect_mms_DeleteProgramInvocation_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_executionArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_Start_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Start_Request_sequence, hf_index, ett_mms_Start_Request);

  return offset;
}


static const ber_sequence_t Stop_Request_sequence[] = {
  { &hf_mms_programInvocationName, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_Stop_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_executionArgument_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_Resume_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Resume_Request_sequence, hf_index, ett_mms_Resume_Request);

  return offset;
}


static const ber_sequence_t Reset_Request_sequence[] = {
  { &hf_mms_programInvocationName, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_Reset_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Reset_Request_sequence, hf_index, ett_mms_Reset_Request);

  return offset;
}


static const ber_sequence_t Kill_Request_sequence[] = {
  { &hf_mms_programInvocationName, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Identifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_Kill_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Kill_Request_sequence, hf_index, ett_mms_Kill_Request);

  return offset;
}



static int
dissect_mms_GetProgramInvocationAttributes_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_ObtainFile_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_EC_Class(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_DefineEventCondition_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_DeleteEventCondition_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 DeleteEventCondition_Request_choice, hf_index, ett_mms_DeleteEventCondition_Request,
                                 NULL);

  return offset;
}



static int
dissect_mms_GetEventConditionAttributes_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_ObjectName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_mms_ReportEventConditionStatus_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_AlterEventConditionMonitoring_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_TriggerEvent_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_DefineEventAction_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_DeleteEventAction_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 DeleteEventAction_Request_choice, hf_index, ett_mms_DeleteEventAction_Request,
                                 NULL);

  return offset;
}



static int
dissect_mms_GetEventActionAttributes_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_ObjectName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_mms_ReportEventActionStatus_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_AlarmAckRule(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_DefineEventEnrollment_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_DeleteEventEnrollment_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_AlterEventEnrollment_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AlterEventEnrollment_Request_sequence, hf_index, ett_mms_AlterEventEnrollment_Request);

  return offset;
}



static int
dissect_mms_ReportEventEnrollmentStatus_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_scopeOfRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
  { &hf_mms_getEventEnrollmentAttributes_Request_continueAfter, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_GetEventEnrollmentAttributes_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_EC_State(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_EventTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_AcknowledgeEventNotification_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_acknowledgmentFilter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_severityFilter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_severityFilter_sequence, hf_index, ett_mms_T_severityFilter);

  return offset;
}


static const ber_sequence_t GetAlarmSummary_Request_sequence[] = {
  { &hf_mms_enrollmentsOnly , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_activeAlarmsOnly, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_acknowledgmentFilter, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_T_acknowledgmentFilter },
  { &hf_mms_severityFilter  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_T_severityFilter },
  { &hf_mms_continueAfter   , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_GetAlarmSummary_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_acknowledgmentFilter_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_severityFilter_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_severityFilter_01_sequence, hf_index, ett_mms_T_severityFilter_01);

  return offset;
}


static const ber_sequence_t GetAlarmEnrollmentSummary_Request_sequence[] = {
  { &hf_mms_enrollmentsOnly , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_activeAlarmsOnly, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_acknowledgmentFilter_01, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_T_acknowledgmentFilter_01 },
  { &hf_mms_severityFilter_01, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_T_severityFilter_01 },
  { &hf_mms_getAlarmEnrollmentSummary_Request_continueAfter, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_GetAlarmEnrollmentSummary_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_rangeStartSpecification(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_rangeStopSpecification(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_rangeStopSpecification_choice, hf_index, ett_mms_T_rangeStopSpecification,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_listOfVariables_sequence_of[1] = {
  { &hf_mms_listOfVariables_item, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_mms_VisibleString },
};

static int
dissect_mms_T_listOfVariables(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_entryToStartAfter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_ReadJournal_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReadJournal_Request_sequence, hf_index, ett_mms_ReadJournal_Request);

  return offset;
}



static int
dissect_mms_JOU_Additional_Detail(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t T_event_sequence[] = {
  { &hf_mms_eventConditionName, BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { &hf_mms_currentState    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_EC_State },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_event(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_listOfVariables_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_listOfVariables_item_sequence, hf_index, ett_mms_T_listOfVariables_item);

  return offset;
}


static const ber_sequence_t T_listOfVariables_01_sequence_of[1] = {
  { &hf_mms_listOfVariables_item_01, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_mms_T_listOfVariables_item },
};

static int
dissect_mms_T_listOfVariables_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_data(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_entryForm(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_EntryContent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EntryContent_sequence, hf_index, ett_mms_EntryContent);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_EntryContent_sequence_of[1] = {
  { &hf_mms_listOfJournalEntry_item_01, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_mms_EntryContent },
};

static int
dissect_mms_SEQUENCE_OF_EntryContent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_WriteJournal_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_limitSpecification(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_InitializeJournal_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InitializeJournal_Request_sequence, hf_index, ett_mms_InitializeJournal_Request);

  return offset;
}



static int
dissect_mms_ReportJournalStatus_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_ObjectName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t CreateJournal_Request_sequence[] = {
  { &hf_mms_journalName     , BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_CreateJournal_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CreateJournal_Request_sequence, hf_index, ett_mms_CreateJournal_Request);

  return offset;
}


static const ber_sequence_t DeleteJournal_Request_sequence[] = {
  { &hf_mms_journalName     , BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_mms_ObjectName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_DeleteJournal_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DeleteJournal_Request_sequence, hf_index, ett_mms_DeleteJournal_Request);

  return offset;
}


static const ber_sequence_t GetCapabilityList_Request_sequence[] = {
  { &hf_mms_getCapabilityList_Request_continueAfter, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_mms_VisibleString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_GetCapabilityList_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_FileOpen_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   FileOpen_Request_sequence, hf_index, ett_mms_FileOpen_Request);

  return offset;
}



static int
dissect_mms_FileRead_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Integer32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_mms_FileClose_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Integer32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t FileRename_Request_sequence[] = {
  { &hf_mms_currentFileName , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_FileName },
  { &hf_mms_newFileName     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_FileName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_FileRename_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   FileRename_Request_sequence, hf_index, ett_mms_FileRename_Request);

  return offset;
}



static int
dissect_mms_FileDelete_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_FileName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t FileDirectory_Request_sequence[] = {
  { &hf_mms_fileSpecification, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_FileName },
  { &hf_mms_fileDirectory_Request_continueAfter, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_FileName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_FileDirectory_Request(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
  {  48, &hf_mms_confirmedServiceRequest_deleteEventCondition, BER_CLASS_CON, 48, 0, dissect_mms_DeleteEventCondition_Request },
  {  49, &hf_mms_getEventConditionAttributes, BER_CLASS_CON, 49, 0, dissect_mms_GetEventConditionAttributes_Request },
  {  50, &hf_mms_reportEventConditionStatus, BER_CLASS_CON, 50, 0, dissect_mms_ReportEventConditionStatus_Request },
  {  51, &hf_mms_alterEventConditionMonitoring, BER_CLASS_CON, 51, BER_FLAGS_IMPLTAG, dissect_mms_AlterEventConditionMonitoring_Request },
  {  52, &hf_mms_triggerEvent    , BER_CLASS_CON, 52, BER_FLAGS_IMPLTAG, dissect_mms_TriggerEvent_Request },
  {  53, &hf_mms_defineEventAction, BER_CLASS_CON, 53, BER_FLAGS_IMPLTAG, dissect_mms_DefineEventAction_Request },
  {  54, &hf_mms_confirmedServiceRequest_deleteEventAction, BER_CLASS_CON, 54, 0, dissect_mms_DeleteEventAction_Request },
  {  55, &hf_mms_getEventActionAttributes, BER_CLASS_CON, 55, 0, dissect_mms_GetEventActionAttributes_Request },
  {  56, &hf_mms_reportEventActionStatus, BER_CLASS_CON, 56, 0, dissect_mms_ReportEventActionStatus_Request },
  {  57, &hf_mms_defineEventEnrollment, BER_CLASS_CON, 57, BER_FLAGS_IMPLTAG, dissect_mms_DefineEventEnrollment_Request },
  {  58, &hf_mms_confirmedServiceRequest_deleteEventEnrollment, BER_CLASS_CON, 58, 0, dissect_mms_DeleteEventEnrollment_Request },
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
dissect_mms_ConfirmedServiceRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
        int8_t   ber_class;
        bool     pc;
        int32_t  tag;

        get_ber_identifier(tvb, offset, &ber_class, &pc, &tag);
        mms_actx_private_data_t *mms_priv = (mms_actx_private_data_t *)actx->private_data;
        if(mms_priv){
            mms_priv->confirmedservice_type = tag;
        }

  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ConfirmedServiceRequest_choice, hf_index, ett_mms_ConfirmedServiceRequest,
                                 NULL);


        if(mms_priv && mms_priv->mms_trans_p){
            if(mms_priv->confirmedservice_type == MMS_CONFIRMEDSERVICE_GETNAMELIST){
                if(mms_priv->objectclass == MMS_OBJECTCLASS_DOMAIN){
                    if(mms_priv->objectscope == MMS_OBJECTSCOPE_VMDSPECIFIC){
                        mms_priv->mms_trans_p->conf_serv_pdu_type_req = MMS_IEC_61850_CONF_SERV_PDU_GET_SERV_DIR;
                    }
                }else if(mms_priv->objectclass == MMS_OBJECTCLASS_NAMMEDVARIABLE){
                    mms_priv->mms_trans_p->conf_serv_pdu_type_req = MMS_IEC_61850_CONF_SERV_PDU_GETLOGICALDEVICEDIRECTORY;
                }else if(mms_priv->objectclass == MMS_OBJECTCLASS_NAMEDVARIABLELIST){
                    mms_priv->mms_trans_p->conf_serv_pdu_type_req = MMS_IEC_61850_CONF_SERV_PDU_GETDATASETDIRECTORY;
                }
            }else if(mms_priv->confirmedservice_type == MMS_CONFIRMEDSERVICE_GETNAMEDVARIABLELISTATTRIBUTES){
                mms_priv->mms_trans_p->conf_serv_pdu_type_req = MMS_IEC_61850_CONF_SERV_PDU_GETDATASETDIRECTORY;
            }else if(mms_priv->confirmedservice_type == MMS_CONFIRMEDSERVICE_READ){
                mms_priv->mms_trans_p->conf_serv_pdu_type_req = MMS_IEC_61850_CONF_SERV_PDU_READ;
            }else if(mms_priv->confirmedservice_type == MMS_CONFIRMEDSERVICE_WRITE){
                mms_priv->mms_trans_p->conf_serv_pdu_type_req = MMS_IEC_61850_CONF_SERV_PDU_WRITE;
            }else if(mms_priv->confirmedservice_type == MMS_CONFIRMEDSERVICE_GETVARIABLEACCESSATTRIBUTES){
                mms_priv->mms_trans_p->conf_serv_pdu_type_req = MMS_IEC_61850_CONF_SERV_PDU_GETDATADIRECTORY;
            }
        }



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
dissect_mms_CS_Request_Detail(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_Confirmed_RequestPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Confirmed_RequestPDU_sequence, hf_index, ett_mms_Confirmed_RequestPDU);

    mms_actx_private_data_t *mms_priv = (mms_actx_private_data_t *)actx->private_data;
    if(tree){
        mms_priv->pdu_item = (proto_item*)tree->last_child;
    }


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
dissect_mms_T_vmdLogicalStatus(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_vmdPhysicalStatus(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_mms_BIT_STRING_SIZE_0_128(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
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
dissect_mms_Status_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_GetNameList_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetNameList_Response_sequence, hf_index, ett_mms_GetNameList_Response);

  return offset;
}


static const ber_sequence_t T_listOfAbstractSyntaxes_sequence_of[1] = {
  { &hf_mms_listOfAbstractSyntaxes_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_mms_OBJECT_IDENTIFIER },
};

static int
dissect_mms_T_listOfAbstractSyntaxes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_Identify_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Identify_Response_sequence, hf_index, ett_mms_Identify_Response);

  return offset;
}



static int
dissect_mms_Rename_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
  {  11, "object-value-invalid" },
  { 0, NULL }
};


static int
dissect_mms_DataAccessError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_AccessResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    int branch_taken;
    mms_actx_private_data_t *mms_priv = (mms_actx_private_data_t *)actx->private_data;
    if(mms_priv){
        /* If listOfAccessResult_cnt > 2 we are into the optional data.
         * if data is not present increase count.
         */
        bool present;
        do {
            mms_priv->listOfAccessResult_cnt+=1;
            present = true;
            switch(mms_priv->listOfAccessResult_cnt){
            case 1: /*RptID*/
                break;
            case 2: /* Reported OptFlds */
                break;
            case 3: /* SeqNum Shall be present if OptFlds.sequence-number is true */
                if((mms_priv->reported_optflds & 0x4000) != 0x4000){
                    present = false;
                }
                break;
            case 4: /*TimeOfEntry Shall be present if OptFlds.report-time-stamp is true */
                if((mms_priv->reported_optflds & 0x2000) != 0x2000){
                    present = false;
                }
                break;
            case 5: /*DatSet Shall be present if OptFlds.data-set-name is true */
                if((mms_priv->reported_optflds & 0x0800) !=0x0800){
                    present = false;
                }
                break;
            case 6: /*BufOvfl Shall be present if OptFlds.buffer-overflow is true */
                if((mms_priv->reported_optflds & 0x0200) !=0x0200){
                    present = false;
                }
                break;
            case 7: /*EntryID Shall be present if OptFlds.entryID is true */
                if((mms_priv->reported_optflds & 0x0100) !=0x0100){
                    present = false;
                }
                break;
            case 8: /*ConfRev Shall be present if OptFlds.conf-rev is true */
                if((mms_priv->reported_optflds & 0x0080) !=0x0080){
                    present = false;
                }
                break;
            case 9: /*SubSeqNum Shall be present if OptFlds.segmentation is true */
                if((mms_priv->reported_optflds & 0x0040) !=0x0040){
                    present = false;
                }
                break;
            case 10: /*MoreSegmentsFollow Shall be present if OptFlds.segmentation is true */
                if((mms_priv->reported_optflds & 0x0040) !=0x0040){
                    present = false;
                }
                break;
            case 11: /*Inclusion-bitstring Shall be present */
                break;
            case 12: /*data-reference(s) Shall be present if OptFlds.data-reference is true */
                if((mms_priv->reported_optflds & 0x0400) !=0x0400){
                    present = false;
                }
                break;
            case 13: /*value(s) See AccessResult for value(s) */
                break;
            case 14: /*ReasonCode(s) Shall be present if OptFlds OptFlds.reason-for-inclusion is true */
                if((mms_priv->reported_optflds & 0x1000) !=0x1000){
                    present = false;
                }
                break;
            default:
                break;
            }
         } while(!present);
    }

  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AccessResult_choice, hf_index, ett_mms_AccessResult,
                                 &branch_taken);

    if(mms_priv){
        mms_priv->success = branch_taken;
    }


  return offset;
}


static const ber_sequence_t SEQUENCE_OF_AccessResult_sequence_of[1] = {
  { &hf_mms_listOfAccessResult_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_AccessResult },
};

static int
dissect_mms_SEQUENCE_OF_AccessResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_Read_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_Write_Response_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Write_Response_item_choice, hf_index, ett_mms_Write_Response_item,
                                 NULL);

  return offset;
}


static const ber_sequence_t Write_Response_sequence_of[1] = {
  { &hf_mms_Write_Response_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_Write_Response_item },
};

static int
dissect_mms_Write_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_GetVariableAccessAttributes_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetVariableAccessAttributes_Response_sequence, hf_index, ett_mms_GetVariableAccessAttributes_Response);

  return offset;
}



static int
dissect_mms_DefineNamedVariable_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_DefineScatteredAccess_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t GetScatteredAccessAttributes_Response_sequence[] = {
  { &hf_mms_mmsDeletable    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_scatteredAccessDescription, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_ScatteredAccessDescription },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_GetScatteredAccessAttributes_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_DeleteVariableAccess_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DeleteVariableAccess_Response_sequence, hf_index, ett_mms_DeleteVariableAccess_Response);

  return offset;
}



static int
dissect_mms_DefineNamedVariableList_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t T_listOfVariable_item_01_sequence[] = {
  { &hf_mms_variableSpecification, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_VariableSpecification },
  { &hf_mms_alternateAccess , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_AlternateAccess },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_listOfVariable_item_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_listOfVariable_item_01_sequence, hf_index, ett_mms_T_listOfVariable_item_01);

  return offset;
}


static const ber_sequence_t T_listOfVariable_01_sequence_of[1] = {
  { &hf_mms_listOfVariable_item_01, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_mms_T_listOfVariable_item_01 },
};

static int
dissect_mms_T_listOfVariable_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_GetNamedVariableListAttributes_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_DeleteNamedVariableList_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DeleteNamedVariableList_Response_sequence, hf_index, ett_mms_DeleteNamedVariableList_Response);

  return offset;
}



static int
dissect_mms_DefineNamedType_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t GetNamedTypeAttributes_Response_sequence[] = {
  { &hf_mms_mmsDeletable    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_typeSpecification, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_TypeSpecification },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_GetNamedTypeAttributes_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_DeleteNamedType_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DeleteNamedType_Response_sequence, hf_index, ett_mms_DeleteNamedType_Response);

  return offset;
}



static int
dissect_mms_Input_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_VisibleString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_mms_Output_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_TakeControl_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 TakeControl_Response_choice, hf_index, ett_mms_TakeControl_Response,
                                 NULL);

  return offset;
}



static int
dissect_mms_RelinquishControl_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_DefineSemaphore_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_DeleteSemaphore_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string mms_T_class_vals[] = {
  {   0, "token" },
  {   1, "pool" },
  { 0, NULL }
};


static int
dissect_mms_T_class(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_ReportSemaphoreStatus_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_listOfNamedTokens_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_listOfNamedTokens_item_choice, hf_index, ett_mms_T_listOfNamedTokens_item,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_listOfNamedTokens_sequence_of[1] = {
  { &hf_mms_listOfNamedTokens_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_T_listOfNamedTokens_item },
};

static int
dissect_mms_T_listOfNamedTokens(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_ReportPoolSemaphoreStatus_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_entryClass(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_SemaphoreEntry(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SemaphoreEntry_sequence, hf_index, ett_mms_SemaphoreEntry);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_SemaphoreEntry_sequence_of[1] = {
  { &hf_mms_listOfSemaphoreEntry_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_mms_SemaphoreEntry },
};

static int
dissect_mms_SEQUENCE_OF_SemaphoreEntry(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_ReportSemaphoreEntryStatus_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReportSemaphoreEntryStatus_Response_sequence, hf_index, ett_mms_ReportSemaphoreEntryStatus_Response);

  return offset;
}



static int
dissect_mms_InitiateDownloadSequence_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_loadData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_DownloadSegment_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DownloadSegment_Response_sequence, hf_index, ett_mms_DownloadSegment_Response);

  return offset;
}



static int
dissect_mms_TerminateDownloadSequence_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t T_listOfCapabilities_02_sequence_of[1] = {
  { &hf_mms_listOfCapabilities_item, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_mms_VisibleString },
};

static int
dissect_mms_T_listOfCapabilities_02(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_InitiateUploadSequence_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_loadData_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_UploadSegment_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UploadSegment_Response_sequence, hf_index, ett_mms_UploadSegment_Response);

  return offset;
}



static int
dissect_mms_TerminateUploadSequence_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_RequestDomainDownload_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_RequestDomainUpload_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_LoadDomainContent_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_StoreDomainContent_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_DeleteDomain_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t T_listOfCapabilities_05_sequence_of[1] = {
  { &hf_mms_listOfCapabilities_item, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_mms_VisibleString },
};

static int
dissect_mms_T_listOfCapabilities_05(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_DomainState(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_mms_Integer8(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t GetDomainAttributes_Response_sequence[] = {
  { &hf_mms_listOfCapabilities_05, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_T_listOfCapabilities_05 },
  { &hf_mms_getDomainAttributes_Response_state, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_DomainState },
  { &hf_mms_mmsDeletable    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_sharable        , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_listOfProgramInvocations, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_mms_SEQUENCE_OF_Identifier },
  { &hf_mms_uploadInProgress, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_mms_Integer8 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_GetDomainAttributes_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetDomainAttributes_Response_sequence, hf_index, ett_mms_GetDomainAttributes_Response);

  return offset;
}



static int
dissect_mms_CreateProgramInvocation_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_DeleteProgramInvocation_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_Start_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_Stop_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_Resume_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_Reset_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_Kill_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_executionArgument_02(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_executionArgument_02_choice, hf_index, ett_mms_T_executionArgument_02,
                                 NULL);

  return offset;
}


static const ber_sequence_t GetProgramInvocationAttributes_Response_sequence[] = {
  { &hf_mms_getProgramInvocationAttributes_Response_state, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_ProgramInvocationState },
  { &hf_mms_listOfDomainNames, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_SEQUENCE_OF_Identifier },
  { &hf_mms_mmsDeletable    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_reusable        , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_monitor         , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_startArgument   , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_mms_VisibleString },
  { &hf_mms_executionArgument_02, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_T_executionArgument_02 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_GetProgramInvocationAttributes_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetProgramInvocationAttributes_Response_sequence, hf_index, ett_mms_GetProgramInvocationAttributes_Response);

  return offset;
}



static int
dissect_mms_ObtainFile_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_GeneralizedTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t FileAttributes_sequence[] = {
  { &hf_mms_sizeOfFile      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  { &hf_mms_lastModified    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_GeneralizedTime },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_FileAttributes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_FileOpen_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   FileOpen_Response_sequence, hf_index, ett_mms_FileOpen_Response);

  return offset;
}



static int
dissect_mms_DefineEventCondition_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_DeleteEventCondition_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_monitoredVariable(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_GetEventConditionAttributes_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_ReportEventConditionStatus_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReportEventConditionStatus_Response_sequence, hf_index, ett_mms_ReportEventConditionStatus_Response);

  return offset;
}



static int
dissect_mms_AlterEventConditionMonitoring_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_TriggerEvent_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_DefineEventAction_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_DeleteEventAction_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Unsigned32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t GetEventActionAttributes_Response_sequence[] = {
  { &hf_mms_mmsDeletable    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { &hf_mms_listOfModifier  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_SEQUENCE_OF_Modifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_GetEventActionAttributes_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetEventActionAttributes_Response_sequence, hf_index, ett_mms_GetEventActionAttributes_Response);

  return offset;
}



static int
dissect_mms_ReportEventActionStatus_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Unsigned32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_mms_DefineEventEnrollment_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_DeleteEventEnrollment_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_EE_State(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
  {   0, &hf_mms_alterEventEnrollment_Response_currentState_state, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_EE_State },
  {   1, &hf_mms_undefined       , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_T_currentState(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_AlterEventEnrollment_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_EE_Duration(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_ReportEventEnrollmentStatus_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_eventConditionName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_eventActionName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_EE_Class(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_EventEnrollment(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EventEnrollment_sequence, hf_index, ett_mms_EventEnrollment);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_EventEnrollment_sequence_of[1] = {
  { &hf_mms_listOfEventEnrollment_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_mms_EventEnrollment },
};

static int
dissect_mms_SEQUENCE_OF_EventEnrollment(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_GetEventEnrollmentAttributes_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetEventEnrollmentAttributes_Response_sequence, hf_index, ett_mms_GetEventEnrollmentAttributes_Response);

  return offset;
}



static int
dissect_mms_AcknowledgeEventNotification_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_unacknowledgedState(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_AlarmSummary(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AlarmSummary_sequence, hf_index, ett_mms_AlarmSummary);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_AlarmSummary_sequence_of[1] = {
  { &hf_mms_listOfAlarmSummary_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_mms_AlarmSummary },
};

static int
dissect_mms_SEQUENCE_OF_AlarmSummary(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_GetAlarmSummary_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_AlarmEnrollmentSummary(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AlarmEnrollmentSummary_sequence, hf_index, ett_mms_AlarmEnrollmentSummary);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_AlarmEnrollmentSummary_sequence_of[1] = {
  { &hf_mms_listOfAlarmEnrollmentSummary_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_mms_AlarmEnrollmentSummary },
};

static int
dissect_mms_SEQUENCE_OF_AlarmEnrollmentSummary(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_GetAlarmEnrollmentSummary_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_JournalEntry(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   JournalEntry_sequence, hf_index, ett_mms_JournalEntry);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_JournalEntry_sequence_of[1] = {
  { &hf_mms_listOfJournalEntry_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_mms_JournalEntry },
};

static int
dissect_mms_SEQUENCE_OF_JournalEntry(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_ReadJournal_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReadJournal_Response_sequence, hf_index, ett_mms_ReadJournal_Response);

  return offset;
}



static int
dissect_mms_WriteJournal_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_InitializeJournal_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Unsigned32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t ReportJournalStatus_Response_sequence[] = {
  { &hf_mms_currentEntries  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  { &hf_mms_mmsDeletable    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_ReportJournalStatus_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReportJournalStatus_Response_sequence, hf_index, ett_mms_ReportJournalStatus_Response);

  return offset;
}



static int
dissect_mms_CreateJournal_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_DeleteJournal_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t T_listOfCapabilities_sequence_of[1] = {
  { &hf_mms_listOfCapabilities_item, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_mms_VisibleString },
};

static int
dissect_mms_T_listOfCapabilities(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_GetCapabilityList_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_FileRead_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   FileRead_Response_sequence, hf_index, ett_mms_FileRead_Response);

  return offset;
}



static int
dissect_mms_FileClose_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_FileRename_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_FileDelete_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t DirectoryEntry_sequence[] = {
  { &hf_mms_filename        , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_FileName },
  { &hf_mms_fileAttributes  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_FileAttributes },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_DirectoryEntry(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DirectoryEntry_sequence, hf_index, ett_mms_DirectoryEntry);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_DirectoryEntry_sequence_of[1] = {
  { &hf_mms_listOfDirectoryEntry_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_mms_DirectoryEntry },
};

static int
dissect_mms_SEQUENCE_OF_DirectoryEntry(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_FileDirectory_Response(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
  {  48, &hf_mms_confirmedServiceResponse_deleteEventCondition, BER_CLASS_CON, 48, BER_FLAGS_IMPLTAG, dissect_mms_DeleteEventCondition_Response },
  {  49, &hf_mms_getEventConditionAttributes_01, BER_CLASS_CON, 49, BER_FLAGS_IMPLTAG, dissect_mms_GetEventConditionAttributes_Response },
  {  50, &hf_mms_reportEventConditionStatus_01, BER_CLASS_CON, 50, BER_FLAGS_IMPLTAG, dissect_mms_ReportEventConditionStatus_Response },
  {  51, &hf_mms_alterEventConditionMonitoring_01, BER_CLASS_CON, 51, BER_FLAGS_IMPLTAG, dissect_mms_AlterEventConditionMonitoring_Response },
  {  52, &hf_mms_triggerEvent_01 , BER_CLASS_CON, 52, BER_FLAGS_IMPLTAG, dissect_mms_TriggerEvent_Response },
  {  53, &hf_mms_defineEventAction_01, BER_CLASS_CON, 53, BER_FLAGS_IMPLTAG, dissect_mms_DefineEventAction_Response },
  {  54, &hf_mms_confirmedServiceRequest_deleteEventAction_01, BER_CLASS_CON, 54, BER_FLAGS_IMPLTAG, dissect_mms_DeleteEventAction_Response },
  {  55, &hf_mms_getEventActionAttributes_01, BER_CLASS_CON, 55, BER_FLAGS_IMPLTAG, dissect_mms_GetEventActionAttributes_Response },
  {  56, &hf_mms_reportActionStatus, BER_CLASS_CON, 56, BER_FLAGS_IMPLTAG, dissect_mms_ReportEventActionStatus_Response },
  {  57, &hf_mms_defineEventEnrollment_01, BER_CLASS_CON, 57, BER_FLAGS_IMPLTAG, dissect_mms_DefineEventEnrollment_Response },
  {  58, &hf_mms_confirmedServiceResponse_deleteEventEnrollment, BER_CLASS_CON, 58, BER_FLAGS_IMPLTAG, dissect_mms_DeleteEventEnrollment_Response },
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
dissect_mms_ConfirmedServiceResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
        int8_t   ber_class;
        bool     pc;
        int32_t  tag;

        get_ber_identifier(tvb, offset, &ber_class, &pc, &tag);
        mms_actx_private_data_t *mms_priv = (mms_actx_private_data_t *)actx->private_data;
        if(mms_priv){
            mms_priv->confirmedservice_type = tag;
        }

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
dissect_mms_Confirmed_ResponsePDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Confirmed_ResponsePDU_sequence, hf_index, ett_mms_Confirmed_ResponsePDU);

    mms_actx_private_data_t *mms_priv = (mms_actx_private_data_t *)actx->private_data;
    if(tree){
        mms_priv->pdu_item = (proto_item*)tree->last_child;
    }


  return offset;
}


static const ber_sequence_t Confirmed_ErrorPDU_sequence[] = {
  { &hf_mms_invokeID        , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  { &hf_mms_modifierPosition, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  { &hf_mms_serviceError    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_ServiceError },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_Confirmed_ErrorPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Confirmed_ErrorPDU_sequence, hf_index, ett_mms_Confirmed_ErrorPDU);

  return offset;
}


static const ber_sequence_t T_listOfAccessResult_sequence_of[1] = {
  { &hf_mms_listOfAccessResult_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_AccessResult },
};

static int
dissect_mms_T_listOfAccessResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

    mms_actx_private_data_t *mms_priv = (mms_actx_private_data_t *)actx->private_data;
    if(mms_priv){
        mms_priv->listOfAccessResult_cnt = 0;
    }

  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_listOfAccessResult_sequence_of, hf_index, ett_mms_T_listOfAccessResult);



  return offset;
}


static const ber_sequence_t InformationReport_sequence[] = {
  { &hf_mms_variableAccessSpecification, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mms_VariableAccessSpecification },
  { &hf_mms_listOfAccessResult_01, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_T_listOfAccessResult },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_InformationReport(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InformationReport_sequence, hf_index, ett_mms_InformationReport);

  return offset;
}



static int
dissect_mms_UnsolicitedStatus(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_eventConditionName_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_eventActionResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_actionResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_EventNotification(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_UnconfirmedService(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_Unconfirmed_PDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
   mms_actx_private_data_t *mms_priv = (mms_actx_private_data_t *)actx->private_data;
    if (!mms_priv->mms_trans_p) {
        /* create a "fake" mms_trans structure */
        mms_priv->mms_trans_p=wmem_new0(actx->pinfo->pool, mms_transaction_t);
        mms_priv->mms_trans_p->req_time = actx->pinfo->fd->abs_ts;

    }

  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Unconfirmed_PDU_sequence, hf_index, ett_mms_Unconfirmed_PDU);

    if(tree){
        mms_priv->pdu_item = (proto_item*)tree->last_child;
    }

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
dissect_mms_T_confirmed_requestPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_confirmed_responsePDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_confirmed_errorPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_unconfirmedPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_pdu_error(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_cancel_requestPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_cancel_responsePDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_cancel_errorPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_conclude_requestPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_conclude_responsePDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_conclude_errorPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_T_rejectReason(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_RejectPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RejectPDU_sequence, hf_index, ett_mms_RejectPDU);

  return offset;
}



static int
dissect_mms_Cancel_RequestPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Unsigned32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_mms_Cancel_ResponsePDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_Unsigned32(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t Cancel_ErrorPDU_sequence[] = {
  { &hf_mms_originalInvokeID, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Unsigned32 },
  { &hf_mms_serviceError    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_ServiceError },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_Cancel_ErrorPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Cancel_ErrorPDU_sequence, hf_index, ett_mms_Cancel_ErrorPDU);

  return offset;
}



static int
dissect_mms_Integer16(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static int * const ParameterSupportOptions_bits[] = {
  &hf_mms_ParameterSupportOptions_str1,
  &hf_mms_ParameterSupportOptions_str2,
  &hf_mms_ParameterSupportOptions_vnam,
  &hf_mms_ParameterSupportOptions_valt,
  &hf_mms_ParameterSupportOptions_vadr,
  &hf_mms_ParameterSupportOptions_vsca,
  &hf_mms_ParameterSupportOptions_tpy,
  &hf_mms_ParameterSupportOptions_vlis,
  &hf_mms_ParameterSupportOptions_real,
  &hf_mms_ParameterSupportOptions_spare_bit9,
  &hf_mms_ParameterSupportOptions_cei,
  NULL
};

static int
dissect_mms_ParameterSupportOptions(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    ParameterSupportOptions_bits, 11, hf_index, ett_mms_ParameterSupportOptions,
                                    NULL);

  return offset;
}


static int * const ServiceSupportOptions_bits[] = {
  &hf_mms_ServiceSupportOptions_status,
  &hf_mms_ServiceSupportOptions_getNameList,
  &hf_mms_ServiceSupportOptions_identify,
  &hf_mms_ServiceSupportOptions_rename,
  &hf_mms_ServiceSupportOptions_read,
  &hf_mms_ServiceSupportOptions_write,
  &hf_mms_ServiceSupportOptions_getVariableAccessAttributes,
  &hf_mms_ServiceSupportOptions_defineNamedVariable,
  &hf_mms_ServiceSupportOptions_defineScatteredAccess,
  &hf_mms_ServiceSupportOptions_getScatteredAccessAttributes,
  &hf_mms_ServiceSupportOptions_deleteVariableAccess,
  &hf_mms_ServiceSupportOptions_defineNamedVariableList,
  &hf_mms_ServiceSupportOptions_getNamedVariableListAttributes,
  &hf_mms_ServiceSupportOptions_deleteNamedVariableList,
  &hf_mms_ServiceSupportOptions_defineNamedType,
  &hf_mms_ServiceSupportOptions_getNamedTypeAttributes,
  &hf_mms_ServiceSupportOptions_deleteNamedType,
  &hf_mms_ServiceSupportOptions_input,
  &hf_mms_ServiceSupportOptions_output,
  &hf_mms_ServiceSupportOptions_takeControl,
  &hf_mms_ServiceSupportOptions_relinquishControl,
  &hf_mms_ServiceSupportOptions_defineSemaphore,
  &hf_mms_ServiceSupportOptions_deleteSemaphore,
  &hf_mms_ServiceSupportOptions_reportSemaphoreStatus,
  &hf_mms_ServiceSupportOptions_reportPoolSemaphoreStatus,
  &hf_mms_ServiceSupportOptions_reportSemaphoreEntryStatus,
  &hf_mms_ServiceSupportOptions_initiateDownloadSequence,
  &hf_mms_ServiceSupportOptions_downloadSegment,
  &hf_mms_ServiceSupportOptions_terminateDownloadSequence,
  &hf_mms_ServiceSupportOptions_initiateUploadSequence,
  &hf_mms_ServiceSupportOptions_uploadSegment,
  &hf_mms_ServiceSupportOptions_terminateUploadSequence,
  &hf_mms_ServiceSupportOptions_requestDomainDownload,
  &hf_mms_ServiceSupportOptions_requestDomainUpload,
  &hf_mms_ServiceSupportOptions_loadDomainContent,
  &hf_mms_ServiceSupportOptions_storeDomainContent,
  &hf_mms_ServiceSupportOptions_deleteDomain,
  &hf_mms_ServiceSupportOptions_getDomainAttributes,
  &hf_mms_ServiceSupportOptions_createProgramInvocation,
  &hf_mms_ServiceSupportOptions_deleteProgramInvocation,
  &hf_mms_ServiceSupportOptions_start,
  &hf_mms_ServiceSupportOptions_stop,
  &hf_mms_ServiceSupportOptions_resume,
  &hf_mms_ServiceSupportOptions_reset,
  &hf_mms_ServiceSupportOptions_kill,
  &hf_mms_ServiceSupportOptions_getProgramInvocationAttributes,
  &hf_mms_ServiceSupportOptions_obtainFile,
  &hf_mms_ServiceSupportOptions_defineEventCondition,
  &hf_mms_ServiceSupportOptions_deleteEventCondition,
  &hf_mms_ServiceSupportOptions_getEventConditionAttributes,
  &hf_mms_ServiceSupportOptions_reportEventConditionStatus,
  &hf_mms_ServiceSupportOptions_alterEventConditionMonitoring,
  &hf_mms_ServiceSupportOptions_triggerEvent,
  &hf_mms_ServiceSupportOptions_defineEventAction,
  &hf_mms_ServiceSupportOptions_deleteEventAction,
  &hf_mms_ServiceSupportOptions_getEventActionAttributes,
  &hf_mms_ServiceSupportOptions_reportActionStatus,
  &hf_mms_ServiceSupportOptions_defineEventEnrollment,
  &hf_mms_ServiceSupportOptions_deleteEventEnrollment,
  &hf_mms_ServiceSupportOptions_alterEventEnrollment,
  &hf_mms_ServiceSupportOptions_reportEventEnrollmentStatus,
  &hf_mms_ServiceSupportOptions_getEventEnrollmentAttributes,
  &hf_mms_ServiceSupportOptions_acknowledgeEventNotification,
  &hf_mms_ServiceSupportOptions_getAlarmSummary,
  &hf_mms_ServiceSupportOptions_getAlarmEnrollmentSummary,
  &hf_mms_ServiceSupportOptions_readJournal,
  &hf_mms_ServiceSupportOptions_writeJournal,
  &hf_mms_ServiceSupportOptions_initializeJournal,
  &hf_mms_ServiceSupportOptions_reportJournalStatus,
  &hf_mms_ServiceSupportOptions_createJournal,
  &hf_mms_ServiceSupportOptions_deleteJournal,
  &hf_mms_ServiceSupportOptions_getCapabilityList,
  &hf_mms_ServiceSupportOptions_fileOpen,
  &hf_mms_ServiceSupportOptions_fileRead,
  &hf_mms_ServiceSupportOptions_fileClose,
  &hf_mms_ServiceSupportOptions_fileRename,
  &hf_mms_ServiceSupportOptions_fileDelete,
  &hf_mms_ServiceSupportOptions_fileDirectory,
  &hf_mms_ServiceSupportOptions_unsolicitedStatus,
  &hf_mms_ServiceSupportOptions_informationReport,
  &hf_mms_ServiceSupportOptions_eventNotification,
  &hf_mms_ServiceSupportOptions_attachToEventCondition,
  &hf_mms_ServiceSupportOptions_attachToSemaphore,
  &hf_mms_ServiceSupportOptions_conclude,
  &hf_mms_ServiceSupportOptions_cancel,
  NULL
};

static int
dissect_mms_ServiceSupportOptions(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    ServiceSupportOptions_bits, 85, hf_index, ett_mms_ServiceSupportOptions,
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
dissect_mms_InitRequestDetail(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_Initiate_RequestPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Initiate_RequestPDU_sequence, hf_index, ett_mms_Initiate_RequestPDU);

    mms_actx_private_data_t *mms_priv = (mms_actx_private_data_t *)actx->private_data;
    if(tree){
        mms_priv->pdu_item = (proto_item*)tree->last_child;
    }



  return offset;
}


static const ber_sequence_t InitResponseDetail_sequence[] = {
  { &hf_mms_negociatedVersionNumber, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mms_Integer16 },
  { &hf_mms_negociatedParameterCBB, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_mms_ParameterSupportOptions },
  { &hf_mms_servicesSupportedCalled, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_mms_ServiceSupportOptions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_mms_InitResponseDetail(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_Initiate_ResponsePDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Initiate_ResponsePDU_sequence, hf_index, ett_mms_Initiate_ResponsePDU);

    mms_actx_private_data_t *mms_priv = (mms_actx_private_data_t *)actx->private_data;
    if(tree){
        mms_priv->pdu_item = (proto_item*)tree->last_child;
    }

  return offset;
}



static int
dissect_mms_Initiate_ErrorPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_mms_ServiceError(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_mms_Conclude_RequestPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_Conclude_ResponsePDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_mms_Conclude_ErrorPDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_mms_MMSpdu(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
        int branch_taken;
        int8_t   ber_class;
        bool     pc;
        int32_t  tag;

        get_ber_identifier(tvb, offset, &ber_class, &pc, &tag);
        mms_actx_private_data_t *mms_priv = (mms_actx_private_data_t *)actx->private_data;
        if(mms_priv){
            mms_priv->mms_pdu_type = tag;
        }


  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 MMSpdu_choice, hf_index, ett_mms_MMSpdu,
                                 &branch_taken);


    if( (branch_taken!=-1) && mms_MMSpdu_vals[branch_taken].strptr ){
            if(mms_priv){
                switch(mms_priv->mms_pdu_type){
                    case MMS_UNCONFIRMED_PDU:
                        if(mms_priv->vmd_specific==IEC61850_8_1_RPT){
                            col_append_str(actx->pinfo->cinfo, COL_INFO, "Unconfirmed <RPT>");
                            proto_item_append_text(mms_priv->pdu_item, " [RPT]");
                        }else if((mms_priv->mms_trans_p)&&(mms_priv->mms_trans_p->itemid==IEC61850_ITEM_ID_OPER)){
                            col_append_str(actx->pinfo->cinfo, COL_INFO, "Unconfirmed-CommandTermination");
                            proto_item_append_text(mms_priv->pdu_item, " [Unconfirmed-CommandTermination]");
                        }
                    break;
                    case MMS_INITIATE_REQUEST_PDU:
                        col_append_str(actx->pinfo->cinfo, COL_INFO, "Associate Request");
                        proto_item_append_text(mms_priv->pdu_item, " [Associate Request]");
                        break;
                    case MMS_INITIATE_RESPONSE_PDU:
                        col_append_str(actx->pinfo->cinfo, COL_INFO, "Associate Response");
                        proto_item_append_text(mms_priv->pdu_item, " [Associate Response]");
                        break;
                    case MMS_CONFIRMED_REQUEST_PDU:
                        if(mms_priv->mms_trans_p){
                            if(mms_priv->mms_trans_p->conf_serv_pdu_type_req == MMS_IEC_61850_CONF_SERV_PDU_GET_SERV_DIR){
                                col_append_str(actx->pinfo->cinfo, COL_INFO, "GetServerDirectoryRequest");
                                proto_item_append_text(mms_priv->pdu_item, " [GetServerDirectoryRequest]");
                            }else if(mms_priv->mms_trans_p->conf_serv_pdu_type_req == MMS_IEC_61850_CONF_SERV_PDU_GETLOGICALDEVICEDIRECTORY){
                                col_append_fstr(actx->pinfo->cinfo, COL_INFO, "GetLogicalDeviceDirectoryRequest %s", mms_priv->itemid_str);
                                proto_item_append_text(mms_priv->pdu_item, " [GetLogicalDeviceDirectoryRequest ]");
                            }else if(mms_priv->mms_trans_p->conf_serv_pdu_type_req == MMS_IEC_61850_CONF_SERV_PDU_GETDATASETDIRECTORY){
                                col_append_fstr(actx->pinfo->cinfo, COL_INFO, "GetDataSetDirectoryRequest %s", mms_priv->itemid_str);
                                proto_item_append_text(mms_priv->pdu_item, " [GetDataSetDirectoryRequest]");
                            }else if(mms_priv->mms_trans_p->conf_serv_pdu_type_req == MMS_IEC_61850_CONF_SERV_PDU_GETDATADIRECTORY){
                                col_append_fstr(actx->pinfo->cinfo, COL_INFO, "GetDataDirectoryRequest%s", private_data_get_moreCinfo(actx));
                                proto_item_append_text(mms_priv->pdu_item, " [GetDataDirectoryRequest]");
                            } else if (mms_priv->mms_trans_p->conf_serv_pdu_type_req == MMS_IEC_61850_CONF_SERV_PDU_READ){
                                if(mms_priv->mms_trans_p->itemid == IEC61850_ITEM_ID_$BR$_OR_$RP$){
                                    col_append_fstr(actx->pinfo->cinfo, COL_INFO, "GetRCBValuesRequest %s", private_data_get_moreCinfo(actx));
                                    proto_item_append_text(mms_priv->pdu_item, " [GetRCBValuesRequest]");
                                }else{
                                    col_append_fstr(actx->pinfo->cinfo, COL_INFO, "GetDataValueRequest %s", private_data_get_moreCinfo(actx));
                                    proto_item_append_text(mms_priv->pdu_item, " [GetDataValueRequest]");
                                }
                            } else if (mms_priv->mms_trans_p->conf_serv_pdu_type_req == MMS_IEC_61850_CONF_SERV_PDU_WRITE){
                                if(mms_priv->mms_trans_p->itemid == IEC61850_ITEM_ID_$BR$_OR_$RP$){
                                    col_append_fstr(actx->pinfo->cinfo, COL_INFO, "SetRCBValuesRequest %s", private_data_get_moreCinfo(actx));
                                    proto_item_append_text(mms_priv->pdu_item, " [SetRCBValuesRequest]");
                                }else{
                                    col_append_fstr(actx->pinfo->cinfo, COL_INFO, "SetDataValueRequest %s", private_data_get_moreCinfo(actx));
                                    proto_item_append_text(mms_priv->pdu_item, " [SetDataValueRequest]");
                                }
                            }else if(mms_priv->mms_trans_p->conf_serv_pdu_type_req == MMS_IEC_61850_CONF_SERV_PDU_SELECTWITHVALUE){
                                col_append_fstr(actx->pinfo->cinfo, COL_INFO, "SelectWithValueRequest %s", private_data_get_moreCinfo(actx));
                                proto_item_append_text(mms_priv->pdu_item, " [SelectWithValueRequest]");
                            }
                        }else if (mms_has_private_data(actx)){
                            col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s%s",
                                    private_data_get_preCinfo(actx), mms_MMSpdu_vals[branch_taken].strptr, private_data_get_moreCinfo(actx));
                        }
                    break;
                    case MMS_CONFIRMED_RESPONSE_PDU:
                        if(mms_priv->mms_trans_p){
                            if(mms_priv->mms_trans_p->conf_serv_pdu_type_req == MMS_IEC_61850_CONF_SERV_PDU_GET_SERV_DIR){
                                col_append_fstr(actx->pinfo->cinfo, COL_INFO, "GetServerDirectoryResponse %s", mms_priv->itemid_str);
                                proto_item_append_text(mms_priv->pdu_item, " [GetServerDirectoryResponse ]");
                            }else if(mms_priv->mms_trans_p->conf_serv_pdu_type_req == MMS_IEC_61850_CONF_SERV_PDU_GETLOGICALDEVICEDIRECTORY){
                                col_append_fstr(actx->pinfo->cinfo, COL_INFO, "GetLogicalDeviceDirectoryResponse%s", private_data_get_moreCinfo(actx));
                                proto_item_append_text(mms_priv->pdu_item, " [GetLogicalDeviceDirectoryResponse ]");
                            }else if(mms_priv->mms_trans_p->conf_serv_pdu_type_req == MMS_IEC_61850_CONF_SERV_PDU_GETDATASETDIRECTORY){
                                col_append_fstr(actx->pinfo->cinfo, COL_INFO, "GetDataSetDirectoryResponse%s", private_data_get_moreCinfo(actx));
                                proto_item_append_text(mms_priv->pdu_item, " [GetDataSetDirectoryResponse ]");
                            }else if(mms_priv->mms_trans_p->conf_serv_pdu_type_req == MMS_IEC_61850_CONF_SERV_PDU_GETDATADIRECTORY){
                                col_append_fstr(actx->pinfo->cinfo, COL_INFO, "GetDataDirectoryResponse%s", private_data_get_moreCinfo(actx));
                                proto_item_append_text(mms_priv->pdu_item, " [GetDataDirectoryResponse ]");
                            }else if (mms_priv->mms_trans_p->conf_serv_pdu_type_req == MMS_IEC_61850_CONF_SERV_PDU_READ){
                                if(mms_priv->mms_trans_p->itemid == IEC61850_ITEM_ID_$BR$_OR_$RP$){
                                    col_append_fstr(actx->pinfo->cinfo, COL_INFO, "GetRCBValuesResponse");
                                    proto_item_append_text(mms_priv->pdu_item, " [GetRCBValuesResponse]");
                                }else{
                                    col_append_fstr(actx->pinfo->cinfo, COL_INFO, "GetDataValueResponse");
                                    proto_item_append_text(mms_priv->pdu_item, " [GetDataValueResponse ]");
                                }
                                if(mms_priv->success == 1){
                                    col_append_fstr(actx->pinfo->cinfo, COL_INFO, " success");
                                }else{
                                     col_append_fstr(actx->pinfo->cinfo, COL_INFO, " failure");
                                }
                            } else if (mms_priv->mms_trans_p->conf_serv_pdu_type_req == MMS_IEC_61850_CONF_SERV_PDU_WRITE){
                                if(mms_priv->mms_trans_p->itemid == IEC61850_ITEM_ID_$BR$_OR_$RP$){
                                    col_append_fstr(actx->pinfo->cinfo, COL_INFO, "SetRCBValuesResponse %s", private_data_get_moreCinfo(actx));
                                    proto_item_append_text(mms_priv->pdu_item, " [SetRCBValuesResponse]");
                                }else{
                                    col_append_fstr(actx->pinfo->cinfo, COL_INFO, "SetDataValueResponse %s", private_data_get_moreCinfo(actx));
                                    proto_item_append_text(mms_priv->pdu_item, " [SetDataValueResponse]");
                                }
                            }else if(mms_priv->mms_trans_p->conf_serv_pdu_type_req == MMS_IEC_61850_CONF_SERV_PDU_SELECTWITHVALUE){
                                col_append_fstr(actx->pinfo->cinfo, COL_INFO, "SelectWithValueResponse %s", private_data_get_moreCinfo(actx));
                                proto_item_append_text(mms_priv->pdu_item, " [SelectWithValueResponse]");
                            }
                        }else if(mms_has_private_data(actx)){
                            col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s%s",
                                    private_data_get_preCinfo(actx), mms_MMSpdu_vals[branch_taken].strptr, private_data_get_moreCinfo(actx));
                        }
                    break;
                   default:
                        col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s%s",
                                private_data_get_preCinfo(actx), mms_MMSpdu_vals[branch_taken].strptr, private_data_get_moreCinfo(actx));
                   break;
                 }
            }else if (mms_has_private_data(actx)){
                    col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s%s%s",
                            private_data_get_preCinfo(actx), mms_MMSpdu_vals[branch_taken].strptr, private_data_get_moreCinfo(actx));
            }else{
                    col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s",
                            mms_MMSpdu_vals[branch_taken].strptr);
            }
    }


  return offset;
}


/*
* Dissect MMS PDUs inside a PPDU.
*/
static int
dissect_mms(tvbuff_t* tvb, packet_info* pinfo, proto_tree* parent_tree, void* data _U_)
{
    int offset = 0;
    int old_offset;
    proto_item* item = NULL;
    proto_tree* tree = NULL;
    asn1_ctx_t asn1_ctx;
    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

    if (parent_tree) {
        item = proto_tree_add_item(parent_tree, proto_mms, tvb, 0, -1, ENC_NA);
        tree = proto_item_add_subtree(item, ett_mms);
        asn1_ctx.subtree.top_tree = parent_tree;
    }
    if (use_iec61850_mapping) {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "MMS/IEC61850");
    }
    else {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "MMS");
    }
    col_clear(pinfo->cinfo, COL_INFO);

    while (tvb_reported_length_remaining(tvb, offset) > 0) {
        old_offset = offset;
        if (use_iec61850_mapping) {
            asn1_ctx.private_data = (void*)wmem_new0(pinfo->pool, mms_actx_private_data_t);
        }
        offset = dissect_mms_MMSpdu(false, tvb, offset, &asn1_ctx, tree, -1);
        if (asn1_ctx.private_data) {
            wmem_free(pinfo->pool, asn1_ctx.private_data);
        }
        if (offset == old_offset) {
            proto_tree_add_expert(tree, pinfo, &ei_mms_zero_pdu, tvb, offset, -1);
            break;
        }
    }
    return tvb_captured_length(tvb);
}


/*--- proto_register_mms -------------------------------------------*/
void proto_register_mms(void) {

    /* List of fields */
    static hf_register_info hf[] =
    {
        { &hf_mms_response_in,
                { "Response In", "mms.response_in",
                FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_RESPONSE), 0x0,
                "The response to this mms request is in this frame", HFILL }
        },
        { &hf_mms_response_to,
                { "Request In", "mms.response_to",
                FT_FRAMENUM, BASE_NONE, FRAMENUM_TYPE(FT_FRAMENUM_REQUEST), 0x0,
                "This is a response to the mms request in this frame", HFILL }
        },
        { &hf_mms_response_time,
                { "Response Time", "mms.response_time",
                FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
                "The time between the Call and the Reply", HFILL }
        },
        { &hf_mms_iec61850_rptid,
          { "RptID", "mms.iec61850.rptid",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_mms_iec61850_reported_optflds,
          { "Reported OptFlds", "mms.iec61850.reported_optfld",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_mms_iec61850_seqnum,
          { "SeqNum", "mms.iec61850.seqnum",
            FT_INT32, BASE_DEC, NULL, 0,
            NULL, HFILL }},
        { &hf_mms_iec61850_timeofentry,
          { "TimeOfEntry", "mms.iec61850.timeofentry",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_mms_iec61850_datset,
          { "DatSet", "mms.iec61850.datset",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_mms_iec61850_bufovfl,
          { "BufOvfl", "mms.iec61850.bufovfl",
            FT_BOOLEAN, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_mms_iec61850_confrev,
          { "ConfRev", "mms.iec61850.confrev",
            FT_INT32, BASE_DEC, NULL, 0,
            NULL, HFILL }},
        { &hf_mms_iec61850_inclusion_bitstring,
          { "Inclusion-bitstring", "mms.iec61850.inclusion_bitstring",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL }},
        { &hf_mms_iec61850_ctlModel,
        { "ctlModel", "mms.iec61850.ctlmodel",
            FT_UINT8, BASE_DEC, VALS(mms_iec6150_cntmodel_vals), 0,
            NULL, HFILL }},
        { &hf_mms_iec61850_QualityC0,
        { "Validity", "mms.iec61850.validity",
            FT_UINT8, BASE_HEX, VALS(mms_iec6150_validity_vals), 0xC0,
            NULL, HFILL }},
        { &hf_mms_iec61850_Quality20,
        { "Overflow", "mms.iec61850.overflow",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL }},
        { &hf_mms_iec61850_Quality10,
        { "OutofRange", "mms.iec61850.outofrange",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }},
        { &hf_mms_iec61850_Quality8,
        { "BadReference", "mms.iec61850.badreference",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }},
        { &hf_mms_iec61850_Quality4,
        { "Oscillatory", "mms.iec61850.oscillatory",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL }},
        { &hf_mms_iec61850_Quality2,
        { "Failure", "mms.iec61850.failure",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }},
        { &hf_mms_iec61850_Quality1,
        { "OldData", "mms.iec61850.oldData",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }},
        { &hf_mms_iec61850_Quality0080,
        { "Inconsistent", "mms.iec61850.inconsistent",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL }},
        { &hf_mms_iec61850_Quality0040,
        { "Inaccurate", "mms.iec61850.inaccurate",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL }},
        { &hf_mms_iec61850_Quality0020,
        { "Source", "mms.iec61850.source",
            FT_UINT8, BASE_HEX, VALS(mms_iec6150_source_vals), 0x20,
            NULL, HFILL }},
        { &hf_mms_iec61850_Quality0010,
        { "Test", "mms.iec61850.test",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL }},
        { &hf_mms_iec61850_Quality0008,
        { "OperatorBlocked", "mms.iec61850.operatorblocked",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL }},
        { &hf_mms_iec61850_quality_bitstring,
          { "Quality", "mms.iec61850.quality_bitstring",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL } },
        { &hf_mms_iec61850_timequality80,
        { "Leap Second Known", "mms.iec61850.leapsecondknown",
            FT_BOOLEAN, 8, NULL, 0x80,
            NULL, HFILL } },
        { &hf_mms_iec61850_timequality40,
        { "ClockFailure", "mms.iec61850.clockfailure",
            FT_BOOLEAN, 8, NULL, 0x40,
            NULL, HFILL } },
        { &hf_mms_iec61850_timequality20,
        { "Clock not synchronized", "mms.iec61850.clocknotsynchronized",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL } },
        { &hf_mms_iec61850_timequality1F,
        { "Time Accuracy", "mms.iec61850.timeaccuracy",
            FT_UINT8, BASE_HEX, VALS(mms_iec6150_timeaccuracy_vals), 0x1F,
            NULL, HFILL } },
        { &hf_mms_iec61850_check_bitstring,
          { "Check", "mms.iec61850.check_bitstring",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL } },
        { &hf_mms_iec61850_check_b1,
        { "Synchrocheck", "mms.iec61850.synchrocheck",
            FT_BOOLEAN, 2, NULL, 0x2,
            NULL, HFILL } },
        { &hf_mms_iec61850_check_b0,
        { "Interlock-check", "mms.iec61850.interlockcheck",
            FT_BOOLEAN, 2, NULL, 0x1,
            NULL, HFILL } },
        { &hf_mms_iec61850_orcategory,
        { "orCategory", "mms.iec61850.orcategory",
            FT_UINT8, BASE_DEC, VALS(mms_iec6150_orcategory_vals), 0,
            NULL, HFILL } },
        { &hf_mms_iec61850_beh$stval,
        { "beh", "mms.iec61850.beh",
            FT_UINT8, BASE_DEC, VALS(mms_iec6150_beh_vals), 0,
            NULL, HFILL } },
        { &hf_mms_iec61850_mod$stval,
        { "mod", "mms.iec61850.mod",
            FT_UINT8, BASE_DEC, VALS(mms_iec6150_beh_vals), 0,
            NULL, HFILL } },
        { &hf_mms_iec61850_health$stval,
        { "health", "mms.iec61850.health",
            FT_UINT8, BASE_DEC, VALS(mms_iec6150_health_vals), 0,
            NULL, HFILL } },
        { &hf_mms_iec61850_ctlval,
        { "ctlVal", "mms.iec61850.ctlval",
            FT_BOOLEAN, BASE_NONE, NULL, 0,
            NULL, HFILL } },
        { &hf_mms_iec61850_origin,
          { "Origin", "mms.iec61850.origin",
            FT_UINT32, BASE_DEC, NULL, 0,
            NULL, HFILL } },
        { &hf_mms_iec61850_origin_orcat,
        { "Origin Category", "mms.iec61850.orcat",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL } },
        { &hf_mms_iec61850_origin_orident,
        { "Origin Identifier", "mms.iec61850.orident",
            FT_BYTES, BASE_NONE, NULL, 0,
            NULL, HFILL } },
        { &hf_mms_iec61850_ctlNum,
        { "ctlNum", "mms.iec61850.ctlnum",
            FT_INT8, BASE_DEC, NULL, 0,
            NULL, HFILL } },
        { &hf_mms_iec61850_T,
        { "T(Timestamp)", "mms.iec61850.timestamp",
            FT_STRING, BASE_NONE, NULL, 0,
            NULL, HFILL } },
        { &hf_mms_iec61850_test,
        { "Test", "mms.iec61850.test",
            FT_BOOLEAN, BASE_NONE, NULL, 0,
            NULL, HFILL }},
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
    { &hf_mms_confirmedServiceRequest_deleteEventCondition,
      { "deleteEventCondition", "mms.confirmedServiceRequest.deleteEventCondition",
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
    { &hf_mms_confirmedServiceRequest_deleteEventAction,
      { "deleteEventAction", "mms.confirmedServiceRequest.deleteEventAction",
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
    { &hf_mms_confirmedServiceRequest_deleteEventEnrollment,
      { "deleteEventEnrollment", "mms.confirmedServiceRequest.deleteEventEnrollment",
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
    { &hf_mms_confirmedServiceResponse_deleteEventCondition,
      { "deleteEventCondition", "mms.confirmedServiceResponse.deleteEventCondition",
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
    { &hf_mms_confirmedServiceRequest_deleteEventAction_01,
      { "deleteEventAction", "mms.confirmedServiceRequest.deleteEventAction",
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
    { &hf_mms_confirmedServiceResponse_deleteEventEnrollment,
      { "deleteEventEnrollment", "mms.confirmedServiceResponse.deleteEventEnrollment",
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
    { &hf_mms_objectName_domain_specific_itemId,
      { "itemId", "mms.itemId",
        FT_STRING, BASE_NONE, NULL, 0,
        "ObjectName_domain_specific_itemid", HFILL }},
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
    { &hf_mms_additionalService,
      { "additionalService", "mms.additionalService",
        FT_UINT32, BASE_DEC, VALS(mms_AdditionalService_Error_vals), 0,
        "AdditionalService_Error", HFILL }},
    { &hf_mms_changeAccessControl,
      { "changeAccessControl", "mms.changeAccessControl",
        FT_INT32, BASE_DEC, NULL, 0,
        "ChangeAccessControl_Error", HFILL }},
    { &hf_mms_defineEcl,
      { "defineEcl", "mms.defineEcl",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "DefineEventConditionList_Error", HFILL }},
    { &hf_mms_addECLReference,
      { "addECLReference", "mms.addECLReference",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "AddEventConditionListReference_Error", HFILL }},
    { &hf_mms_removeECLReference,
      { "removeECLReference", "mms.removeECLReference",
        FT_UINT32, BASE_DEC, VALS(mms_RemoveEventConditionListReference_Error_vals), 0,
        "RemoveEventConditionListReference_Error", HFILL }},
    { &hf_mms_initiateUC,
      { "initiateUC", "mms.initiateUC",
        FT_UINT32, BASE_DEC, VALS(mms_InitiateUnitControl_Error_vals), 0,
        "InitiateUnitControl_Error", HFILL }},
    { &hf_mms_startUC,
      { "startUC", "mms.startUC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "StartUnitControl_Error", HFILL }},
    { &hf_mms_stopUC,
      { "stopUC", "mms.stopUC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "StopUnitControl_Error", HFILL }},
    { &hf_mms_deleteUC,
      { "deleteUC", "mms.deleteUC",
        FT_UINT32, BASE_DEC, VALS(mms_DeleteUnitControl_Error_vals), 0,
        "DeleteUnitControl_Error", HFILL }},
    { &hf_mms_loadUCFromFile,
      { "loadUCFromFile", "mms.loadUCFromFile",
        FT_UINT32, BASE_DEC, VALS(mms_LoadUnitControlFromFile_Error_vals), 0,
        "LoadUnitControlFromFile_Error", HFILL }},
    { &hf_mms_eventCondition,
      { "eventCondition", "mms.eventCondition",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_mms_eventConditionList,
      { "eventConditionList", "mms.eventConditionList",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_mms_domain,
      { "domain", "mms.domain",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_mms_programInvocation,
      { "programInvocation", "mms.programInvocation",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_mms_programInvocationName,
      { "programInvocationName", "mms.programInvocationName",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_mms_programInvocationState,
      { "programInvocationState", "mms.programInvocationState",
        FT_INT32, BASE_DEC, VALS(mms_ProgramInvocationState_vals), 0,
        NULL, HFILL }},
    { &hf_mms_none,
      { "none", "mms.none_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
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
    { &hf_mms_extendedObjectClass,
      { "extendedObjectClass", "mms.extendedObjectClass",
        FT_UINT32, BASE_DEC, VALS(mms_T_extendedObjectClass_vals), 0,
        NULL, HFILL }},
    { &hf_mms_objectClass,
      { "objectClass", "mms.objectClass",
        FT_INT32, BASE_DEC, VALS(mms_ObjectClass_vals), 0,
        NULL, HFILL }},
    { &hf_mms_objectScope,
      { "objectScope", "mms.objectScope",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectScope_vals), 0,
        NULL, HFILL }},
    { &hf_mms_getNameList_Request_continueAfter,
      { "continueAfter", "mms.getNameList-Request_continueAfter",
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
        FT_INT32, BASE_DEC, VALS(mms_T_objectClass_vals), 0,
        NULL, HFILL }},
    { &hf_mms_currentName,
      { "currentName", "mms.currentName",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_mms_newIdentifier,
      { "newIdentifier", "mms.newIdentifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "Identifier", HFILL }},
    { &hf_mms_getCapabilityList_Request_continueAfter,
      { "continueAfter", "mms.getCapabilityList-Request_continueAfter",
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
    { &hf_mms_getDomainAttributes_Response_state,
      { "state", "mms.getDomainAttributes-Response_state",
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
    { &hf_mms_getProgramInvocationAttributes_Response_state,
      { "state", "mms.getProgramInvocationAttributes-Response_state",
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
    { &hf_mms_typeSpecification_bit_string,
      { "bit-string", "mms.typeSpecification_bit-string",
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
    { &hf_mms_typeSpecification_octet_string,
      { "octet-string", "mms.typeSpecification.octet-string",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer32", HFILL }},
    { &hf_mms_typeSpecification_visible_string,
      { "visible-string", "mms.typeSpecification.visible-string",
        FT_INT32, BASE_DEC, NULL, 0,
        "Integer32", HFILL }},
    { &hf_mms_generalized_time,
      { "generalized-time", "mms.generalized_time_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_typeSpecification_binary_time,
      { "binary-time", "mms.typeSpecification.binary-time",
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
        NULL, HFILL }},
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
    { &hf_mms_listOfAccessResult_01,
      { "listOfAccessResult", "mms.listOfAccessResult",
        FT_UINT32, BASE_DEC, NULL, 0,
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
        "T_structure_01", HFILL }},
    { &hf_mms_structure_item,
      { "Data", "mms.Data",
        FT_UINT32, BASE_DEC, VALS(mms_Data_vals), 0,
        NULL, HFILL }},
    { &hf_mms_boolean_01,
      { "boolean", "mms.boolean",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_data_bit_string,
      { "bit-string", "mms.data_bit-string",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_data_bit_string", HFILL }},
    { &hf_mms_integer_01,
      { "integer", "mms.integer",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_unsigned_01,
      { "unsigned", "mms.unsigned",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_mms_floating_point,
      { "floating-point", "mms.floating_point",
        FT_BYTES, BASE_NONE, NULL, 0,
        "FloatingPoint", HFILL }},
    { &hf_mms_data_octet_string,
      { "octet-string", "mms.data.octet-string",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_data_octet_string", HFILL }},
    { &hf_mms_data_visible_string,
      { "visible-string", "mms.data.visible-string",
        FT_STRING, BASE_NONE, NULL, 0,
        "T_data_visible_string", HFILL }},
    { &hf_mms_data_binary_time,
      { "binary-time", "mms.data.binary-time",
        FT_STRING, BASE_NONE, NULL, 0,
        "T_data_binary_time", HFILL }},
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
    { &hf_mms_reportSemaphoreEntryStatus_Request_state,
      { "state", "mms.reportSemaphoreEntryStatus-Request_state",
        FT_INT32, BASE_DEC, VALS(mms_T_reportSemaphoreEntryStatus_Request_state_vals), 0,
        "T_reportSemaphoreEntryStatus_Request_state", HFILL }},
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
    { &hf_mms_getEventEnrollmentAttributes_Request_continueAfter,
      { "continueAfter", "mms.getEventEnrollmentAttributes-Request_continueAfter",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "ObjectName", HFILL }},
    { &hf_mms_eventConditionName_01,
      { "eventConditionName", "mms.eventConditionName",
        FT_UINT32, BASE_DEC, VALS(mms_T_eventConditionName_vals), 0,
        NULL, HFILL }},
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
    { &hf_mms_alterEventEnrollment_Response_currentState_state,
      { "state", "mms.alterEventEnrollment-Response_currentState_state",
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
    { &hf_mms_continueAfter,
      { "continueAfter", "mms.continueAfter",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "ObjectName", HFILL }},
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
    { &hf_mms_getAlarmEnrollmentSummary_Request_continueAfter,
      { "continueAfter", "mms.getAlarmEnrollmentSummary-Request_continueAfter",
        FT_UINT32, BASE_DEC, VALS(mms_ObjectName_vals), 0,
        "ObjectName", HFILL }},
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
    { &hf_mms_fileDirectory_Request_continueAfter,
      { "continueAfter", "mms.fileDirectory-Request_continueAfter",
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
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_mms_ReportedOptFlds_reserved,
      { "reserved", "mms.ReportedOptFlds.reserved",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_mms_ReportedOptFlds_sequence_number,
      { "sequence-number", "mms.ReportedOptFlds.sequence.number",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_mms_ReportedOptFlds_report_time_stamp,
      { "report-time-stamp", "mms.ReportedOptFlds.report.time.stamp",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_mms_ReportedOptFlds_reason_for_inclusion,
      { "reason-for-inclusion", "mms.ReportedOptFlds.reason.for.inclusion",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_mms_ReportedOptFlds_data_set_name,
      { "data-set-name", "mms.ReportedOptFlds.data.set.name",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_mms_ReportedOptFlds_data_reference,
      { "data-reference", "mms.ReportedOptFlds.data.reference",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_mms_ReportedOptFlds_buffer_overflow,
      { "buffer-overflow", "mms.ReportedOptFlds.buffer.overflow",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_mms_ReportedOptFlds_entryID,
      { "entryID", "mms.ReportedOptFlds.entryID",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_mms_ReportedOptFlds_conf_revision,
      { "conf-revision", "mms.ReportedOptFlds.conf.revision",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_mms_ReportedOptFlds_segmentation,
      { "segmentation", "mms.ReportedOptFlds.segmentation",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_mms_ParameterSupportOptions_str1,
      { "str1", "mms.ParameterSupportOptions.str1",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_mms_ParameterSupportOptions_str2,
      { "str2", "mms.ParameterSupportOptions.str2",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_mms_ParameterSupportOptions_vnam,
      { "vnam", "mms.ParameterSupportOptions.vnam",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_mms_ParameterSupportOptions_valt,
      { "valt", "mms.ParameterSupportOptions.valt",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_mms_ParameterSupportOptions_vadr,
      { "vadr", "mms.ParameterSupportOptions.vadr",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_mms_ParameterSupportOptions_vsca,
      { "vsca", "mms.ParameterSupportOptions.vsca",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_mms_ParameterSupportOptions_tpy,
      { "tpy", "mms.ParameterSupportOptions.tpy",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_mms_ParameterSupportOptions_vlis,
      { "vlis", "mms.ParameterSupportOptions.vlis",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_mms_ParameterSupportOptions_real,
      { "real", "mms.ParameterSupportOptions.real",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_mms_ParameterSupportOptions_spare_bit9,
      { "spare_bit9", "mms.ParameterSupportOptions.spare.bit9",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_mms_ParameterSupportOptions_cei,
      { "cei", "mms.ParameterSupportOptions.cei",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_status,
      { "status", "mms.ServiceSupportOptions.status",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_getNameList,
      { "getNameList", "mms.ServiceSupportOptions.getNameList",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_identify,
      { "identify", "mms.ServiceSupportOptions.identify",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_rename,
      { "rename", "mms.ServiceSupportOptions.rename",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_read,
      { "read", "mms.ServiceSupportOptions.read",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_write,
      { "write", "mms.ServiceSupportOptions.write",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_getVariableAccessAttributes,
      { "getVariableAccessAttributes", "mms.ServiceSupportOptions.getVariableAccessAttributes",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_defineNamedVariable,
      { "defineNamedVariable", "mms.ServiceSupportOptions.defineNamedVariable",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_defineScatteredAccess,
      { "defineScatteredAccess", "mms.ServiceSupportOptions.defineScatteredAccess",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_getScatteredAccessAttributes,
      { "getScatteredAccessAttributes", "mms.ServiceSupportOptions.getScatteredAccessAttributes",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_deleteVariableAccess,
      { "deleteVariableAccess", "mms.ServiceSupportOptions.deleteVariableAccess",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_defineNamedVariableList,
      { "defineNamedVariableList", "mms.ServiceSupportOptions.defineNamedVariableList",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_getNamedVariableListAttributes,
      { "getNamedVariableListAttributes", "mms.ServiceSupportOptions.getNamedVariableListAttributes",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_deleteNamedVariableList,
      { "deleteNamedVariableList", "mms.ServiceSupportOptions.deleteNamedVariableList",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_defineNamedType,
      { "defineNamedType", "mms.ServiceSupportOptions.defineNamedType",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_getNamedTypeAttributes,
      { "getNamedTypeAttributes", "mms.ServiceSupportOptions.getNamedTypeAttributes",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_deleteNamedType,
      { "deleteNamedType", "mms.ServiceSupportOptions.deleteNamedType",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_input,
      { "input", "mms.ServiceSupportOptions.input",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_output,
      { "output", "mms.ServiceSupportOptions.output",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_takeControl,
      { "takeControl", "mms.ServiceSupportOptions.takeControl",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_relinquishControl,
      { "relinquishControl", "mms.ServiceSupportOptions.relinquishControl",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_defineSemaphore,
      { "defineSemaphore", "mms.ServiceSupportOptions.defineSemaphore",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_deleteSemaphore,
      { "deleteSemaphore", "mms.ServiceSupportOptions.deleteSemaphore",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_reportSemaphoreStatus,
      { "reportSemaphoreStatus", "mms.ServiceSupportOptions.reportSemaphoreStatus",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_reportPoolSemaphoreStatus,
      { "reportPoolSemaphoreStatus", "mms.ServiceSupportOptions.reportPoolSemaphoreStatus",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_reportSemaphoreEntryStatus,
      { "reportSemaphoreEntryStatus", "mms.ServiceSupportOptions.reportSemaphoreEntryStatus",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_initiateDownloadSequence,
      { "initiateDownloadSequence", "mms.ServiceSupportOptions.initiateDownloadSequence",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_downloadSegment,
      { "downloadSegment", "mms.ServiceSupportOptions.downloadSegment",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_terminateDownloadSequence,
      { "terminateDownloadSequence", "mms.ServiceSupportOptions.terminateDownloadSequence",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_initiateUploadSequence,
      { "initiateUploadSequence", "mms.ServiceSupportOptions.initiateUploadSequence",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_uploadSegment,
      { "uploadSegment", "mms.ServiceSupportOptions.uploadSegment",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_terminateUploadSequence,
      { "terminateUploadSequence", "mms.ServiceSupportOptions.terminateUploadSequence",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_requestDomainDownload,
      { "requestDomainDownload", "mms.ServiceSupportOptions.requestDomainDownload",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_requestDomainUpload,
      { "requestDomainUpload", "mms.ServiceSupportOptions.requestDomainUpload",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_loadDomainContent,
      { "loadDomainContent", "mms.ServiceSupportOptions.loadDomainContent",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_storeDomainContent,
      { "storeDomainContent", "mms.ServiceSupportOptions.storeDomainContent",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_deleteDomain,
      { "deleteDomain", "mms.ServiceSupportOptions.deleteDomain",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_getDomainAttributes,
      { "getDomainAttributes", "mms.ServiceSupportOptions.getDomainAttributes",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_createProgramInvocation,
      { "createProgramInvocation", "mms.ServiceSupportOptions.createProgramInvocation",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_deleteProgramInvocation,
      { "deleteProgramInvocation", "mms.ServiceSupportOptions.deleteProgramInvocation",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_start,
      { "start", "mms.ServiceSupportOptions.start",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_stop,
      { "stop", "mms.ServiceSupportOptions.stop",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_resume,
      { "resume", "mms.ServiceSupportOptions.resume",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_reset,
      { "reset", "mms.ServiceSupportOptions.reset",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_kill,
      { "kill", "mms.ServiceSupportOptions.kill",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_getProgramInvocationAttributes,
      { "getProgramInvocationAttributes", "mms.ServiceSupportOptions.getProgramInvocationAttributes",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_obtainFile,
      { "obtainFile", "mms.ServiceSupportOptions.obtainFile",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_defineEventCondition,
      { "defineEventCondition", "mms.ServiceSupportOptions.defineEventCondition",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_deleteEventCondition,
      { "deleteEventCondition", "mms.ServiceSupportOptions.deleteEventCondition",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_getEventConditionAttributes,
      { "getEventConditionAttributes", "mms.ServiceSupportOptions.getEventConditionAttributes",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_reportEventConditionStatus,
      { "reportEventConditionStatus", "mms.ServiceSupportOptions.reportEventConditionStatus",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_alterEventConditionMonitoring,
      { "alterEventConditionMonitoring", "mms.ServiceSupportOptions.alterEventConditionMonitoring",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_triggerEvent,
      { "triggerEvent", "mms.ServiceSupportOptions.triggerEvent",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_defineEventAction,
      { "defineEventAction", "mms.ServiceSupportOptions.defineEventAction",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_deleteEventAction,
      { "deleteEventAction", "mms.ServiceSupportOptions.deleteEventAction",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_getEventActionAttributes,
      { "getEventActionAttributes", "mms.ServiceSupportOptions.getEventActionAttributes",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_reportActionStatus,
      { "reportActionStatus", "mms.ServiceSupportOptions.reportActionStatus",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_defineEventEnrollment,
      { "defineEventEnrollment", "mms.ServiceSupportOptions.defineEventEnrollment",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_deleteEventEnrollment,
      { "deleteEventEnrollment", "mms.ServiceSupportOptions.deleteEventEnrollment",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_alterEventEnrollment,
      { "alterEventEnrollment", "mms.ServiceSupportOptions.alterEventEnrollment",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_reportEventEnrollmentStatus,
      { "reportEventEnrollmentStatus", "mms.ServiceSupportOptions.reportEventEnrollmentStatus",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_getEventEnrollmentAttributes,
      { "getEventEnrollmentAttributes", "mms.ServiceSupportOptions.getEventEnrollmentAttributes",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_acknowledgeEventNotification,
      { "acknowledgeEventNotification", "mms.ServiceSupportOptions.acknowledgeEventNotification",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_getAlarmSummary,
      { "getAlarmSummary", "mms.ServiceSupportOptions.getAlarmSummary",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_getAlarmEnrollmentSummary,
      { "getAlarmEnrollmentSummary", "mms.ServiceSupportOptions.getAlarmEnrollmentSummary",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_readJournal,
      { "readJournal", "mms.ServiceSupportOptions.readJournal",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_writeJournal,
      { "writeJournal", "mms.ServiceSupportOptions.writeJournal",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_initializeJournal,
      { "initializeJournal", "mms.ServiceSupportOptions.initializeJournal",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_reportJournalStatus,
      { "reportJournalStatus", "mms.ServiceSupportOptions.reportJournalStatus",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_createJournal,
      { "createJournal", "mms.ServiceSupportOptions.createJournal",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_deleteJournal,
      { "deleteJournal", "mms.ServiceSupportOptions.deleteJournal",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_getCapabilityList,
      { "getCapabilityList", "mms.ServiceSupportOptions.getCapabilityList",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_fileOpen,
      { "fileOpen", "mms.ServiceSupportOptions.fileOpen",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_fileRead,
      { "fileRead", "mms.ServiceSupportOptions.fileRead",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_fileClose,
      { "fileClose", "mms.ServiceSupportOptions.fileClose",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_fileRename,
      { "fileRename", "mms.ServiceSupportOptions.fileRename",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_fileDelete,
      { "fileDelete", "mms.ServiceSupportOptions.fileDelete",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_fileDirectory,
      { "fileDirectory", "mms.ServiceSupportOptions.fileDirectory",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_unsolicitedStatus,
      { "unsolicitedStatus", "mms.ServiceSupportOptions.unsolicitedStatus",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_informationReport,
      { "informationReport", "mms.ServiceSupportOptions.informationReport",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_eventNotification,
      { "eventNotification", "mms.ServiceSupportOptions.eventNotification",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_attachToEventCondition,
      { "attachToEventCondition", "mms.ServiceSupportOptions.attachToEventCondition",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_attachToSemaphore,
      { "attachToSemaphore", "mms.ServiceSupportOptions.attachToSemaphore",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_conclude,
      { "conclude", "mms.ServiceSupportOptions.conclude",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_mms_ServiceSupportOptions_cancel,
      { "cancel", "mms.ServiceSupportOptions.cancel",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_mms_Transitions_idle_to_disabled,
      { "idle-to-disabled", "mms.Transitions.idle.to.disabled",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_mms_Transitions_active_to_disabled,
      { "active-to-disabled", "mms.Transitions.active.to.disabled",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_mms_Transitions_disabled_to_idle,
      { "disabled-to-idle", "mms.Transitions.disabled.to.idle",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_mms_Transitions_active_to_idle,
      { "active-to-idle", "mms.Transitions.active.to.idle",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_mms_Transitions_disabled_to_active,
      { "disabled-to-active", "mms.Transitions.disabled.to.active",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_mms_Transitions_idle_to_active,
      { "idle-to-active", "mms.Transitions.idle.to.active",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_mms_Transitions_any_to_deleted,
      { "any-to-deleted", "mms.Transitions.any.to.deleted",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    };

    /* List of subtrees */
    static int* ett[] = {
            &ett_mms,
            &ett_mms_iec61850_quality_bitstring,
            &ett_mms_iec61850_check_bitstring,
    &ett_mms_ReportedOptFlds,
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
    &ett_mms_AdditionalService_Error,
    &ett_mms_RemoveEventConditionListReference_Error,
    &ett_mms_InitiateUnitControl_Error,
    &ett_mms_StartUnitControl_Error,
    &ett_mms_StopUnitControl_Error,
    &ett_mms_DeleteUnitControl_Error,
    &ett_mms_LoadUnitControlFromFile_Error,
    &ett_mms_RejectPDU,
    &ett_mms_T_rejectReason,
    &ett_mms_Status_Response,
    &ett_mms_ObjectScope,
    &ett_mms_GetNameList_Request,
    &ett_mms_T_extendedObjectClass,
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
    &ett_mms_T_listOfData,
    &ett_mms_Write_Response,
    &ett_mms_Write_Response_item,
    &ett_mms_InformationReport,
    &ett_mms_T_listOfAccessResult,
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
    &ett_mms_SEQUENCE_OF_Data,
    &ett_mms_T_structure_01,
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
    };

    static ei_register_info ei[] = {
            { &ei_mms_mal_timeofday_encoding, { "mms.malformed.timeofday_encoding", PI_MALFORMED, PI_WARN, "BER Error: malformed TimeOfDay encoding", EXPFILL }},
            { &ei_mms_mal_utctime_encoding, { "mms.malformed.utctime", PI_MALFORMED, PI_WARN, "BER Error: malformed IEC61850 UTCTime encoding", EXPFILL }},
            { &ei_mms_zero_pdu, { "mms.zero_pdu", PI_PROTOCOL, PI_ERROR, "Internal error, zero-byte MMS PDU", EXPFILL }},
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

    /* Setting to enable/disable the IEC-61850 mapping on MMS */
    module_t* mms_module = prefs_register_protocol(proto_mms, proto_reg_handoff_mms);

    prefs_register_bool_preference(mms_module, "use_iec61850_mapping",
        "Dissect MMS as IEC-61850",
        "Enables or disables dissection as IEC-61850 on top of MMS",
        &use_iec61850_mapping);
}


static bool
dissect_mms_heur(tvbuff_t* tvb, packet_info* pinfo, proto_tree* parent_tree, void* data)
{
    /* must check that this really is an mms packet */
    int offset = 0;
    uint32_t length = 0;
    uint32_t oct;
    int idx = 0;

    int8_t tmp_class;
    bool tmp_pc;
    int32_t tmp_tag;

    /* first, check do we have at least 2 bytes (pdu) */
    if (!tvb_bytes_exist(tvb, 0, 2))
        return false;	/* no */

    /* can we recognize MMS PDU ? Return false if  not */
    /*   get MMS PDU type */
    offset = get_ber_identifier(tvb, offset, &tmp_class, &tmp_pc, &tmp_tag);

    /* check MMS type */

    /* Class should be constructed */
    if (tmp_class != BER_CLASS_CON)
        return false;

    /* see if the tag is a valid MMS PDU */
    try_val_to_str_idx(tmp_tag, mms_MMSpdu_vals, &idx);
    if (idx == -1) {
        return false;  /* no, it isn't an MMS PDU */
    }

    /* check MMS length  */
    oct = tvb_get_uint8(tvb, offset) & 0x7F;
    if (oct == 0)
        /* MMS requires length after tag so not MMS if indefinite length*/
        return false;

    offset = get_ber_length(tvb, offset, &length, NULL);
    /* do we have enough bytes? */
    if (!tvb_bytes_exist(tvb, offset, length))
        return false;

    dissect_mms(tvb, pinfo, parent_tree, data);
    return true;
}

/*--- proto_reg_handoff_mms --- */
void proto_reg_handoff_mms(void) {
    register_ber_oid_dissector("1.0.9506.2.3", dissect_mms, proto_mms, "MMS");
    register_ber_oid_dissector("1.0.9506.2.1", dissect_mms, proto_mms, "mms-abstract-syntax-version1(1)");
    heur_dissector_add("cotp", dissect_mms_heur, "MMS over COTP", "mms_cotp", proto_mms, HEURISTIC_ENABLE);
    heur_dissector_add("cotp_is", dissect_mms_heur, "MMS over COTP (inactive subset)", "mms_cotp_is", proto_mms, HEURISTIC_ENABLE);
}

