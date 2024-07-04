/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-cmip.c                                                              */
/* asn2wrs.py -b -q -L -p cmip -c ./cmip.cnf -s ./packet-cmip-template -D . -O ../.. CMIP-1.asn CMIP-A-ABORT-Information.asn CMIP-A-ASSOCIATE-Information.asn ../x721/Attribute-ASN1Module.asn ../ros/Remote-Operations-Information-Objects.asn ../ros/Remote-Operations-Generic-ROS-PDUs.asn */

/* packet-cmip.c
 * Routines for X.711 CMIP packet dissection
 *   Ronnie Sahlberg 2004
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/oids.h>
#include <epan/asn1.h>
#include <epan/proto_data.h>

#include "packet-ber.h"
#include "packet-acse.h"
#include "packet-x509if.h"
#include "packet-cmip.h"

#define PNAME  "X711 CMIP"
#define PSNAME "CMIP"
#define PFNAME "cmip"

void proto_register_cmip(void);
void proto_reg_handoff_cmip(void);

/* XXX some stuff we need until we can get rid of it */
#include "packet-ses.h"
#include "packet-pres.h"

/* Initialize the protocol and registered fields */
static int proto_cmip;
static int hf_cmip_actionType_OID;
static int hf_cmip_eventType_OID;
static int hf_cmip_attributeId_OID;
static int hf_cmip_errorId_OID;

static int hf_cmip_BaseManagedObjectId_PDU;       /* BaseManagedObjectId */
static int hf_cmip_EventTypeId_PDU;               /* EventTypeId */
static int hf_cmip_ObjectClass_PDU;               /* ObjectClass */
static int hf_cmip_ActiveDestination_PDU;         /* ActiveDestination */
static int hf_cmip_AdditionalText_PDU;            /* AdditionalText */
static int hf_cmip_AdditionalInformation_PDU;     /* AdditionalInformation */
static int hf_cmip_Allomorphs_PDU;                /* Allomorphs */
static int hf_cmip_AdministrativeState_PDU;       /* AdministrativeState */
static int hf_cmip_AttributeIdentifierList_PDU;   /* AttributeIdentifierList */
static int hf_cmip_AttributeList_PDU;             /* AttributeList */
static int hf_cmip_AttributeValueChangeDefinition_PDU;  /* AttributeValueChangeDefinition */
static int hf_cmip_AlarmStatus_PDU;               /* AlarmStatus */
static int hf_cmip_AvailabilityStatus_PDU;        /* AvailabilityStatus */
static int hf_cmip_BackedUpStatus_PDU;            /* BackedUpStatus */
static int hf_cmip_BackUpDestinationList_PDU;     /* BackUpDestinationList */
static int hf_cmip_BackUpRelationshipObject_PDU;  /* BackUpRelationshipObject */
static int hf_cmip_CapacityAlarmThreshold_PDU;    /* CapacityAlarmThreshold */
static int hf_cmip_ConfirmedMode_PDU;             /* ConfirmedMode */
static int hf_cmip_ControlStatus_PDU;             /* ControlStatus */
static int hf_cmip_CorrelatedNotifications_PDU;   /* CorrelatedNotifications */
static int hf_cmip_CurrentLogSize_PDU;            /* CurrentLogSize */
static int hf_cmip_Destination_PDU;               /* Destination */
static int hf_cmip_DiscriminatorConstruct_PDU;    /* DiscriminatorConstruct */
static int hf_cmip_EventTime_PDU;                 /* EventTime */
static int hf_cmip_GroupObjects_PDU;              /* GroupObjects */
static int hf_cmip_IntervalsOfDay_PDU;            /* IntervalsOfDay */
static int hf_cmip_LifecycleState_PDU;            /* LifecycleState */
static int hf_cmip_LogFullAction_PDU;             /* LogFullAction */
static int hf_cmip_LoggingTime_PDU;               /* LoggingTime */
static int hf_cmip_LogRecordId_PDU;               /* LogRecordId */
static int hf_cmip_MaxLogSize_PDU;                /* MaxLogSize */
static int hf_cmip_MonitoredAttributes_PDU;       /* MonitoredAttributes */
static int hf_cmip_NameBinding_PDU;               /* NameBinding */
static int hf_cmip_NotificationIdentifier_PDU;    /* NotificationIdentifier */
static int hf_cmip_NumberOfRecords_PDU;           /* NumberOfRecords */
static int hf_cmip_OperationalState_PDU;          /* OperationalState */
static int hf_cmip_Packages_PDU;                  /* Packages */
static int hf_cmip_PerceivedSeverity_PDU;         /* PerceivedSeverity */
static int hf_cmip_PrioritisedObject_PDU;         /* PrioritisedObject */
static int hf_cmip_ProbableCause_PDU;             /* ProbableCause */
static int hf_cmip_ProceduralStatus_PDU;          /* ProceduralStatus */
static int hf_cmip_ProposedRepairActions_PDU;     /* ProposedRepairActions */
static int hf_cmip_SecurityAlarmCause_PDU;        /* SecurityAlarmCause */
static int hf_cmip_SecurityAlarmSeverity_PDU;     /* SecurityAlarmSeverity */
static int hf_cmip_SecurityAlarmDetector_PDU;     /* SecurityAlarmDetector */
static int hf_cmip_ServiceProvider_PDU;           /* ServiceProvider */
static int hf_cmip_ServiceUser_PDU;               /* ServiceUser */
static int hf_cmip_SimpleNameType_PDU;            /* SimpleNameType */
static int hf_cmip_SourceIndicator_PDU;           /* SourceIndicator */
static int hf_cmip_SpecificProblems_PDU;          /* SpecificProblems */
static int hf_cmip_StandbyStatus_PDU;             /* StandbyStatus */
static int hf_cmip_StartTime_PDU;                 /* StartTime */
static int hf_cmip_StopTime_PDU;                  /* StopTime */
static int hf_cmip_SupportedFeatures_PDU;         /* SupportedFeatures */
static int hf_cmip_SystemId_PDU;                  /* SystemId */
static int hf_cmip_SystemTitle_PDU;               /* SystemTitle */
static int hf_cmip_ThresholdInfo_PDU;             /* ThresholdInfo */
static int hf_cmip_TrendIndication_PDU;           /* TrendIndication */
static int hf_cmip_UnknownStatus_PDU;             /* UnknownStatus */
static int hf_cmip_UsageState_PDU;                /* UsageState */
static int hf_cmip_WeekMask_PDU;                  /* WeekMask */
static int hf_cmip_PAR_missingAttributeValue_item;  /* AttributeId */
static int hf_cmip_managedObjectClass;            /* ObjectClass */
static int hf_cmip_managedObjectInstance;         /* ObjectInstance */
static int hf_cmip_currentTime;                   /* GeneralizedTime */
static int hf_cmip_actionErroractionErrorInfo;    /* ActionErrorInfo */
static int hf_cmip_actionErrorInfo_errorStatus;   /* T_actionErrorInfo_errorStatus */
static int hf_cmip_actionErrorInfo;               /* T_actionErrorInfo */
static int hf_cmip_actionType;                    /* ActionTypeId */
static int hf_cmip_actionArgument;                /* NoSuchArgument */
static int hf_cmip_argumentValue;                 /* InvalidArgumentValue */
static int hf_cmip_actionInfoArg;                 /* T_actionInfoArg */
static int hf_cmip_actionReplyInfo;               /* T_actionReplyInfo */
static int hf_cmip_actionReply;                   /* ActionReply */
static int hf_cmip_actionTypeId_globalForm;       /* T_actionTypeId_globalForm */
static int hf_cmip_localForm;                     /* INTEGER */
static int hf_cmip_attributeid;                   /* AttributeId */
static int hf_cmip_value;                         /* AttributeValue */
static int hf_cmip_attributeError_errorStatus;    /* T_attributeError_errorStatus */
static int hf_cmip_modifyOperator;                /* ModifyOperator */
static int hf_cmip_attributeId;                   /* AttributeId */
static int hf_cmip_attributeValue;                /* T_attributeValue */
static int hf_cmip_attributeId_globalForm;        /* T_attributeId_globalForm */
static int hf_cmip_attributeIdlocalForm;          /* T_attributeIdlocalForm */
static int hf_cmip_attributeIdError_errorStatus;  /* T_attributeIdError_errorStatus */
static int hf_cmip_id;                            /* T_id */
static int hf_cmip_attributeValueAssertionvalue;  /* T_attributeValueAssertionvalue */
static int hf_cmip_baseManagedObjectClass;        /* ObjectClass */
static int hf_cmip_baseManagedObjectInstance;     /* ObjectInstance */
static int hf_cmip_item;                          /* FilterItem */
static int hf_cmip_and;                           /* SET_OF_CMISFilter */
static int hf_cmip_and_item;                      /* CMISFilter */
static int hf_cmip_or;                            /* SET_OF_CMISFilter */
static int hf_cmip_or_item;                       /* CMISFilter */
static int hf_cmip_not;                           /* CMISFilter */
static int hf_cmip_scope;                         /* Scope */
static int hf_cmip_filter;                        /* CMISFilter */
static int hf_cmip_sync;                          /* CMISSync */
static int hf_cmip_managedOrSuperiorObjectInstance;  /* T_managedOrSuperiorObjectInstance */
static int hf_cmip_superiorObjectInstance;        /* ObjectInstance */
static int hf_cmip_accessControl;                 /* AccessControl */
static int hf_cmip_referenceObjectInstance;       /* ObjectInstance */
static int hf_cmip_attributeList;                 /* SET_OF_Attribute */
static int hf_cmip_attributeList_item;            /* Attribute */
static int hf_cmip_deleteErrorInfo;               /* T_deleteErrorInfo */
static int hf_cmip_eventType;                     /* EventTypeId */
static int hf_cmip_eventReplyInfo;                /* T_eventReplyInfo */
static int hf_cmip_eventTime;                     /* GeneralizedTime */
static int hf_cmip_eventReportArgumenteventInfo;  /* EventReportArgumentEventInfo */
static int hf_cmip_eventReply;                    /* EventReply */
static int hf_cmip_eventTypeId_globalForm;        /* T_eventTypeId_globalForm */
static int hf_cmip_equality;                      /* Attribute */
static int hf_cmip_substrings;                    /* T_substrings */
static int hf_cmip_substrings_item;               /* T_substrings_item */
static int hf_cmip_initialString;                 /* Attribute */
static int hf_cmip_anyString;                     /* Attribute */
static int hf_cmip_finalString;                   /* Attribute */
static int hf_cmip_greaterOrEqual;                /* Attribute */
static int hf_cmip_lessOrEqual;                   /* Attribute */
static int hf_cmip_filterItempresent;             /* AttributeId */
static int hf_cmip_subsetOf;                      /* Attribute */
static int hf_cmip_supersetOf;                    /* Attribute */
static int hf_cmip_nonNullSetIntersection;        /* Attribute */
static int hf_cmip_attributeIdError;              /* AttributeIdError */
static int hf_cmip_attribute;                     /* Attribute */
static int hf_cmip_getInfoList;                   /* SET_OF_GetInfoStatus */
static int hf_cmip_getInfoList_item;              /* GetInfoStatus */
static int hf_cmip_actionValue;                   /* ActionInfo */
static int hf_cmip_eventValue;                    /* T_eventValue */
static int hf_cmip_eventInfo;                     /* T_eventInfo */
static int hf_cmip_getResult;                     /* GetResult */
static int hf_cmip_getListError;                  /* GetListError */
static int hf_cmip_setResult;                     /* SetResult */
static int hf_cmip_setListError;                  /* SetListError */
static int hf_cmip_actionResult;                  /* ActionResult */
static int hf_cmip_processingFailure;             /* ProcessingFailure */
static int hf_cmip_deleteResult;                  /* DeleteResult */
static int hf_cmip_actionError;                   /* ActionError */
static int hf_cmip_deleteError;                   /* DeleteError */
static int hf_cmip_actionId;                      /* T_actionId */
static int hf_cmip_eventId;                       /* T_eventId */
static int hf_cmip_objectClass_globalForm;        /* T_objectClass_globalForm */
static int hf_cmip_objectClasslocalForm;          /* INTEGER */
static int hf_cmip_distinguishedName;             /* DistinguishedName */
static int hf_cmip_nonSpecificForm;               /* OCTET_STRING */
static int hf_cmip_localDistinguishedName;        /* RDNSequence */
static int hf_cmip_specificErrorInfo;             /* SpecificErrorInfo */
static int hf_cmip_RDNSequence_item;              /* RelativeDistinguishedName */
static int hf_cmip_RelativeDistinguishedName_item;  /* AttributeValueAssertion */
static int hf_cmip_namedNumbers;                  /* T_namedNumbers */
static int hf_cmip_individualLevels;              /* INTEGER */
static int hf_cmip_baseToNthLevel;                /* INTEGER */
static int hf_cmip_attributeError;                /* AttributeError */
static int hf_cmip_setInfoList;                   /* SET_OF_SetInfoStatus */
static int hf_cmip_setInfoList_item;              /* SetInfoStatus */
static int hf_cmip_errorId;                       /* T_errorId */
static int hf_cmip_errorInfo;                     /* T_errorInfo */
static int hf_cmip_abortSource;                   /* CMIPAbortSource */
static int hf_cmip_userInfo;                      /* EXTERNAL */
static int hf_cmip_protocolVersion;               /* ProtocolVersion */
static int hf_cmip_functionalUnits;               /* FunctionalUnits */
static int hf_cmip_cmipUserInfoaccessControl;     /* EXTERNAL */
static int hf_cmip_AdditionalInformation_item;    /* ManagementExtension */
static int hf_cmip_Allomorphs_item;               /* ObjectClass */
static int hf_cmip_AttributeIdentifierList_item;  /* AttributeId */
static int hf_cmip_AttributeList_item;            /* Attribute */
static int hf_cmip_AttributeValueChangeDefinition_item;  /* AttributeValueChangeDefinition_item */
static int hf_cmip_oldAttributeValue;             /* T_oldAttributeValue */
static int hf_cmip_newAttributeValue;             /* T_newAttributeValue */
static int hf_cmip_AlarmStatus_item;              /* AlarmStatus_item */
static int hf_cmip_AvailabilityStatus_item;       /* AvailabilityStatus_item */
static int hf_cmip_BackUpDestinationList_item;    /* AE_title */
static int hf_cmip_objectName;                    /* ObjectInstance */
static int hf_cmip_noObject;                      /* NULL */
static int hf_cmip_CapacityAlarmThreshold_item;   /* INTEGER_0_100 */
static int hf_cmip_ControlStatus_item;            /* ControlStatus_item */
static int hf_cmip_CorrelatedNotifications_item;  /* CorrelatedNotifications_item */
static int hf_cmip_correlatedNotifications;       /* SET_OF_NotificationIdentifier */
static int hf_cmip_correlatedNotifications_item;  /* NotificationIdentifier */
static int hf_cmip_sourceObjectInst;              /* ObjectInstance */
static int hf_cmip_single;                        /* AE_title */
static int hf_cmip_multiple;                      /* SET_OF_AE_title */
static int hf_cmip_multiple_item;                 /* AE_title */
static int hf_cmip_GroupObjects_item;             /* ObjectInstance */
static int hf_cmip_IntervalsOfDay_item;           /* IntervalsOfDay_item */
static int hf_cmip_intervalStart;                 /* Time24 */
static int hf_cmip_intervalEnd;                   /* Time24 */
static int hf_cmip_managementExtensionidentifier;  /* T_managementExtensionidentifier */
static int hf_cmip_significance;                  /* BOOLEAN */
static int hf_cmip_information;                   /* T_information */
static int hf_cmip_MonitoredAttributes_item;      /* Attribute */
static int hf_cmip_integer;                       /* INTEGER */
static int hf_cmip_real;                          /* REAL */
static int hf_cmip_Packages_item;                 /* OBJECT_IDENTIFIER */
static int hf_cmip_PrioritisedObject_item;        /* PrioritisedObject_item */
static int hf_cmip_object;                        /* ObjectInstance */
static int hf_cmip_priority;                      /* T_priority */
static int hf_cmip_globalValue;                   /* OBJECT_IDENTIFIER */
static int hf_cmip_localValue;                    /* INTEGER */
static int hf_cmip_ProceduralStatus_item;         /* ProceduralStatus_item */
static int hf_cmip_ProposedRepairActions_item;    /* SpecificIdentifier */
static int hf_cmip_mechanism;                     /* OBJECT_IDENTIFIER */
static int hf_cmip_application;                   /* AE_title */
static int hf_cmip_serviceUseridentifier;         /* T_serviceUseridentifier */
static int hf_cmip_details;                       /* T_details */
static int hf_cmip_number;                        /* INTEGER */
static int hf_cmip_string;                        /* GraphicString */
static int hf_cmip_oi;                            /* OBJECT_IDENTIFIER */
static int hf_cmip_int;                           /* INTEGER */
static int hf_cmip_SpecificProblems_item;         /* SpecificIdentifier */
static int hf_cmip_specific;                      /* GeneralizedTime */
static int hf_cmip_continual;                     /* NULL */
static int hf_cmip_SupportedFeatures_item;        /* SupportedFeatures_item */
static int hf_cmip_featureIdentifier;             /* T_featureIdentifier */
static int hf_cmip_featureInfo;                   /* T_featureInfo */
static int hf_cmip_name;                          /* GraphicString */
static int hf_cmip_nothing;                       /* NULL */
static int hf_cmip_oid;                           /* OBJECT_IDENTIFIER */
static int hf_cmip_hour;                          /* INTEGER_0_23 */
static int hf_cmip_minute;                        /* INTEGER_0_59 */
static int hf_cmip_triggeredThreshold;            /* AttributeId */
static int hf_cmip_observedValue;                 /* ObservedValue */
static int hf_cmip_thresholdLevel;                /* ThresholdLevelInd */
static int hf_cmip_armTime;                       /* GeneralizedTime */
static int hf_cmip_up;                            /* T_up */
static int hf_cmip_high;                          /* ObservedValue */
static int hf_cmip_low;                           /* ObservedValue */
static int hf_cmip_down;                          /* T_down */
static int hf_cmip_WeekMask_item;                 /* WeekMask_item */
static int hf_cmip_daysOfWeek;                    /* T_daysOfWeek */
static int hf_cmip_intervalsOfDay;                /* IntervalsOfDay */
static int hf_cmip_local;                         /* T_local */
static int hf_cmip_global;                        /* OBJECT_IDENTIFIER */
static int hf_cmip_invoke;                        /* Invoke */
static int hf_cmip_returnResult;                  /* ReturnResult */
static int hf_cmip_returnError;                   /* ReturnError */
static int hf_cmip_reject;                        /* Reject */
static int hf_cmip_invokeId;                      /* InvokeId */
static int hf_cmip_linkedId;                      /* T_linkedId */
static int hf_cmip_linkedIdPresent;               /* T_linkedIdPresent */
static int hf_cmip_absent;                        /* NULL */
static int hf_cmip_opcode;                        /* Code */
static int hf_cmip_argument;                      /* InvokeArgument */
static int hf_cmip_result;                        /* T_result */
static int hf_cmip_resultArgument;                /* ResultArgument */
static int hf_cmip_errcode;                       /* Code */
static int hf_cmip_parameter;                     /* T_parameter */
static int hf_cmip_problem;                       /* T_problem */
static int hf_cmip_general;                       /* GeneralProblem */
static int hf_cmip_invokeProblem;                 /* InvokeProblem */
static int hf_cmip_returnResultProblem;           /* ReturnResultProblem */
static int hf_cmip_returnErrorProblem;            /* ReturnErrorProblem */
static int hf_cmip_present;                       /* INTEGER */
static int hf_cmip_synchronization;               /* CMISSync */
static int hf_cmip_actionInfo;                    /* ActionInfo */
static int hf_cmip_attributeIdList;               /* SET_OF_AttributeId */
static int hf_cmip_attributeIdList_item;          /* AttributeId */
static int hf_cmip_modificationList;              /* T_modificationList */
static int hf_cmip_modificationList_item;         /* T_modificationList_item */
static int hf_cmip_attributevalue;                /* T_attributevalue */
static int hf_cmip_InvokeId_present;              /* InvokeId_present */
/* named bits */
static int hf_cmip_FunctionalUnits_multipleObjectSelection;
static int hf_cmip_FunctionalUnits_filter;
static int hf_cmip_FunctionalUnits_multipleReply;
static int hf_cmip_FunctionalUnits_extendedService;
static int hf_cmip_FunctionalUnits_cancelGet;
static int hf_cmip_ProtocolVersion_version1;
static int hf_cmip_ProtocolVersion_version2;
static int hf_cmip_T_daysOfWeek_sunday;
static int hf_cmip_T_daysOfWeek_monday;
static int hf_cmip_T_daysOfWeek_tuesday;
static int hf_cmip_T_daysOfWeek_wednesday;
static int hf_cmip_T_daysOfWeek_thursday;
static int hf_cmip_T_daysOfWeek_friday;
static int hf_cmip_T_daysOfWeek_saturday;

/* Initialize the subtree pointers */
static int ett_cmip;
static int ett_cmip_PAR_missingAttributeValue;
static int ett_cmip_ActionArgument;
static int ett_cmip_ActionError;
static int ett_cmip_ActionErrorInfo;
static int ett_cmip_T_actionErrorInfo;
static int ett_cmip_ActionInfo;
static int ett_cmip_ActionReply;
static int ett_cmip_ActionResult;
static int ett_cmip_ActionTypeId;
static int ett_cmip_Attribute;
static int ett_cmip_AttributeError;
static int ett_cmip_AttributeId;
static int ett_cmip_AttributeIdError;
static int ett_cmip_AttributeValueAssertion;
static int ett_cmip_BaseManagedObjectId;
static int ett_cmip_CMISFilter;
static int ett_cmip_SET_OF_CMISFilter;
static int ett_cmip_ComplexityLimitation;
static int ett_cmip_CreateArgument;
static int ett_cmip_T_managedOrSuperiorObjectInstance;
static int ett_cmip_SET_OF_Attribute;
static int ett_cmip_CreateResult;
static int ett_cmip_DeleteArgument;
static int ett_cmip_DeleteError;
static int ett_cmip_DeleteResult;
static int ett_cmip_EventReply;
static int ett_cmip_EventReportArgument;
static int ett_cmip_EventReportResult;
static int ett_cmip_EventTypeId;
static int ett_cmip_FilterItem;
static int ett_cmip_T_substrings;
static int ett_cmip_T_substrings_item;
static int ett_cmip_GetArgument;
static int ett_cmip_GetInfoStatus;
static int ett_cmip_GetListError;
static int ett_cmip_SET_OF_GetInfoStatus;
static int ett_cmip_GetResult;
static int ett_cmip_InvalidArgumentValue;
static int ett_cmip_T_eventValue;
static int ett_cmip_LinkedReplyArgument;
static int ett_cmip_NoSuchAction;
static int ett_cmip_NoSuchArgument;
static int ett_cmip_T_actionId;
static int ett_cmip_T_eventId;
static int ett_cmip_NoSuchEventType;
static int ett_cmip_ObjectClass;
static int ett_cmip_ObjectInstance;
static int ett_cmip_ProcessingFailure;
static int ett_cmip_RDNSequence;
static int ett_cmip_RelativeDistinguishedName;
static int ett_cmip_Scope;
static int ett_cmip_SetArgument;
static int ett_cmip_SetInfoStatus;
static int ett_cmip_SetListError;
static int ett_cmip_SET_OF_SetInfoStatus;
static int ett_cmip_SetResult;
static int ett_cmip_SpecificErrorInfo;
static int ett_cmip_CMIPAbortInfo;
static int ett_cmip_FunctionalUnits;
static int ett_cmip_CMIPUserInfo;
static int ett_cmip_ProtocolVersion;
static int ett_cmip_AdditionalInformation;
static int ett_cmip_Allomorphs;
static int ett_cmip_AttributeIdentifierList;
static int ett_cmip_AttributeList;
static int ett_cmip_AttributeValueChangeDefinition;
static int ett_cmip_AttributeValueChangeDefinition_item;
static int ett_cmip_AlarmStatus;
static int ett_cmip_AvailabilityStatus;
static int ett_cmip_BackUpDestinationList;
static int ett_cmip_BackUpRelationshipObject;
static int ett_cmip_CapacityAlarmThreshold;
static int ett_cmip_ControlStatus;
static int ett_cmip_CorrelatedNotifications;
static int ett_cmip_CorrelatedNotifications_item;
static int ett_cmip_SET_OF_NotificationIdentifier;
static int ett_cmip_Destination;
static int ett_cmip_SET_OF_AE_title;
static int ett_cmip_GroupObjects;
static int ett_cmip_IntervalsOfDay;
static int ett_cmip_IntervalsOfDay_item;
static int ett_cmip_ManagementExtension;
static int ett_cmip_MonitoredAttributes;
static int ett_cmip_ObservedValue;
static int ett_cmip_Packages;
static int ett_cmip_PrioritisedObject;
static int ett_cmip_PrioritisedObject_item;
static int ett_cmip_ProbableCause;
static int ett_cmip_ProceduralStatus;
static int ett_cmip_ProposedRepairActions;
static int ett_cmip_SecurityAlarmDetector;
static int ett_cmip_ServiceUser;
static int ett_cmip_SimpleNameType;
static int ett_cmip_SpecificIdentifier;
static int ett_cmip_SpecificProblems;
static int ett_cmip_StopTime;
static int ett_cmip_SupportedFeatures;
static int ett_cmip_SupportedFeatures_item;
static int ett_cmip_SystemId;
static int ett_cmip_SystemTitle;
static int ett_cmip_Time24;
static int ett_cmip_ThresholdInfo;
static int ett_cmip_ThresholdLevelInd;
static int ett_cmip_T_up;
static int ett_cmip_T_down;
static int ett_cmip_WeekMask;
static int ett_cmip_WeekMask_item;
static int ett_cmip_T_daysOfWeek;
static int ett_cmip_Code;
static int ett_cmip_ROS;
static int ett_cmip_Invoke;
static int ett_cmip_T_linkedId;
static int ett_cmip_ReturnResult;
static int ett_cmip_T_result;
static int ett_cmip_ReturnError;
static int ett_cmip_Reject;
static int ett_cmip_T_problem;
static int ett_cmip_InvokeId;
static int ett_cmip_SET_OF_AttributeId;
static int ett_cmip_T_modificationList;
static int ett_cmip_T_modificationList_item;

static expert_field ei_wrong_spdu_type;

static uint32_t opcode;

static dissector_handle_t cmip_handle;

/* Dissector table */
static dissector_table_t attribute_id_dissector_table;


/* CMIP OPERATIONS */
static const value_string cmip_Opcode_vals[] = {
	{ 6, "m_Action" },
	{ 7, "m_Action_Confirmed" },
	{ 10, "m_CancelGet" },
	{ 8, "m_Create" },
	{ 9, "m_Delete" },
	{ 0, "m_EventReport" },
	{ 1, "m_EventReport_Confirmed" },
	{ 3, "m_Get" },
	{ 2, "m_Linked_Reply" },
	{ 4, "m_Set" },
	{ 5, "m_Set_Confirmed" },
  { 0, NULL }
};


/* CMIP ERRORS */
static const value_string cmip_error_code_vals[] = {
	{ 2, "accessDenied" },
	{ 19, "classInstanceConflict" },
	{ 20, "complexityLimitation" },
	{ 11, "duplicateManagedObjectInstance" },
	{ 7, "getListError" },
	{ 15, "invalidArgumentValue" },
	{ 6, "invalidAttributeValue" },
	{ 4, "invalidFilter" },
	{ 17, "invalidObjectInstance" },
	{ 16, "invalidScope" },
	{ 18, "missingAttributeValue" },
	{ 21, "mistypedOperation" },
	{ 9, "noSuchAction" },
	{ 14, "noSuchArgument" },
	{ 5, "noSuchAttribute" },
	{ 13, "noSuchEventType" },
	{ 22, "noSuchInvokeId" },
	{ 0, "noSuchObjectClass" },
	{ 1, "noSuchObjectInstance" },
	{ 12, "noSuchReferenceObject" },
	{ 23, "operationCancelled" },
	{ 10, "processingFailure" },
	{ 8, "setListError" },
	{ 3, "syncNotSupported" },
  { 0, NULL }
};


static int opcode_type;
#define OPCODE_INVOKE        1
#define OPCODE_RETURN_RESULT 2
#define OPCODE_RETURN_ERROR  3
#define OPCODE_REJECT        4

static const char *object_identifier_id;

#define smi2AttributeID                "2.9.3.2.7"
#define smi2AttributeGroup             "2.9.3.2.8"
#define arfProbableCause               "2.9.3.2.0.0"
#define adapterError                   arfProbableCause".1"
#define applicationSubsystemFailure    arfProbableCause".2"
#define bandwidthReduced               arfProbableCause".3"
#define callEstablishmentError         arfProbableCause".4"
#define communicationsProtocolError    arfProbableCause".5"
#define communicationsSubsystemFailure arfProbableCause".6"
#define configurationOrCustomizationError arfProbableCause".7"
#define congestion                     arfProbableCause".8"
#define corruptData                    arfProbableCause".9"
#define cpuCyclesLimitExceeded         arfProbableCause".10"
#define dataSetOrModemError            arfProbableCause".11"
#define degradedSignal                 arfProbableCause".12"
#define dTE_DCEInterfaceError          arfProbableCause".13"
#define enclosureDoorOpen              arfProbableCause".14"
#define equipmentMalfunction           arfProbableCause".15"
#define excessiveVibration             arfProbableCause".16"
#define fileError                      arfProbableCause".17"
#define fireDetected                   arfProbableCause".18"
#define floodDetected                  arfProbableCause".19"
#define framingError                   arfProbableCause".20"
#define heatingOrVentilationOrCoolingSystemProblem arfProbableCause".21"
#define humidityUnacceptable           arfProbableCause".22"
#define inputOutputDeviceError         arfProbableCause".23"
#define inputDeviceError               arfProbableCause".24"
#define lANError                       arfProbableCause".25"
#define leakDetected                   arfProbableCause".26"
#define localNodeTransmissionError     arfProbableCause".27"
#define lossOfFrame                    arfProbableCause".28"
#define lossOfSignal                   arfProbableCause".29"
#define materialSupplyExhausted        arfProbableCause".30"
#define multiplexerProblem             arfProbableCause".31"
#define outOfMemory                    arfProbableCause".32"
#define ouputDeviceError               arfProbableCause".33"
#define performanceDegraded            arfProbableCause".34"
#define powerProblem                   arfProbableCause".35"
#define pressureUnacceptable           arfProbableCause".36"
#define processorProblem               arfProbableCause".37"
#define pumpFailure                    arfProbableCause".38"
#define queueSizeExceeded              arfProbableCause".39"
#define receiveFailure                 arfProbableCause".40"
#define receiverFailure                arfProbableCause".41"
#define remoteNodeTransmissionError    arfProbableCause".42"
#define resourceAtOrNearingCapacity    arfProbableCause".43"
#define responseTimeExcessive          arfProbableCause".44"
#define retransmissionRateExcessive    arfProbableCause".45"
#define softwareError                  arfProbableCause".46"
#define softwareProgramAbnormallyTerminated arfProbableCause".47"
#define softwareProgramError           arfProbableCause".48"
#define storageCapacityProblem         arfProbableCause".49"
#define temperatureUnacceptable        arfProbableCause".50"
#define thresholdCrossed               arfProbableCause".51"
#define timingProblem                  arfProbableCause".52"
#define toxicLeakDetected              arfProbableCause".53"
#define transmitFailure                arfProbableCause".54"
#define transmitterFailure             arfProbableCause".55"
#define underlyingResourceUnavailable  arfProbableCause".56"
#define versionMismatch                arfProbableCause".57"
#define arfProposedRepairAction        "2.9.3.2.0.2"
#define noActionRequired               arfProposedRepairAction".1"
#define repairActionRequired           arfProposedRepairAction".2"
#define securityAlarmCause             "2.9.3.2.0.1"
#define authenticationFailure          securityAlarmCause".1"
#define breachOfConfidentiality        securityAlarmCause".2"
#define cableTamper                    securityAlarmCause".3"
#define delayedInformation             securityAlarmCause".4"
#define denialOfService                securityAlarmCause".5"
#define duplicateInformation           securityAlarmCause".6"
#define informationMissing             securityAlarmCause".7"
#define informationModificationDetected securityAlarmCause".8"
#define informationOutOfSequence       securityAlarmCause".9"
#define intrusionDetection             securityAlarmCause".10"
#define keyExpired                     securityAlarmCause".11"
#define nonRepudiationFailure          securityAlarmCause".12"
#define outOfHoursActivity             securityAlarmCause".13"
#define outOfService                   securityAlarmCause".14"
#define proceduralError                securityAlarmCause".15"
#define unauthorizedAccessAttempt      securityAlarmCause".16"
#define unexpectedInformation          securityAlarmCause".17"
#define unspecifiedReason              securityAlarmCause".18"
#define defaultDiscriminatorConstruct  []
#define noInvokeId                     NULL
/*--- Cyclic dependencies ---*/

/* CMISFilter -> CMISFilter/and -> CMISFilter */
/* CMISFilter -> CMISFilter */
static int dissect_cmip_CMISFilter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);




static int
dissect_cmip_T_attributeId_globalForm(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &actx->external.direct_reference);

  actx->external.direct_ref_present = (actx->external.direct_reference != NULL) ? true : false;


  return offset;
}



static int
dissect_cmip_T_attributeIdlocalForm(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &actx->external.indirect_reference);

  actx->external.indirect_ref_present = true;


  return offset;
}


static const value_string cmip_AttributeId_vals[] = {
  {   0, "globalForm" },
  {   1, "localForm" },
  { 0, NULL }
};

static const ber_choice_t AttributeId_choice[] = {
  {   0, &hf_cmip_attributeId_globalForm, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_cmip_T_attributeId_globalForm },
  {   1, &hf_cmip_attributeIdlocalForm, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_cmip_T_attributeIdlocalForm },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_AttributeId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AttributeId_choice, hf_index, ett_cmip_AttributeId,
                                 NULL);

  return offset;
}


static const ber_sequence_t PAR_missingAttributeValue_set_of[1] = {
  { &hf_cmip_PAR_missingAttributeValue_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_AttributeId },
};

static int
dissect_cmip_PAR_missingAttributeValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 PAR_missingAttributeValue_set_of, hf_index, ett_cmip_PAR_missingAttributeValue);

  return offset;
}



static int
dissect_cmip_AccessControl(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_external_type(implicit_tag, tree, tvb, offset, actx, hf_index, NULL);

  return offset;
}



static int
dissect_cmip_T_objectClass_globalForm(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_cmip_INTEGER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


const value_string cmip_ObjectClass_vals[] = {
  {   0, "globalForm" },
  {   1, "localForm" },
  { 0, NULL }
};

static const ber_choice_t ObjectClass_choice[] = {
  {   0, &hf_cmip_objectClass_globalForm, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_cmip_T_objectClass_globalForm },
  {   1, &hf_cmip_objectClasslocalForm, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_cmip_INTEGER },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_cmip_ObjectClass(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ObjectClass_choice, hf_index, ett_cmip_ObjectClass,
                                 NULL);

  return offset;
}



static int
dissect_cmip_T_id(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &actx->external.direct_reference);

  actx->external.direct_ref_present = (actx->external.direct_reference != NULL) ? true : false;

  return offset;
}



static int
dissect_cmip_T_attributeValueAssertionvalue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  if (actx->external.direct_ref_present) {
    offset=call_ber_oid_callback(actx->external.direct_reference, tvb, offset, actx->pinfo, tree, actx->private_data);
  }


  return offset;
}


static const ber_sequence_t AttributeValueAssertion_sequence[] = {
  { &hf_cmip_id             , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cmip_T_id },
  { &hf_cmip_attributeValueAssertionvalue, BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_cmip_T_attributeValueAssertionvalue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_AttributeValueAssertion(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttributeValueAssertion_sequence, hf_index, ett_cmip_AttributeValueAssertion);

  return offset;
}


static const ber_sequence_t RelativeDistinguishedName_set_of[1] = {
  { &hf_cmip_RelativeDistinguishedName_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmip_AttributeValueAssertion },
};

static int
dissect_cmip_RelativeDistinguishedName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 RelativeDistinguishedName_set_of, hf_index, ett_cmip_RelativeDistinguishedName);

  return offset;
}


static const ber_sequence_t RDNSequence_sequence_of[1] = {
  { &hf_cmip_RDNSequence_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_cmip_RelativeDistinguishedName },
};

int
dissect_cmip_RDNSequence(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      RDNSequence_sequence_of, hf_index, ett_cmip_RDNSequence);

  return offset;
}



static int
dissect_cmip_DistinguishedName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cmip_RDNSequence(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_cmip_OCTET_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


const value_string cmip_ObjectInstance_vals[] = {
  {   2, "distinguishedName" },
  {   3, "nonSpecificForm" },
  {   4, "localDistinguishedName" },
  { 0, NULL }
};

static const ber_choice_t ObjectInstance_choice[] = {
  {   2, &hf_cmip_distinguishedName, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_cmip_DistinguishedName },
  {   3, &hf_cmip_nonSpecificForm, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_cmip_OCTET_STRING },
  {   4, &hf_cmip_localDistinguishedName, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_cmip_RDNSequence },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_cmip_ObjectInstance(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ObjectInstance_choice, hf_index, ett_cmip_ObjectInstance,
                                 NULL);

  return offset;
}


static const value_string cmip_CMISSync_vals[] = {
  {   0, "bestEffort" },
  {   1, "atomic" },
  { 0, NULL }
};


static int
dissect_cmip_CMISSync(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string cmip_T_namedNumbers_vals[] = {
  {   0, "baseObject" },
  {   1, "firstLevelOnly" },
  {   2, "wholeSubtree" },
  { 0, NULL }
};


static int
dissect_cmip_T_namedNumbers(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string cmip_Scope_vals[] = {
  {   0, "namedNumbers" },
  {   1, "individualLevels" },
  {   2, "baseToNthLevel" },
  { 0, NULL }
};

static const ber_choice_t Scope_choice[] = {
  {   0, &hf_cmip_namedNumbers   , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmip_T_namedNumbers },
  {   1, &hf_cmip_individualLevels, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_cmip_INTEGER },
  {   2, &hf_cmip_baseToNthLevel , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_cmip_INTEGER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_Scope(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Scope_choice, hf_index, ett_cmip_Scope,
                                 NULL);

  return offset;
}



static int
dissect_cmip_AttributeValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  if(actx->external.direct_ref_present){
    offset=call_ber_oid_callback(actx->external.direct_reference, tvb, offset, actx->pinfo, tree, actx->private_data);
  } else if (actx->external.indirect_ref_present &&
             dissector_try_uint(attribute_id_dissector_table, actx->external.indirect_reference, tvb, actx->pinfo, tree)) {
    offset=tvb_reported_length (tvb);
  } else {
    offset=dissect_unknown_ber(actx->pinfo, tvb, offset, tree);
  }


  return offset;
}


static const ber_sequence_t Attribute_sequence[] = {
  { &hf_cmip_attributeid    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_AttributeId },
  { &hf_cmip_value          , BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_cmip_AttributeValue },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cmip_Attribute(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Attribute_sequence, hf_index, ett_cmip_Attribute);

  return offset;
}


static const value_string cmip_T_substrings_item_vals[] = {
  {   0, "initialString" },
  {   1, "anyString" },
  {   2, "finalString" },
  { 0, NULL }
};

static const ber_choice_t T_substrings_item_choice[] = {
  {   0, &hf_cmip_initialString  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_cmip_Attribute },
  {   1, &hf_cmip_anyString      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_cmip_Attribute },
  {   2, &hf_cmip_finalString    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_cmip_Attribute },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_T_substrings_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_substrings_item_choice, hf_index, ett_cmip_T_substrings_item,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_substrings_sequence_of[1] = {
  { &hf_cmip_substrings_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_T_substrings_item },
};

static int
dissect_cmip_T_substrings(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_substrings_sequence_of, hf_index, ett_cmip_T_substrings);

  return offset;
}


static const value_string cmip_FilterItem_vals[] = {
  {   0, "equality" },
  {   1, "substrings" },
  {   2, "greaterOrEqual" },
  {   3, "lessOrEqual" },
  {   4, "present" },
  {   5, "subsetOf" },
  {   6, "supersetOf" },
  {   7, "nonNullSetIntersection" },
  { 0, NULL }
};

static const ber_choice_t FilterItem_choice[] = {
  {   0, &hf_cmip_equality       , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_cmip_Attribute },
  {   1, &hf_cmip_substrings     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_cmip_T_substrings },
  {   2, &hf_cmip_greaterOrEqual , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_cmip_Attribute },
  {   3, &hf_cmip_lessOrEqual    , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_cmip_Attribute },
  {   4, &hf_cmip_filterItempresent, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_cmip_AttributeId },
  {   5, &hf_cmip_subsetOf       , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_cmip_Attribute },
  {   6, &hf_cmip_supersetOf     , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_cmip_Attribute },
  {   7, &hf_cmip_nonNullSetIntersection, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_cmip_Attribute },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_FilterItem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 FilterItem_choice, hf_index, ett_cmip_FilterItem,
                                 NULL);

  return offset;
}


static const ber_sequence_t SET_OF_CMISFilter_set_of[1] = {
  { &hf_cmip_and_item       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_CMISFilter },
};

static int
dissect_cmip_SET_OF_CMISFilter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_CMISFilter_set_of, hf_index, ett_cmip_SET_OF_CMISFilter);

  return offset;
}


static const value_string cmip_CMISFilter_vals[] = {
  {   8, "item" },
  {   9, "and" },
  {  10, "or" },
  {  11, "not" },
  { 0, NULL }
};

static const ber_choice_t CMISFilter_choice[] = {
  {   8, &hf_cmip_item           , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_cmip_FilterItem },
  {   9, &hf_cmip_and            , BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_cmip_SET_OF_CMISFilter },
  {  10, &hf_cmip_or             , BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_cmip_SET_OF_CMISFilter },
  {  11, &hf_cmip_not            , BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_cmip_CMISFilter },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_CMISFilter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  // CMISFilter -> CMISFilter/and -> CMISFilter
  actx->pinfo->dissection_depth += 2;
  increment_dissection_depth(actx->pinfo);
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CMISFilter_choice, hf_index, ett_cmip_CMISFilter,
                                 NULL);

  actx->pinfo->dissection_depth -= 2;
  decrement_dissection_depth(actx->pinfo);
  return offset;
}



static int
dissect_cmip_T_actionTypeId_globalForm(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_cmip_actionType_OID, &object_identifier_id);

  return offset;
}


static const value_string cmip_ActionTypeId_vals[] = {
  {   2, "globalForm" },
  {   3, "localForm" },
  { 0, NULL }
};

static const ber_choice_t ActionTypeId_choice[] = {
  {   2, &hf_cmip_actionTypeId_globalForm, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_cmip_T_actionTypeId_globalForm },
  {   3, &hf_cmip_localForm      , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_cmip_INTEGER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_ActionTypeId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ActionTypeId_choice, hf_index, ett_cmip_ActionTypeId,
                                 NULL);

  return offset;
}



static int
dissect_cmip_T_actionInfoArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree, actx->private_data);


  return offset;
}


static const ber_sequence_t ActionInfo_sequence[] = {
  { &hf_cmip_actionType     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ActionTypeId },
  { &hf_cmip_actionInfoArg  , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_T_actionInfoArg },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_ActionInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ActionInfo_sequence, hf_index, ett_cmip_ActionInfo);

  return offset;
}


static const ber_sequence_t ActionArgument_sequence[] = {
  { &hf_cmip_baseManagedObjectClass, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectClass },
  { &hf_cmip_baseManagedObjectInstance, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectInstance },
  { &hf_cmip_accessControl  , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_AccessControl },
  { &hf_cmip_synchronization, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_CMISSync },
  { &hf_cmip_scope          , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_Scope },
  { &hf_cmip_filter         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_CMISFilter },
  { &hf_cmip_actionInfo     , BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_cmip_ActionInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_ActionArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ActionArgument_sequence, hf_index, ett_cmip_ActionArgument);

  return offset;
}



static int
dissect_cmip_GeneralizedTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string cmip_T_actionErrorInfo_errorStatus_vals[] = {
  {   2, "accessDenied" },
  {   9, "noSuchAction" },
  {  14, "noSuchArgument" },
  {  15, "invalidArgumentValue" },
  { 0, NULL }
};


static int
dissect_cmip_T_actionErrorInfo_errorStatus(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t T_actionId_sequence[] = {
  { &hf_cmip_managedObjectClass, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectClass },
  { &hf_cmip_actionType     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ActionTypeId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_T_actionId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_actionId_sequence, hf_index, ett_cmip_T_actionId);

  return offset;
}



static int
dissect_cmip_T_eventTypeId_globalForm(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_cmip_eventType_OID, &object_identifier_id);

  return offset;
}


static const value_string cmip_EventTypeId_vals[] = {
  {   6, "globalForm" },
  {   7, "localForm" },
  { 0, NULL }
};

static const ber_choice_t EventTypeId_choice[] = {
  {   6, &hf_cmip_eventTypeId_globalForm, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_cmip_T_eventTypeId_globalForm },
  {   7, &hf_cmip_localForm      , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_cmip_INTEGER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_EventTypeId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 EventTypeId_choice, hf_index, ett_cmip_EventTypeId,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_eventId_sequence[] = {
  { &hf_cmip_managedObjectClass, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectClass },
  { &hf_cmip_eventType      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_EventTypeId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_T_eventId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_eventId_sequence, hf_index, ett_cmip_T_eventId);

  return offset;
}


static const value_string cmip_NoSuchArgument_vals[] = {
  {   0, "actionId" },
  {   1, "eventId" },
  { 0, NULL }
};

static const ber_choice_t NoSuchArgument_choice[] = {
  {   0, &hf_cmip_actionId       , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_cmip_T_actionId },
  {   1, &hf_cmip_eventId        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_cmip_T_eventId },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_NoSuchArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 NoSuchArgument_choice, hf_index, ett_cmip_NoSuchArgument,
                                 NULL);

  return offset;
}



static int
dissect_cmip_T_eventInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree, actx->private_data);


  return offset;
}


static const ber_sequence_t T_eventValue_sequence[] = {
  { &hf_cmip_eventType      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_EventTypeId },
  { &hf_cmip_eventInfo      , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_T_eventInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_T_eventValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_eventValue_sequence, hf_index, ett_cmip_T_eventValue);

  return offset;
}


static const value_string cmip_InvalidArgumentValue_vals[] = {
  {   0, "actionValue" },
  {   1, "eventValue" },
  { 0, NULL }
};

static const ber_choice_t InvalidArgumentValue_choice[] = {
  {   0, &hf_cmip_actionValue    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_cmip_ActionInfo },
  {   1, &hf_cmip_eventValue     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_cmip_T_eventValue },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_InvalidArgumentValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 InvalidArgumentValue_choice, hf_index, ett_cmip_InvalidArgumentValue,
                                 NULL);

  return offset;
}


static const value_string cmip_T_actionErrorInfo_vals[] = {
  {   0, "actionType" },
  {   1, "actionArgument" },
  {   2, "argumentValue" },
  { 0, NULL }
};

static const ber_choice_t T_actionErrorInfo_choice[] = {
  {   0, &hf_cmip_actionType     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_cmip_ActionTypeId },
  {   1, &hf_cmip_actionArgument , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_cmip_NoSuchArgument },
  {   2, &hf_cmip_argumentValue  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_cmip_InvalidArgumentValue },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_T_actionErrorInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_actionErrorInfo_choice, hf_index, ett_cmip_T_actionErrorInfo,
                                 NULL);

  return offset;
}


static const ber_sequence_t ActionErrorInfo_sequence[] = {
  { &hf_cmip_actionErrorInfo_errorStatus, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_cmip_T_actionErrorInfo_errorStatus },
  { &hf_cmip_actionErrorInfo, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_T_actionErrorInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_ActionErrorInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ActionErrorInfo_sequence, hf_index, ett_cmip_ActionErrorInfo);

  return offset;
}


static const ber_sequence_t ActionError_sequence[] = {
  { &hf_cmip_managedObjectClass, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectClass },
  { &hf_cmip_managedObjectInstance, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectInstance },
  { &hf_cmip_currentTime    , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_GeneralizedTime },
  { &hf_cmip_actionErroractionErrorInfo, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_cmip_ActionErrorInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_ActionError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ActionError_sequence, hf_index, ett_cmip_ActionError);

  return offset;
}



static int
dissect_cmip_T_actionReplyInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree, actx->private_data);



  return offset;
}


static const ber_sequence_t ActionReply_sequence[] = {
  { &hf_cmip_actionType     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ActionTypeId },
  { &hf_cmip_actionReplyInfo, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_cmip_T_actionReplyInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_ActionReply(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ActionReply_sequence, hf_index, ett_cmip_ActionReply);

  return offset;
}


static const ber_sequence_t ActionResult_sequence[] = {
  { &hf_cmip_managedObjectClass, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectClass },
  { &hf_cmip_managedObjectInstance, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectInstance },
  { &hf_cmip_currentTime    , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_GeneralizedTime },
  { &hf_cmip_actionReply    , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_ActionReply },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_ActionResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ActionResult_sequence, hf_index, ett_cmip_ActionResult);

  return offset;
}


static const value_string cmip_T_attributeError_errorStatus_vals[] = {
  {   2, "accessDenied" },
  {   5, "noSuchAttribute" },
  {   6, "invalidAttributeValue" },
  {  24, "invalidOperation" },
  {  25, "invalidOperator" },
  { 0, NULL }
};


static int
dissect_cmip_T_attributeError_errorStatus(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string cmip_ModifyOperator_vals[] = {
  {   0, "replace" },
  {   1, "addValues" },
  {   2, "removeValues" },
  {   3, "setToDefault" },
  { 0, NULL }
};


static int
dissect_cmip_ModifyOperator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_cmip_T_attributeValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree, actx->private_data);


  return offset;
}


static const ber_sequence_t AttributeError_sequence[] = {
  { &hf_cmip_attributeError_errorStatus, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_cmip_T_attributeError_errorStatus },
  { &hf_cmip_modifyOperator , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_ModifyOperator },
  { &hf_cmip_attributeId    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_AttributeId },
  { &hf_cmip_attributeValue , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cmip_T_attributeValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_AttributeError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttributeError_sequence, hf_index, ett_cmip_AttributeError);

  return offset;
}


static const value_string cmip_T_attributeIdError_errorStatus_vals[] = {
  {   2, "accessDenied" },
  {   5, "noSuchAttribute" },
  { 0, NULL }
};


static int
dissect_cmip_T_attributeIdError_errorStatus(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t AttributeIdError_sequence[] = {
  { &hf_cmip_attributeIdError_errorStatus, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_cmip_T_attributeIdError_errorStatus },
  { &hf_cmip_attributeId    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_AttributeId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_AttributeIdError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttributeIdError_sequence, hf_index, ett_cmip_AttributeIdError);

  return offset;
}


static const ber_sequence_t BaseManagedObjectId_sequence[] = {
  { &hf_cmip_baseManagedObjectClass, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectClass },
  { &hf_cmip_baseManagedObjectInstance, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectInstance },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_BaseManagedObjectId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   BaseManagedObjectId_sequence, hf_index, ett_cmip_BaseManagedObjectId);

  return offset;
}


static const ber_sequence_t ComplexityLimitation_set[] = {
  { &hf_cmip_scope          , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_Scope },
  { &hf_cmip_filter         , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_CMISFilter },
  { &hf_cmip_sync           , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_CMISSync },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_ComplexityLimitation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ComplexityLimitation_set, hf_index, ett_cmip_ComplexityLimitation);

  return offset;
}


static const value_string cmip_T_managedOrSuperiorObjectInstance_vals[] = {
  {   0, "managedObjectInstance" },
  {   1, "superiorObjectInstance" },
  { 0, NULL }
};

static const ber_choice_t T_managedOrSuperiorObjectInstance_choice[] = {
  {   0, &hf_cmip_managedObjectInstance, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_cmip_ObjectInstance },
  {   1, &hf_cmip_superiorObjectInstance, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_cmip_ObjectInstance },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_T_managedOrSuperiorObjectInstance(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_managedOrSuperiorObjectInstance_choice, hf_index, ett_cmip_T_managedOrSuperiorObjectInstance,
                                 NULL);

  return offset;
}


static const ber_sequence_t SET_OF_Attribute_set_of[1] = {
  { &hf_cmip_attributeList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmip_Attribute },
};

static int
dissect_cmip_SET_OF_Attribute(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_Attribute_set_of, hf_index, ett_cmip_SET_OF_Attribute);

  return offset;
}


static const ber_sequence_t CreateArgument_sequence[] = {
  { &hf_cmip_managedObjectClass, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectClass },
  { &hf_cmip_managedOrSuperiorObjectInstance, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_T_managedOrSuperiorObjectInstance },
  { &hf_cmip_accessControl  , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_AccessControl },
  { &hf_cmip_referenceObjectInstance, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectInstance },
  { &hf_cmip_attributeList  , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_SET_OF_Attribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_CreateArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CreateArgument_sequence, hf_index, ett_cmip_CreateArgument);

  return offset;
}


static const ber_sequence_t CreateResult_sequence[] = {
  { &hf_cmip_managedObjectClass, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectClass },
  { &hf_cmip_managedObjectInstance, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectInstance },
  { &hf_cmip_currentTime    , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_GeneralizedTime },
  { &hf_cmip_attributeList  , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_SET_OF_Attribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_CreateResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CreateResult_sequence, hf_index, ett_cmip_CreateResult);

  return offset;
}


static const ber_sequence_t DeleteArgument_sequence[] = {
  { &hf_cmip_baseManagedObjectClass, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectClass },
  { &hf_cmip_baseManagedObjectInstance, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectInstance },
  { &hf_cmip_accessControl  , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_AccessControl },
  { &hf_cmip_synchronization, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_CMISSync },
  { &hf_cmip_scope          , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_Scope },
  { &hf_cmip_filter         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_CMISFilter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_DeleteArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DeleteArgument_sequence, hf_index, ett_cmip_DeleteArgument);

  return offset;
}


static const value_string cmip_T_deleteErrorInfo_vals[] = {
  {   2, "accessDenied" },
  { 0, NULL }
};


static int
dissect_cmip_T_deleteErrorInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t DeleteError_sequence[] = {
  { &hf_cmip_managedObjectClass, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectClass },
  { &hf_cmip_managedObjectInstance, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectInstance },
  { &hf_cmip_currentTime    , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_GeneralizedTime },
  { &hf_cmip_deleteErrorInfo, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_cmip_T_deleteErrorInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_DeleteError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DeleteError_sequence, hf_index, ett_cmip_DeleteError);

  return offset;
}


static const ber_sequence_t DeleteResult_sequence[] = {
  { &hf_cmip_managedObjectClass, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectClass },
  { &hf_cmip_managedObjectInstance, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectInstance },
  { &hf_cmip_currentTime    , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_GeneralizedTime },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_DeleteResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DeleteResult_sequence, hf_index, ett_cmip_DeleteResult);

  return offset;
}



static int
dissect_cmip_T_eventReplyInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree, actx->private_data);


  return offset;
}


static const ber_sequence_t EventReply_sequence[] = {
  { &hf_cmip_eventType      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_EventTypeId },
  { &hf_cmip_eventReplyInfo , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_T_eventReplyInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_EventReply(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EventReply_sequence, hf_index, ett_cmip_EventReply);

  return offset;
}



static int
dissect_cmip_EventReportArgumentEventInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree, actx->private_data);


  return offset;
}


static const ber_sequence_t EventReportArgument_sequence[] = {
  { &hf_cmip_managedObjectClass, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectClass },
  { &hf_cmip_managedObjectInstance, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectInstance },
  { &hf_cmip_eventTime      , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_GeneralizedTime },
  { &hf_cmip_eventType      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_EventTypeId },
  { &hf_cmip_eventReportArgumenteventInfo, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_EventReportArgumentEventInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_EventReportArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EventReportArgument_sequence, hf_index, ett_cmip_EventReportArgument);

  return offset;
}


static const ber_sequence_t EventReportResult_sequence[] = {
  { &hf_cmip_managedObjectClass, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectClass },
  { &hf_cmip_managedObjectInstance, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectInstance },
  { &hf_cmip_currentTime    , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_GeneralizedTime },
  { &hf_cmip_eventReply     , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cmip_EventReply },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_EventReportResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EventReportResult_sequence, hf_index, ett_cmip_EventReportResult);

  return offset;
}


static const ber_sequence_t SET_OF_AttributeId_set_of[1] = {
  { &hf_cmip_attributeIdList_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_AttributeId },
};

static int
dissect_cmip_SET_OF_AttributeId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_AttributeId_set_of, hf_index, ett_cmip_SET_OF_AttributeId);

  return offset;
}


static const ber_sequence_t GetArgument_sequence[] = {
  { &hf_cmip_baseManagedObjectClass, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectClass },
  { &hf_cmip_baseManagedObjectInstance, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectInstance },
  { &hf_cmip_accessControl  , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_AccessControl },
  { &hf_cmip_synchronization, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_CMISSync },
  { &hf_cmip_scope          , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_Scope },
  { &hf_cmip_filter         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_CMISFilter },
  { &hf_cmip_attributeIdList, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_SET_OF_AttributeId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_GetArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetArgument_sequence, hf_index, ett_cmip_GetArgument);

  return offset;
}


static const value_string cmip_GetInfoStatus_vals[] = {
  {   0, "attributeIdError" },
  {   1, "attribute" },
  { 0, NULL }
};

static const ber_choice_t GetInfoStatus_choice[] = {
  {   0, &hf_cmip_attributeIdError, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_cmip_AttributeIdError },
  {   1, &hf_cmip_attribute      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_cmip_Attribute },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_GetInfoStatus(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 GetInfoStatus_choice, hf_index, ett_cmip_GetInfoStatus,
                                 NULL);

  return offset;
}


static const ber_sequence_t SET_OF_GetInfoStatus_set_of[1] = {
  { &hf_cmip_getInfoList_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_GetInfoStatus },
};

static int
dissect_cmip_SET_OF_GetInfoStatus(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_GetInfoStatus_set_of, hf_index, ett_cmip_SET_OF_GetInfoStatus);

  return offset;
}


static const ber_sequence_t GetListError_sequence[] = {
  { &hf_cmip_managedObjectClass, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectClass },
  { &hf_cmip_managedObjectInstance, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectInstance },
  { &hf_cmip_currentTime    , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_GeneralizedTime },
  { &hf_cmip_getInfoList    , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_cmip_SET_OF_GetInfoStatus },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_GetListError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetListError_sequence, hf_index, ett_cmip_GetListError);

  return offset;
}


static const ber_sequence_t GetResult_sequence[] = {
  { &hf_cmip_managedObjectClass, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectClass },
  { &hf_cmip_managedObjectInstance, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectInstance },
  { &hf_cmip_currentTime    , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_GeneralizedTime },
  { &hf_cmip_attributeList  , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_SET_OF_Attribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_GetResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetResult_sequence, hf_index, ett_cmip_GetResult);

  return offset;
}



static int
dissect_cmip_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string cmip_InvokeId_vals[] = {
  {   0, "present" },
  {   1, "absent" },
  { 0, NULL }
};

static const ber_choice_t InvokeId_choice[] = {
  {   0, &hf_cmip_present        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmip_INTEGER },
  {   1, &hf_cmip_absent         , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_cmip_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_InvokeId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 InvokeId_choice, hf_index, ett_cmip_InvokeId,
                                 NULL);

  return offset;
}



int
dissect_cmip_InvokeIDType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cmip_InvokeId(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t SetResult_sequence[] = {
  { &hf_cmip_managedObjectClass, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectClass },
  { &hf_cmip_managedObjectInstance, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectInstance },
  { &hf_cmip_currentTime    , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_GeneralizedTime },
  { &hf_cmip_attributeList  , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_SET_OF_Attribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_SetResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SetResult_sequence, hf_index, ett_cmip_SetResult);

  return offset;
}


static const value_string cmip_SetInfoStatus_vals[] = {
  {   0, "attributeError" },
  {   1, "attribute" },
  { 0, NULL }
};

static const ber_choice_t SetInfoStatus_choice[] = {
  {   0, &hf_cmip_attributeError , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_cmip_AttributeError },
  {   1, &hf_cmip_attribute      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_cmip_Attribute },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_SetInfoStatus(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SetInfoStatus_choice, hf_index, ett_cmip_SetInfoStatus,
                                 NULL);

  return offset;
}


static const ber_sequence_t SET_OF_SetInfoStatus_set_of[1] = {
  { &hf_cmip_setInfoList_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_SetInfoStatus },
};

static int
dissect_cmip_SET_OF_SetInfoStatus(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_SetInfoStatus_set_of, hf_index, ett_cmip_SET_OF_SetInfoStatus);

  return offset;
}


static const ber_sequence_t SetListError_sequence[] = {
  { &hf_cmip_managedObjectClass, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectClass },
  { &hf_cmip_managedObjectInstance, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectInstance },
  { &hf_cmip_currentTime    , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_GeneralizedTime },
  { &hf_cmip_setInfoList    , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_cmip_SET_OF_SetInfoStatus },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_SetListError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SetListError_sequence, hf_index, ett_cmip_SetListError);

  return offset;
}



static int
dissect_cmip_T_errorId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_cmip_errorId_OID, &object_identifier_id);

  return offset;
}



static int
dissect_cmip_T_errorInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree, actx->private_data);


  return offset;
}


static const ber_sequence_t SpecificErrorInfo_sequence[] = {
  { &hf_cmip_errorId        , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cmip_T_errorId },
  { &hf_cmip_errorInfo      , BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_cmip_T_errorInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_SpecificErrorInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SpecificErrorInfo_sequence, hf_index, ett_cmip_SpecificErrorInfo);

  return offset;
}


static const ber_sequence_t ProcessingFailure_sequence[] = {
  { &hf_cmip_managedObjectClass, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectClass },
  { &hf_cmip_managedObjectInstance, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectInstance },
  { &hf_cmip_specificErrorInfo, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_cmip_SpecificErrorInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_ProcessingFailure(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ProcessingFailure_sequence, hf_index, ett_cmip_ProcessingFailure);

  return offset;
}


static const ber_choice_t LinkedReplyArgument_choice[] = {
  {   0, &hf_cmip_getResult      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_cmip_GetResult },
  {   1, &hf_cmip_getListError   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_cmip_GetListError },
  {   2, &hf_cmip_setResult      , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_cmip_SetResult },
  {   3, &hf_cmip_setListError   , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_cmip_SetListError },
  {   4, &hf_cmip_actionResult   , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_cmip_ActionResult },
  {   5, &hf_cmip_processingFailure, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_cmip_ProcessingFailure },
  {   6, &hf_cmip_deleteResult   , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_cmip_DeleteResult },
  {   7, &hf_cmip_actionError    , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_cmip_ActionError },
  {   8, &hf_cmip_deleteError    , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_cmip_DeleteError },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_LinkedReplyArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 LinkedReplyArgument_choice, hf_index, ett_cmip_LinkedReplyArgument,
                                 NULL);

  return offset;
}


static const ber_sequence_t NoSuchAction_sequence[] = {
  { &hf_cmip_managedObjectClass, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectClass },
  { &hf_cmip_actionType     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ActionTypeId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_NoSuchAction(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NoSuchAction_sequence, hf_index, ett_cmip_NoSuchAction);

  return offset;
}


static const ber_sequence_t NoSuchEventType_sequence[] = {
  { &hf_cmip_managedObjectClass, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectClass },
  { &hf_cmip_eventType      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_EventTypeId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_NoSuchEventType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NoSuchEventType_sequence, hf_index, ett_cmip_NoSuchEventType);

  return offset;
}



static int
dissect_cmip_T_attributevalue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  if(actx->external.direct_ref_present){
    offset=call_ber_oid_callback(actx->external.direct_reference, tvb, offset, actx->pinfo, tree, NULL);
  } else if (actx->external.indirect_ref_present &&
             dissector_try_uint(attribute_id_dissector_table, actx->external.indirect_reference, tvb, actx->pinfo, tree)) {
    offset=tvb_reported_length (tvb);
  } else {
    offset=dissect_unknown_ber(actx->pinfo, tvb, offset, tree);
  }


  return offset;
}


static const ber_sequence_t T_modificationList_item_sequence[] = {
  { &hf_cmip_modifyOperator , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_ModifyOperator },
  { &hf_cmip_attributeId    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_AttributeId },
  { &hf_cmip_attributevalue , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cmip_T_attributevalue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_T_modificationList_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_modificationList_item_sequence, hf_index, ett_cmip_T_modificationList_item);

  return offset;
}


static const ber_sequence_t T_modificationList_set_of[1] = {
  { &hf_cmip_modificationList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmip_T_modificationList_item },
};

static int
dissect_cmip_T_modificationList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_modificationList_set_of, hf_index, ett_cmip_T_modificationList);

  return offset;
}


static const ber_sequence_t SetArgument_sequence[] = {
  { &hf_cmip_baseManagedObjectClass, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectClass },
  { &hf_cmip_baseManagedObjectInstance, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectInstance },
  { &hf_cmip_accessControl  , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_AccessControl },
  { &hf_cmip_synchronization, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_CMISSync },
  { &hf_cmip_scope          , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_Scope },
  { &hf_cmip_filter         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_CMISFilter },
  { &hf_cmip_modificationList, BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_cmip_T_modificationList },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_SetArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SetArgument_sequence, hf_index, ett_cmip_SetArgument);

  return offset;
}


static const value_string cmip_CMIPAbortSource_vals[] = {
  {   0, "cmiseServiceUser" },
  {   1, "cmiseServiceProvider" },
  { 0, NULL }
};


static int
dissect_cmip_CMIPAbortSource(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  uint32_t value;

    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  &value);

  col_append_fstr(actx->pinfo->cinfo, COL_INFO, " AbortSource:%s", val_to_str(value, cmip_CMIPAbortSource_vals, " Unknown AbortSource:%d"));

  return offset;
}



static int
dissect_cmip_EXTERNAL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_external_type(implicit_tag, tree, tvb, offset, actx, hf_index, NULL);

  return offset;
}


static const ber_sequence_t CMIPAbortInfo_sequence[] = {
  { &hf_cmip_abortSource    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_cmip_CMIPAbortSource },
  { &hf_cmip_userInfo       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_EXTERNAL },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cmip_CMIPAbortInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_str(actx->pinfo->cinfo, COL_INFO, "CMIP-A-ABORT");
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CMIPAbortInfo_sequence, hf_index, ett_cmip_CMIPAbortInfo);

  return offset;
}


static int * const FunctionalUnits_bits[] = {
  &hf_cmip_FunctionalUnits_multipleObjectSelection,
  &hf_cmip_FunctionalUnits_filter,
  &hf_cmip_FunctionalUnits_multipleReply,
  &hf_cmip_FunctionalUnits_extendedService,
  &hf_cmip_FunctionalUnits_cancelGet,
  NULL
};

static int
dissect_cmip_FunctionalUnits(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    FunctionalUnits_bits, 5, hf_index, ett_cmip_FunctionalUnits,
                                    NULL);

  return offset;
}


static int * const ProtocolVersion_bits[] = {
  &hf_cmip_ProtocolVersion_version1,
  &hf_cmip_ProtocolVersion_version2,
  NULL
};

static int
dissect_cmip_ProtocolVersion(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    ProtocolVersion_bits, 2, hf_index, ett_cmip_ProtocolVersion,
                                    NULL);

  return offset;
}


static const ber_sequence_t CMIPUserInfo_sequence[] = {
  { &hf_cmip_protocolVersion, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_ProtocolVersion },
  { &hf_cmip_functionalUnits, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_FunctionalUnits },
  { &hf_cmip_cmipUserInfoaccessControl, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_EXTERNAL },
  { &hf_cmip_userInfo       , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_EXTERNAL },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cmip_CMIPUserInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  col_append_str(actx->pinfo->cinfo, COL_INFO, "CMIP-A-ASSOCIATE");
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CMIPUserInfo_sequence, hf_index, ett_cmip_CMIPUserInfo);

  return offset;
}


static const ber_sequence_t SET_OF_AE_title_set_of[1] = {
  { &hf_cmip_multiple_item  , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_acse_AE_title },
};

static int
dissect_cmip_SET_OF_AE_title(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_AE_title_set_of, hf_index, ett_cmip_SET_OF_AE_title);

  return offset;
}


static const value_string cmip_Destination_vals[] = {
  {   0, "single" },
  {   1, "multiple" },
  { 0, NULL }
};

static const ber_choice_t Destination_choice[] = {
  {   0, &hf_cmip_single         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_acse_AE_title },
  {   1, &hf_cmip_multiple       , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_cmip_SET_OF_AE_title },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_Destination(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Destination_choice, hf_index, ett_cmip_Destination,
                                 NULL);

  return offset;
}



static int
dissect_cmip_ActiveDestination(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cmip_Destination(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_cmip_AdditionalText(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GraphicString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_cmip_T_managementExtensionidentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &object_identifier_id);

  return offset;
}



static int
dissect_cmip_BOOLEAN(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_cmip_T_information(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree, actx->private_data);


  return offset;
}


static const ber_sequence_t ManagementExtension_sequence[] = {
  { &hf_cmip_managementExtensionidentifier, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cmip_T_managementExtensionidentifier },
  { &hf_cmip_significance   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_BOOLEAN },
  { &hf_cmip_information    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_cmip_T_information },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_ManagementExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ManagementExtension_sequence, hf_index, ett_cmip_ManagementExtension);

  return offset;
}


static const ber_sequence_t AdditionalInformation_set_of[1] = {
  { &hf_cmip_AdditionalInformation_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmip_ManagementExtension },
};

int
dissect_cmip_AdditionalInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 AdditionalInformation_set_of, hf_index, ett_cmip_AdditionalInformation);

  return offset;
}


static const ber_sequence_t Allomorphs_set_of[1] = {
  { &hf_cmip_Allomorphs_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectClass },
};

static int
dissect_cmip_Allomorphs(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 Allomorphs_set_of, hf_index, ett_cmip_Allomorphs);

  return offset;
}


const value_string cmip_AdministrativeState_vals[] = {
  {   0, "locked" },
  {   1, "unlocked" },
  {   2, "shuttingDown" },
  { 0, NULL }
};


int
dissect_cmip_AdministrativeState(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t AttributeIdentifierList_set_of[1] = {
  { &hf_cmip_AttributeIdentifierList_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_AttributeId },
};

static int
dissect_cmip_AttributeIdentifierList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 AttributeIdentifierList_set_of, hf_index, ett_cmip_AttributeIdentifierList);

  return offset;
}


static const ber_sequence_t AttributeList_set_of[1] = {
  { &hf_cmip_AttributeList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmip_Attribute },
};

int
dissect_cmip_AttributeList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 AttributeList_set_of, hf_index, ett_cmip_AttributeList);

  return offset;
}



static int
dissect_cmip_T_oldAttributeValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree, actx->private_data);


  return offset;
}



static int
dissect_cmip_T_newAttributeValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree, actx->private_data);


  return offset;
}


static const ber_sequence_t AttributeValueChangeDefinition_item_sequence[] = {
  { &hf_cmip_attributeId    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_AttributeId },
  { &hf_cmip_oldAttributeValue, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_T_oldAttributeValue },
  { &hf_cmip_newAttributeValue, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_cmip_T_newAttributeValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_AttributeValueChangeDefinition_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttributeValueChangeDefinition_item_sequence, hf_index, ett_cmip_AttributeValueChangeDefinition_item);

  return offset;
}


static const ber_sequence_t AttributeValueChangeDefinition_set_of[1] = {
  { &hf_cmip_AttributeValueChangeDefinition_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmip_AttributeValueChangeDefinition_item },
};

static int
dissect_cmip_AttributeValueChangeDefinition(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 AttributeValueChangeDefinition_set_of, hf_index, ett_cmip_AttributeValueChangeDefinition);

  return offset;
}


static const value_string cmip_AlarmStatus_item_vals[] = {
  {   0, "underRepair" },
  {   1, "critical" },
  {   2, "major" },
  {   3, "minor" },
  {   4, "alarmOutstanding" },
  { 0, NULL }
};


static int
dissect_cmip_AlarmStatus_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t AlarmStatus_set_of[1] = {
  { &hf_cmip_AlarmStatus_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmip_AlarmStatus_item },
};

static int
dissect_cmip_AlarmStatus(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 AlarmStatus_set_of, hf_index, ett_cmip_AlarmStatus);

  return offset;
}


static const value_string cmip_AvailabilityStatus_item_vals[] = {
  {   0, "inTest" },
  {   1, "failed" },
  {   2, "powerOff" },
  {   3, "offLine" },
  {   4, "offDuty" },
  {   5, "dependency" },
  {   6, "degraded" },
  {   7, "notInstalled" },
  {   8, "logFull" },
  { 0, NULL }
};


static int
dissect_cmip_AvailabilityStatus_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t AvailabilityStatus_set_of[1] = {
  { &hf_cmip_AvailabilityStatus_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmip_AvailabilityStatus_item },
};

int
dissect_cmip_AvailabilityStatus(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 AvailabilityStatus_set_of, hf_index, ett_cmip_AvailabilityStatus);

  return offset;
}



static int
dissect_cmip_BackedUpStatus(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t BackUpDestinationList_sequence_of[1] = {
  { &hf_cmip_BackUpDestinationList_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_acse_AE_title },
};

static int
dissect_cmip_BackUpDestinationList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      BackUpDestinationList_sequence_of, hf_index, ett_cmip_BackUpDestinationList);

  return offset;
}


static const value_string cmip_BackUpRelationshipObject_vals[] = {
  {   0, "objectName" },
  {   1, "noObject" },
  { 0, NULL }
};

static const ber_choice_t BackUpRelationshipObject_choice[] = {
  {   0, &hf_cmip_objectName     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_cmip_ObjectInstance },
  {   1, &hf_cmip_noObject       , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_cmip_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_BackUpRelationshipObject(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 BackUpRelationshipObject_choice, hf_index, ett_cmip_BackUpRelationshipObject,
                                 NULL);

  return offset;
}



static int
dissect_cmip_INTEGER_0_100(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t CapacityAlarmThreshold_set_of[1] = {
  { &hf_cmip_CapacityAlarmThreshold_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmip_INTEGER_0_100 },
};

static int
dissect_cmip_CapacityAlarmThreshold(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 CapacityAlarmThreshold_set_of, hf_index, ett_cmip_CapacityAlarmThreshold);

  return offset;
}



static int
dissect_cmip_ConfirmedMode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const value_string cmip_ControlStatus_item_vals[] = {
  {   0, "subjectToTest" },
  {   1, "partOfServicesLocked" },
  {   2, "reservedForTest" },
  {   3, "suspended" },
  { 0, NULL }
};


static int
dissect_cmip_ControlStatus_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t ControlStatus_set_of[1] = {
  { &hf_cmip_ControlStatus_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmip_ControlStatus_item },
};

static int
dissect_cmip_ControlStatus(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 ControlStatus_set_of, hf_index, ett_cmip_ControlStatus);

  return offset;
}



static int
dissect_cmip_NotificationIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t SET_OF_NotificationIdentifier_set_of[1] = {
  { &hf_cmip_correlatedNotifications_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmip_NotificationIdentifier },
};

static int
dissect_cmip_SET_OF_NotificationIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_NotificationIdentifier_set_of, hf_index, ett_cmip_SET_OF_NotificationIdentifier);

  return offset;
}


static const ber_sequence_t CorrelatedNotifications_item_sequence[] = {
  { &hf_cmip_correlatedNotifications, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_cmip_SET_OF_NotificationIdentifier },
  { &hf_cmip_sourceObjectInst, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectInstance },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_CorrelatedNotifications_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CorrelatedNotifications_item_sequence, hf_index, ett_cmip_CorrelatedNotifications_item);

  return offset;
}


static const ber_sequence_t CorrelatedNotifications_set_of[1] = {
  { &hf_cmip_CorrelatedNotifications_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmip_CorrelatedNotifications_item },
};

static int
dissect_cmip_CorrelatedNotifications(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 CorrelatedNotifications_set_of, hf_index, ett_cmip_CorrelatedNotifications);

  return offset;
}



static int
dissect_cmip_CurrentLogSize(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_cmip_DiscriminatorConstruct(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cmip_CMISFilter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_cmip_EventTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t GroupObjects_set_of[1] = {
  { &hf_cmip_GroupObjects_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectInstance },
};

static int
dissect_cmip_GroupObjects(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 GroupObjects_set_of, hf_index, ett_cmip_GroupObjects);

  return offset;
}



static int
dissect_cmip_INTEGER_0_23(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_cmip_INTEGER_0_59(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t Time24_sequence[] = {
  { &hf_cmip_hour           , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmip_INTEGER_0_23 },
  { &hf_cmip_minute         , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmip_INTEGER_0_59 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_Time24(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Time24_sequence, hf_index, ett_cmip_Time24);

  return offset;
}


static const ber_sequence_t IntervalsOfDay_item_sequence[] = {
  { &hf_cmip_intervalStart  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmip_Time24 },
  { &hf_cmip_intervalEnd    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmip_Time24 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_IntervalsOfDay_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IntervalsOfDay_item_sequence, hf_index, ett_cmip_IntervalsOfDay_item);

  return offset;
}


static const ber_sequence_t IntervalsOfDay_set_of[1] = {
  { &hf_cmip_IntervalsOfDay_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmip_IntervalsOfDay_item },
};

static int
dissect_cmip_IntervalsOfDay(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 IntervalsOfDay_set_of, hf_index, ett_cmip_IntervalsOfDay);

  return offset;
}


static const value_string cmip_LifecycleState_vals[] = {
  {   0, "planned" },
  {   1, "installed" },
  {   2, "pendingRemoval" },
  { 0, NULL }
};


static int
dissect_cmip_LifecycleState(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string cmip_LogFullAction_vals[] = {
  {   0, "wrap" },
  {   1, "halt" },
  { 0, NULL }
};


static int
dissect_cmip_LogFullAction(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_cmip_LoggingTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_cmip_GraphicString(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GraphicString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string cmip_SimpleNameType_vals[] = {
  {   0, "number" },
  {   1, "string" },
  { 0, NULL }
};

static const ber_choice_t SimpleNameType_choice[] = {
  {   0, &hf_cmip_number         , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmip_INTEGER },
  {   1, &hf_cmip_string         , BER_CLASS_UNI, BER_UNI_TAG_GraphicString, BER_FLAGS_NOOWNTAG, dissect_cmip_GraphicString },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_SimpleNameType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SimpleNameType_choice, hf_index, ett_cmip_SimpleNameType,
                                 NULL);

  return offset;
}



static int
dissect_cmip_LogRecordId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cmip_SimpleNameType(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string cmip_MaxLogSize_vals[] = {
  {   0, "unlimited" },
  { 0, NULL }
};


static int
dissect_cmip_MaxLogSize(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t MonitoredAttributes_set_of[1] = {
  { &hf_cmip_MonitoredAttributes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmip_Attribute },
};

static int
dissect_cmip_MonitoredAttributes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 MonitoredAttributes_set_of, hf_index, ett_cmip_MonitoredAttributes);

  return offset;
}



static int
dissect_cmip_NameBinding(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_cmip_NumberOfRecords(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_cmip_REAL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_real(implicit_tag, actx, tree, tvb, offset, hf_index,
                               NULL);

  return offset;
}


static const value_string cmip_ObservedValue_vals[] = {
  {   0, "integer" },
  {   1, "real" },
  { 0, NULL }
};

static const ber_choice_t ObservedValue_choice[] = {
  {   0, &hf_cmip_integer        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmip_INTEGER },
  {   1, &hf_cmip_real           , BER_CLASS_UNI, BER_UNI_TAG_REAL, BER_FLAGS_NOOWNTAG, dissect_cmip_REAL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_ObservedValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ObservedValue_choice, hf_index, ett_cmip_ObservedValue,
                                 NULL);

  return offset;
}


static const value_string cmip_OperationalState_vals[] = {
  {   0, "disabled" },
  {   1, "enabled" },
  { 0, NULL }
};


static int
dissect_cmip_OperationalState(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_cmip_OBJECT_IDENTIFIER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t Packages_set_of[1] = {
  { &hf_cmip_Packages_item  , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cmip_OBJECT_IDENTIFIER },
};

static int
dissect_cmip_Packages(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 Packages_set_of, hf_index, ett_cmip_Packages);

  return offset;
}


static const value_string cmip_PerceivedSeverity_vals[] = {
  {   0, "indeterminate" },
  {   1, "critical" },
  {   2, "major" },
  {   3, "minor" },
  {   4, "warning" },
  {   5, "cleared" },
  { 0, NULL }
};


static int
dissect_cmip_PerceivedSeverity(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string cmip_T_priority_vals[] = {
  {   0, "highest" },
  { 127, "lowest" },
  { 0, NULL }
};


static int
dissect_cmip_T_priority(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t PrioritisedObject_item_sequence[] = {
  { &hf_cmip_object         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectInstance },
  { &hf_cmip_priority       , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmip_T_priority },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_PrioritisedObject_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PrioritisedObject_item_sequence, hf_index, ett_cmip_PrioritisedObject_item);

  return offset;
}


static const ber_sequence_t PrioritisedObject_set_of[1] = {
  { &hf_cmip_PrioritisedObject_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmip_PrioritisedObject_item },
};

static int
dissect_cmip_PrioritisedObject(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 PrioritisedObject_set_of, hf_index, ett_cmip_PrioritisedObject);

  return offset;
}


const value_string cmip_ProbableCause_vals[] = {
  {   0, "globalValue" },
  {   1, "localValue" },
  { 0, NULL }
};

static const ber_choice_t ProbableCause_choice[] = {
  {   0, &hf_cmip_globalValue    , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cmip_OBJECT_IDENTIFIER },
  {   1, &hf_cmip_localValue     , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmip_INTEGER },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_cmip_ProbableCause(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ProbableCause_choice, hf_index, ett_cmip_ProbableCause,
                                 NULL);

  return offset;
}


static const value_string cmip_ProceduralStatus_item_vals[] = {
  {   0, "initializationRequired" },
  {   1, "notInitialized" },
  {   2, "initializing" },
  {   3, "reporting" },
  {   4, "terminating" },
  { 0, NULL }
};


static int
dissect_cmip_ProceduralStatus_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t ProceduralStatus_set_of[1] = {
  { &hf_cmip_ProceduralStatus_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmip_ProceduralStatus_item },
};

static int
dissect_cmip_ProceduralStatus(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 ProceduralStatus_set_of, hf_index, ett_cmip_ProceduralStatus);

  return offset;
}


static const value_string cmip_SpecificIdentifier_vals[] = {
  {   0, "oi" },
  {   1, "int" },
  { 0, NULL }
};

static const ber_choice_t SpecificIdentifier_choice[] = {
  {   0, &hf_cmip_oi             , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cmip_OBJECT_IDENTIFIER },
  {   1, &hf_cmip_int            , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmip_INTEGER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_SpecificIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SpecificIdentifier_choice, hf_index, ett_cmip_SpecificIdentifier,
                                 NULL);

  return offset;
}


static const ber_sequence_t ProposedRepairActions_set_of[1] = {
  { &hf_cmip_ProposedRepairActions_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_SpecificIdentifier },
};

static int
dissect_cmip_ProposedRepairActions(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 ProposedRepairActions_set_of, hf_index, ett_cmip_ProposedRepairActions);

  return offset;
}



static int
dissect_cmip_SecurityAlarmCause(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_cmip_SecurityAlarmSeverity(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cmip_PerceivedSeverity(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string cmip_SecurityAlarmDetector_vals[] = {
  {   0, "mechanism" },
  {   1, "object" },
  {   2, "application" },
  { 0, NULL }
};

static const ber_choice_t SecurityAlarmDetector_choice[] = {
  {   0, &hf_cmip_mechanism      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_cmip_OBJECT_IDENTIFIER },
  {   1, &hf_cmip_object         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_cmip_ObjectInstance },
  {   2, &hf_cmip_application    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_acse_AE_title },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_SecurityAlarmDetector(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SecurityAlarmDetector_choice, hf_index, ett_cmip_SecurityAlarmDetector,
                                 NULL);

  return offset;
}



static int
dissect_cmip_T_serviceUseridentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &object_identifier_id);

  return offset;
}



static int
dissect_cmip_T_details(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree, actx->private_data);


  return offset;
}


static const ber_sequence_t ServiceUser_sequence[] = {
  { &hf_cmip_serviceUseridentifier, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cmip_T_serviceUseridentifier },
  { &hf_cmip_details        , BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_cmip_T_details },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_ServiceUser(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ServiceUser_sequence, hf_index, ett_cmip_ServiceUser);

  return offset;
}



static int
dissect_cmip_ServiceProvider(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cmip_ServiceUser(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string cmip_SourceIndicator_vals[] = {
  {   0, "resourceOperation" },
  {   1, "managementOperation" },
  {   2, "unknown" },
  { 0, NULL }
};


static int
dissect_cmip_SourceIndicator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t SpecificProblems_set_of[1] = {
  { &hf_cmip_SpecificProblems_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_SpecificIdentifier },
};

static int
dissect_cmip_SpecificProblems(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SpecificProblems_set_of, hf_index, ett_cmip_SpecificProblems);

  return offset;
}


static const value_string cmip_StandbyStatus_vals[] = {
  {   0, "hotStandby" },
  {   1, "coldStandby" },
  {   2, "providingService" },
  { 0, NULL }
};


static int
dissect_cmip_StandbyStatus(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_cmip_StartTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string cmip_StopTime_vals[] = {
  {   0, "specific" },
  {   1, "continual" },
  { 0, NULL }
};

static const ber_choice_t StopTime_choice[] = {
  {   0, &hf_cmip_specific       , BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_cmip_GeneralizedTime },
  {   1, &hf_cmip_continual      , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_cmip_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_StopTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 StopTime_choice, hf_index, ett_cmip_StopTime,
                                 NULL);

  return offset;
}



static int
dissect_cmip_T_featureIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &object_identifier_id);

  return offset;
}



static int
dissect_cmip_T_featureInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree, actx->private_data);


  return offset;
}


static const ber_sequence_t SupportedFeatures_item_sequence[] = {
  { &hf_cmip_featureIdentifier, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cmip_T_featureIdentifier },
  { &hf_cmip_featureInfo    , BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_cmip_T_featureInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_SupportedFeatures_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SupportedFeatures_item_sequence, hf_index, ett_cmip_SupportedFeatures_item);

  return offset;
}


static const ber_sequence_t SupportedFeatures_set_of[1] = {
  { &hf_cmip_SupportedFeatures_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmip_SupportedFeatures_item },
};

static int
dissect_cmip_SupportedFeatures(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SupportedFeatures_set_of, hf_index, ett_cmip_SupportedFeatures);

  return offset;
}


static const value_string cmip_SystemId_vals[] = {
  {   0, "name" },
  {   1, "number" },
  {   2, "nothing" },
  { 0, NULL }
};

static const ber_choice_t SystemId_choice[] = {
  {   0, &hf_cmip_name           , BER_CLASS_UNI, BER_UNI_TAG_GraphicString, BER_FLAGS_NOOWNTAG, dissect_cmip_GraphicString },
  {   1, &hf_cmip_number         , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmip_INTEGER },
  {   2, &hf_cmip_nothing        , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_cmip_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_SystemId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SystemId_choice, hf_index, ett_cmip_SystemId,
                                 NULL);

  return offset;
}


static const value_string cmip_SystemTitle_vals[] = {
  {   0, "distinguishedName" },
  {   1, "oid" },
  {   2, "nothing" },
  { 0, NULL }
};

static const ber_choice_t SystemTitle_choice[] = {
  {   0, &hf_cmip_distinguishedName, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmip_DistinguishedName },
  {   1, &hf_cmip_oid            , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cmip_OBJECT_IDENTIFIER },
  {   2, &hf_cmip_nothing        , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_cmip_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_SystemTitle(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SystemTitle_choice, hf_index, ett_cmip_SystemTitle,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_up_sequence[] = {
  { &hf_cmip_high           , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObservedValue },
  { &hf_cmip_low            , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObservedValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_T_up(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_up_sequence, hf_index, ett_cmip_T_up);

  return offset;
}


static const ber_sequence_t T_down_sequence[] = {
  { &hf_cmip_high           , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObservedValue },
  { &hf_cmip_low            , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObservedValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_T_down(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_down_sequence, hf_index, ett_cmip_T_down);

  return offset;
}


static const value_string cmip_ThresholdLevelInd_vals[] = {
  {   1, "up" },
  {   2, "down" },
  { 0, NULL }
};

static const ber_choice_t ThresholdLevelInd_choice[] = {
  {   1, &hf_cmip_up             , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_cmip_T_up },
  {   2, &hf_cmip_down           , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_cmip_T_down },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_ThresholdLevelInd(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ThresholdLevelInd_choice, hf_index, ett_cmip_ThresholdLevelInd,
                                 NULL);

  return offset;
}


static const ber_sequence_t ThresholdInfo_sequence[] = {
  { &hf_cmip_triggeredThreshold, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_AttributeId },
  { &hf_cmip_observedValue  , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObservedValue },
  { &hf_cmip_thresholdLevel , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ThresholdLevelInd },
  { &hf_cmip_armTime        , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_GeneralizedTime },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_ThresholdInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ThresholdInfo_sequence, hf_index, ett_cmip_ThresholdInfo);

  return offset;
}


static const value_string cmip_TrendIndication_vals[] = {
  {   0, "lessSevere" },
  {   1, "noChange" },
  {   2, "moreSevere" },
  { 0, NULL }
};


static int
dissect_cmip_TrendIndication(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_cmip_UnknownStatus(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const value_string cmip_UsageState_vals[] = {
  {   0, "idle" },
  {   1, "active" },
  {   2, "busy" },
  { 0, NULL }
};


static int
dissect_cmip_UsageState(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static int * const T_daysOfWeek_bits[] = {
  &hf_cmip_T_daysOfWeek_sunday,
  &hf_cmip_T_daysOfWeek_monday,
  &hf_cmip_T_daysOfWeek_tuesday,
  &hf_cmip_T_daysOfWeek_wednesday,
  &hf_cmip_T_daysOfWeek_thursday,
  &hf_cmip_T_daysOfWeek_friday,
  &hf_cmip_T_daysOfWeek_saturday,
  NULL
};

static int
dissect_cmip_T_daysOfWeek(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    T_daysOfWeek_bits, 7, hf_index, ett_cmip_T_daysOfWeek,
                                    NULL);

  return offset;
}


static const ber_sequence_t WeekMask_item_sequence[] = {
  { &hf_cmip_daysOfWeek     , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_cmip_T_daysOfWeek },
  { &hf_cmip_intervalsOfDay , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_cmip_IntervalsOfDay },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_WeekMask_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   WeekMask_item_sequence, hf_index, ett_cmip_WeekMask_item);

  return offset;
}


static const ber_sequence_t WeekMask_set_of[1] = {
  { &hf_cmip_WeekMask_item  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmip_WeekMask_item },
};

static int
dissect_cmip_WeekMask(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 WeekMask_set_of, hf_index, ett_cmip_WeekMask);

  return offset;
}



static int
dissect_cmip_T_local(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &opcode);

  if(opcode_type== OPCODE_RETURN_ERROR){
	col_append_str(actx->pinfo->cinfo, COL_INFO, val_to_str(opcode, cmip_error_code_vals, " Unknown Opcode:%d"));
  }else{
	col_append_str(actx->pinfo->cinfo, COL_INFO, val_to_str(opcode, cmip_Opcode_vals, " Unknown Opcode:%d"));
  }

  return offset;
}


static const value_string cmip_Code_vals[] = {
  {   0, "local" },
  {   1, "global" },
  { 0, NULL }
};

static const ber_choice_t Code_choice[] = {
  {   0, &hf_cmip_local          , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmip_T_local },
  {   1, &hf_cmip_global         , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cmip_OBJECT_IDENTIFIER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_Code(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Code_choice, hf_index, ett_cmip_Code,
                                 NULL);

  return offset;
}



static int
dissect_cmip_InvokeId_present(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_cmip_T_linkedIdPresent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cmip_InvokeId_present(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string cmip_T_linkedId_vals[] = {
  {   0, "present" },
  {   1, "absent" },
  { 0, NULL }
};

static const ber_choice_t T_linkedId_choice[] = {
  {   0, &hf_cmip_linkedIdPresent, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_cmip_T_linkedIdPresent },
  {   1, &hf_cmip_absent         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_cmip_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_T_linkedId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_linkedId_choice, hf_index, ett_cmip_T_linkedId,
                                 NULL);

  return offset;
}



static int
dissect_cmip_InvokeArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    switch(opcode){
    case 0: /* M-eventreport */
      offset = dissect_cmip_EventReportArgument(false, tvb, offset, actx, tree, -1);
      break;
    case 1: /* M-eventreport-confirmed */
      offset = dissect_cmip_EventReportArgument(false, tvb, offset, actx, tree, -1);
      break;
    case 2: /* M-linkedreply */
      offset = dissect_cmip_LinkedReplyArgument(false, tvb, offset, actx, tree, -1);
      break;
    case 3: /* M-get */
      offset = dissect_cmip_GetArgument(false, tvb, offset,actx, tree, -1);
      break;
    case 4: /* M-set */
      offset = dissect_cmip_SetArgument(false, tvb, offset,actx, tree, -1);
      break;
    case 5: /* M-set-confirmed */
      offset = dissect_cmip_SetArgument(false, tvb, offset,actx, tree, -1);
      break;
    case 6: /* M-action*/
      offset = dissect_cmip_ActionArgument(false, tvb,  offset, actx, tree, -1);
      break;
    case 7: /* M-action-confirmed*/
      offset = dissect_cmip_ActionArgument(false, tvb,  offset, actx, tree, -1);
      break;
    case 8: /* M-create*/
      offset = dissect_cmip_CreateArgument(false, tvb,  offset, actx, tree, -1);
      break;
    case 9: /* M-delete*/
      offset = dissect_cmip_DeleteArgument(false, tvb,  offset, actx, tree, -1);
      break;
    case 10: /* M-cancelget */
      offset = dissect_cmip_InvokeIDType(false, tvb,  offset, actx, tree, -1);
      break;
    }



  return offset;
}


static const ber_sequence_t Invoke_sequence[] = {
  { &hf_cmip_invokeId       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_InvokeId },
  { &hf_cmip_linkedId       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_T_linkedId },
  { &hf_cmip_opcode         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_Code },
  { &hf_cmip_argument       , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cmip_InvokeArgument },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_Invoke(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  opcode_type=OPCODE_INVOKE;
  col_prepend_fstr(actx->pinfo->cinfo, COL_INFO, "Invoke ");
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Invoke_sequence, hf_index, ett_cmip_Invoke);

  return offset;
}



static int
dissect_cmip_ResultArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

    switch(opcode){
    case 0: /* M-eventreport*/
      break;  /* No return data */
    case 1: /* M-eventreport-confirmed */
      offset = dissect_cmip_EventReportResult(false, tvb, offset, actx, tree, -1);
      break;
    case 2: /* M-linkedreply*/
      break;  /* No return data */
    case 3: /* M-get */
      offset = dissect_cmip_GetResult(false, tvb, offset, actx, tree, -1);
      break;
    case 4: /* M-set */
      break;  /* No return data */
    case 5: /* M-set-confirmed*/
      offset = dissect_cmip_SetResult(false, tvb, offset, actx, tree, -1);
      break;
    case 6: /* M-action*/
      break;  /* No return data */
    case 7: /* M-action-confirmed*/
      offset = dissect_cmip_ActionResult(false, tvb, offset, actx, tree, -1);
      break;
    case 8: /* M-create*/
      offset = dissect_cmip_CreateResult(false, tvb,  offset, actx, tree, -1);
      break;
    case 9: /* M-delete*/
      offset = dissect_cmip_DeleteResult(false, tvb,  offset, actx, tree, -1);
      break;
    case 10: /* M-cancelget */
      break; /* doe this one return any data? */
    }
  /*XXX add more types here */


  return offset;
}


static const ber_sequence_t T_result_sequence[] = {
  { &hf_cmip_opcode         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_Code },
  { &hf_cmip_resultArgument , BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_cmip_ResultArgument },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_T_result(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_result_sequence, hf_index, ett_cmip_T_result);

  return offset;
}


static const ber_sequence_t ReturnResult_sequence[] = {
  { &hf_cmip_invokeId       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_InvokeId },
  { &hf_cmip_result         , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cmip_T_result },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_ReturnResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  opcode_type=OPCODE_RETURN_RESULT;
  col_prepend_fstr(actx->pinfo->cinfo, COL_INFO, "ReturnResult ");
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReturnResult_sequence, hf_index, ett_cmip_ReturnResult);

  return offset;
}



static int
dissect_cmip_T_parameter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

    switch(opcode){
	case 19: /* classInstanceConflict */
		dissect_cmip_BaseManagedObjectId(false, tvb,  offset, actx, tree, -1);
		break;
	case 20:  /* complexityLimitation */
		dissect_cmip_ComplexityLimitation(false, tvb,  offset, actx, tree, -1);
		break;
	case 11: /* duplicateManagedObjectInstance */
		dissect_cmip_ObjectInstance(false, tvb,  offset, actx, tree, -1);
		break;
	case 7: /*  getListError */
		dissect_cmip_GetListError(false, tvb,  offset, actx, tree, -1);
		break;
	case 15: /* invalidArgumentValue */
		dissect_cmip_InvalidArgumentValue(false, tvb,  offset, actx, tree, -1);
		break;
	case 6: /* invalidAttributeValue */
		dissect_cmip_Attribute(false, tvb,  offset, actx, tree, -1);
		break;
	case 4: /* invalidFilter */
		dissect_cmip_CMISFilter(false, tvb,  offset, actx, tree, -1);
		break;
	case 17: /* invalidObjectInstance */
		dissect_cmip_ObjectInstance(false, tvb,  offset, actx, tree, -1);
		break;
	case 16: /* invalidScope */
		dissect_cmip_Scope(false, tvb,  offset, actx, tree, -1);
		break;
	case 18: /* missingAttributeValue */
		/* Hmmm  SET OF AttributeId */
		dissect_cmip_PAR_missingAttributeValue(false, tvb,  offset, actx, tree, -1);
		break;
	case 9: /* noSuchAction */
		dissect_cmip_NoSuchAction(false, tvb,  offset, actx, tree, -1);
		break;
	case 14: /* noSuchArgument */
		dissect_cmip_NoSuchArgument(false, tvb,  offset, actx, tree, -1);
		break;
	case 5: /* noSuchAttribute */
		dissect_cmip_AttributeId(false, tvb,  offset, actx, tree, -1);
		break;
	case 13: /* noSuchEventType */
		dissect_cmip_NoSuchEventType(false, tvb,  offset, actx, tree, -1);
		break;
	case 22: /* noSuchInvokeId */
		dissect_cmip_InvokeIDType(false, tvb,  offset, actx, tree, -1);
		break;
	case 0: /* noSuchObjectClass */
		dissect_cmip_ObjectClass(false, tvb,  offset, actx, tree, -1);
		break;
	case 1:/* noSuchObjectInstance */
		dissect_cmip_ObjectInstance(false, tvb,  offset, actx, tree, -1);
		break;
	case 12: /* noSuchReferenceObject */
		dissect_cmip_ObjectInstance(false, tvb,  offset, actx, tree, -1);
		break;
	case 10: /* processingFailure OPTIONAL   true*/
		dissect_cmip_ProcessingFailure(false, tvb,  offset, actx, tree, -1);
		break;
	case 8: /* setListError */
		dissect_cmip_SetListError(false, tvb,  offset, actx, tree, -1);
		break;
	case 3:/* syncNotSupported */
		dissect_cmip_CMISSync(false, tvb,  offset, actx, tree, -1);
		break;
	}


  return offset;
}


static const ber_sequence_t ReturnError_sequence[] = {
  { &hf_cmip_invokeId       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_InvokeId },
  { &hf_cmip_errcode        , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_Code },
  { &hf_cmip_parameter      , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cmip_T_parameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_ReturnError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  opcode_type=OPCODE_RETURN_ERROR;
  col_prepend_fstr(actx->pinfo->cinfo, COL_INFO, "ReturnError ");
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReturnError_sequence, hf_index, ett_cmip_ReturnError);

  return offset;
}


static const value_string cmip_GeneralProblem_vals[] = {
  {   0, "unrecognizedPDU" },
  {   1, "mistypedPDU" },
  {   2, "badlyStructuredPDU" },
  { 0, NULL }
};


static int
dissect_cmip_GeneralProblem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string cmip_InvokeProblem_vals[] = {
  {   0, "duplicateInvocation" },
  {   1, "unrecognizedOperation" },
  {   2, "mistypedArgument" },
  {   3, "resourceLimitation" },
  {   4, "releaseInProgress" },
  {   5, "unrecognizedLinkedId" },
  {   6, "linkedResponseUnexpected" },
  {   7, "unexpectedLinkedOperation" },
  { 0, NULL }
};


static int
dissect_cmip_InvokeProblem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string cmip_ReturnResultProblem_vals[] = {
  {   0, "unrecognizedInvocation" },
  {   1, "resultResponseUnexpected" },
  {   2, "mistypedResult" },
  { 0, NULL }
};


static int
dissect_cmip_ReturnResultProblem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string cmip_ReturnErrorProblem_vals[] = {
  {   0, "unrecognizedInvocation" },
  {   1, "errorResponseUnexpected" },
  {   2, "unrecognizedError" },
  {   3, "unexpectedError" },
  {   4, "mistypedParameter" },
  { 0, NULL }
};


static int
dissect_cmip_ReturnErrorProblem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string cmip_T_problem_vals[] = {
  {   0, "general" },
  {   1, "invoke" },
  {   2, "returnResult" },
  {   3, "returnError" },
  { 0, NULL }
};

static const ber_choice_t T_problem_choice[] = {
  {   0, &hf_cmip_general        , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_cmip_GeneralProblem },
  {   1, &hf_cmip_invokeProblem  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_cmip_InvokeProblem },
  {   2, &hf_cmip_returnResultProblem, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_cmip_ReturnResultProblem },
  {   3, &hf_cmip_returnErrorProblem, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_cmip_ReturnErrorProblem },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_T_problem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_problem_choice, hf_index, ett_cmip_T_problem,
                                 NULL);

  return offset;
}


static const ber_sequence_t Reject_sequence[] = {
  { &hf_cmip_invokeId       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_InvokeId },
  { &hf_cmip_problem        , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_T_problem },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_Reject(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  opcode_type=OPCODE_REJECT;
  col_prepend_fstr(actx->pinfo->cinfo, COL_INFO, "Reject ");
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Reject_sequence, hf_index, ett_cmip_Reject);

  return offset;
}


const value_string cmip_ROS_vals[] = {
  {   1, "invoke" },
  {   2, "returnResult" },
  {   3, "returnError" },
  {   4, "reject" },
  { 0, NULL }
};

static const ber_choice_t ROS_choice[] = {
  {   1, &hf_cmip_invoke         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_cmip_Invoke },
  {   2, &hf_cmip_returnResult   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_cmip_ReturnResult },
  {   3, &hf_cmip_returnError    , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_cmip_ReturnError },
  {   4, &hf_cmip_reject         , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_cmip_Reject },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_cmip_ROS(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ROS_choice, hf_index, ett_cmip_ROS,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_BaseManagedObjectId_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_BaseManagedObjectId(false, tvb, offset, &asn1_ctx, tree, hf_cmip_BaseManagedObjectId_PDU);
  return offset;
}
static int dissect_EventTypeId_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_EventTypeId(false, tvb, offset, &asn1_ctx, tree, hf_cmip_EventTypeId_PDU);
  return offset;
}
static int dissect_ObjectClass_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_ObjectClass(false, tvb, offset, &asn1_ctx, tree, hf_cmip_ObjectClass_PDU);
  return offset;
}
static int dissect_ActiveDestination_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_ActiveDestination(false, tvb, offset, &asn1_ctx, tree, hf_cmip_ActiveDestination_PDU);
  return offset;
}
static int dissect_AdditionalText_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_AdditionalText(false, tvb, offset, &asn1_ctx, tree, hf_cmip_AdditionalText_PDU);
  return offset;
}
static int dissect_AdditionalInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_AdditionalInformation(false, tvb, offset, &asn1_ctx, tree, hf_cmip_AdditionalInformation_PDU);
  return offset;
}
static int dissect_Allomorphs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_Allomorphs(false, tvb, offset, &asn1_ctx, tree, hf_cmip_Allomorphs_PDU);
  return offset;
}
static int dissect_AdministrativeState_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_AdministrativeState(false, tvb, offset, &asn1_ctx, tree, hf_cmip_AdministrativeState_PDU);
  return offset;
}
static int dissect_AttributeIdentifierList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_AttributeIdentifierList(false, tvb, offset, &asn1_ctx, tree, hf_cmip_AttributeIdentifierList_PDU);
  return offset;
}
static int dissect_AttributeList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_AttributeList(false, tvb, offset, &asn1_ctx, tree, hf_cmip_AttributeList_PDU);
  return offset;
}
static int dissect_AttributeValueChangeDefinition_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_AttributeValueChangeDefinition(false, tvb, offset, &asn1_ctx, tree, hf_cmip_AttributeValueChangeDefinition_PDU);
  return offset;
}
static int dissect_AlarmStatus_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_AlarmStatus(false, tvb, offset, &asn1_ctx, tree, hf_cmip_AlarmStatus_PDU);
  return offset;
}
static int dissect_AvailabilityStatus_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_AvailabilityStatus(false, tvb, offset, &asn1_ctx, tree, hf_cmip_AvailabilityStatus_PDU);
  return offset;
}
static int dissect_BackedUpStatus_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_BackedUpStatus(false, tvb, offset, &asn1_ctx, tree, hf_cmip_BackedUpStatus_PDU);
  return offset;
}
static int dissect_BackUpDestinationList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_BackUpDestinationList(false, tvb, offset, &asn1_ctx, tree, hf_cmip_BackUpDestinationList_PDU);
  return offset;
}
static int dissect_BackUpRelationshipObject_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_BackUpRelationshipObject(false, tvb, offset, &asn1_ctx, tree, hf_cmip_BackUpRelationshipObject_PDU);
  return offset;
}
static int dissect_CapacityAlarmThreshold_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_CapacityAlarmThreshold(false, tvb, offset, &asn1_ctx, tree, hf_cmip_CapacityAlarmThreshold_PDU);
  return offset;
}
static int dissect_ConfirmedMode_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_ConfirmedMode(false, tvb, offset, &asn1_ctx, tree, hf_cmip_ConfirmedMode_PDU);
  return offset;
}
static int dissect_ControlStatus_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_ControlStatus(false, tvb, offset, &asn1_ctx, tree, hf_cmip_ControlStatus_PDU);
  return offset;
}
static int dissect_CorrelatedNotifications_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_CorrelatedNotifications(false, tvb, offset, &asn1_ctx, tree, hf_cmip_CorrelatedNotifications_PDU);
  return offset;
}
static int dissect_CurrentLogSize_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_CurrentLogSize(false, tvb, offset, &asn1_ctx, tree, hf_cmip_CurrentLogSize_PDU);
  return offset;
}
static int dissect_Destination_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_Destination(false, tvb, offset, &asn1_ctx, tree, hf_cmip_Destination_PDU);
  return offset;
}
static int dissect_DiscriminatorConstruct_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_DiscriminatorConstruct(false, tvb, offset, &asn1_ctx, tree, hf_cmip_DiscriminatorConstruct_PDU);
  return offset;
}
static int dissect_EventTime_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_EventTime(false, tvb, offset, &asn1_ctx, tree, hf_cmip_EventTime_PDU);
  return offset;
}
static int dissect_GroupObjects_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_GroupObjects(false, tvb, offset, &asn1_ctx, tree, hf_cmip_GroupObjects_PDU);
  return offset;
}
static int dissect_IntervalsOfDay_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_IntervalsOfDay(false, tvb, offset, &asn1_ctx, tree, hf_cmip_IntervalsOfDay_PDU);
  return offset;
}
static int dissect_LifecycleState_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_LifecycleState(false, tvb, offset, &asn1_ctx, tree, hf_cmip_LifecycleState_PDU);
  return offset;
}
static int dissect_LogFullAction_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_LogFullAction(false, tvb, offset, &asn1_ctx, tree, hf_cmip_LogFullAction_PDU);
  return offset;
}
static int dissect_LoggingTime_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_LoggingTime(false, tvb, offset, &asn1_ctx, tree, hf_cmip_LoggingTime_PDU);
  return offset;
}
static int dissect_LogRecordId_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_LogRecordId(false, tvb, offset, &asn1_ctx, tree, hf_cmip_LogRecordId_PDU);
  return offset;
}
static int dissect_MaxLogSize_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_MaxLogSize(false, tvb, offset, &asn1_ctx, tree, hf_cmip_MaxLogSize_PDU);
  return offset;
}
static int dissect_MonitoredAttributes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_MonitoredAttributes(false, tvb, offset, &asn1_ctx, tree, hf_cmip_MonitoredAttributes_PDU);
  return offset;
}
static int dissect_NameBinding_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_NameBinding(false, tvb, offset, &asn1_ctx, tree, hf_cmip_NameBinding_PDU);
  return offset;
}
static int dissect_NotificationIdentifier_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_NotificationIdentifier(false, tvb, offset, &asn1_ctx, tree, hf_cmip_NotificationIdentifier_PDU);
  return offset;
}
static int dissect_NumberOfRecords_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_NumberOfRecords(false, tvb, offset, &asn1_ctx, tree, hf_cmip_NumberOfRecords_PDU);
  return offset;
}
static int dissect_OperationalState_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_OperationalState(false, tvb, offset, &asn1_ctx, tree, hf_cmip_OperationalState_PDU);
  return offset;
}
static int dissect_Packages_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_Packages(false, tvb, offset, &asn1_ctx, tree, hf_cmip_Packages_PDU);
  return offset;
}
static int dissect_PerceivedSeverity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_PerceivedSeverity(false, tvb, offset, &asn1_ctx, tree, hf_cmip_PerceivedSeverity_PDU);
  return offset;
}
static int dissect_PrioritisedObject_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_PrioritisedObject(false, tvb, offset, &asn1_ctx, tree, hf_cmip_PrioritisedObject_PDU);
  return offset;
}
static int dissect_ProbableCause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_ProbableCause(false, tvb, offset, &asn1_ctx, tree, hf_cmip_ProbableCause_PDU);
  return offset;
}
static int dissect_ProceduralStatus_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_ProceduralStatus(false, tvb, offset, &asn1_ctx, tree, hf_cmip_ProceduralStatus_PDU);
  return offset;
}
static int dissect_ProposedRepairActions_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_ProposedRepairActions(false, tvb, offset, &asn1_ctx, tree, hf_cmip_ProposedRepairActions_PDU);
  return offset;
}
static int dissect_SecurityAlarmCause_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_SecurityAlarmCause(false, tvb, offset, &asn1_ctx, tree, hf_cmip_SecurityAlarmCause_PDU);
  return offset;
}
static int dissect_SecurityAlarmSeverity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_SecurityAlarmSeverity(false, tvb, offset, &asn1_ctx, tree, hf_cmip_SecurityAlarmSeverity_PDU);
  return offset;
}
static int dissect_SecurityAlarmDetector_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_SecurityAlarmDetector(false, tvb, offset, &asn1_ctx, tree, hf_cmip_SecurityAlarmDetector_PDU);
  return offset;
}
static int dissect_ServiceProvider_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_ServiceProvider(false, tvb, offset, &asn1_ctx, tree, hf_cmip_ServiceProvider_PDU);
  return offset;
}
static int dissect_ServiceUser_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_ServiceUser(false, tvb, offset, &asn1_ctx, tree, hf_cmip_ServiceUser_PDU);
  return offset;
}
static int dissect_SimpleNameType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_SimpleNameType(false, tvb, offset, &asn1_ctx, tree, hf_cmip_SimpleNameType_PDU);
  return offset;
}
static int dissect_SourceIndicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_SourceIndicator(false, tvb, offset, &asn1_ctx, tree, hf_cmip_SourceIndicator_PDU);
  return offset;
}
static int dissect_SpecificProblems_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_SpecificProblems(false, tvb, offset, &asn1_ctx, tree, hf_cmip_SpecificProblems_PDU);
  return offset;
}
static int dissect_StandbyStatus_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_StandbyStatus(false, tvb, offset, &asn1_ctx, tree, hf_cmip_StandbyStatus_PDU);
  return offset;
}
static int dissect_StartTime_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_StartTime(false, tvb, offset, &asn1_ctx, tree, hf_cmip_StartTime_PDU);
  return offset;
}
static int dissect_StopTime_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_StopTime(false, tvb, offset, &asn1_ctx, tree, hf_cmip_StopTime_PDU);
  return offset;
}
static int dissect_SupportedFeatures_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_SupportedFeatures(false, tvb, offset, &asn1_ctx, tree, hf_cmip_SupportedFeatures_PDU);
  return offset;
}
static int dissect_SystemId_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_SystemId(false, tvb, offset, &asn1_ctx, tree, hf_cmip_SystemId_PDU);
  return offset;
}
static int dissect_SystemTitle_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_SystemTitle(false, tvb, offset, &asn1_ctx, tree, hf_cmip_SystemTitle_PDU);
  return offset;
}
static int dissect_ThresholdInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_ThresholdInfo(false, tvb, offset, &asn1_ctx, tree, hf_cmip_ThresholdInfo_PDU);
  return offset;
}
static int dissect_TrendIndication_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_TrendIndication(false, tvb, offset, &asn1_ctx, tree, hf_cmip_TrendIndication_PDU);
  return offset;
}
static int dissect_UnknownStatus_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_UnknownStatus(false, tvb, offset, &asn1_ctx, tree, hf_cmip_UnknownStatus_PDU);
  return offset;
}
static int dissect_UsageState_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_UsageState(false, tvb, offset, &asn1_ctx, tree, hf_cmip_UsageState_PDU);
  return offset;
}
static int dissect_WeekMask_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cmip_WeekMask(false, tvb, offset, &asn1_ctx, tree, hf_cmip_WeekMask_PDU);
  return offset;
}





/* XXX this one should be broken out later and moved into the conformance file */
static int
dissect_cmip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data)
{
	struct SESSION_DATA_STRUCTURE* session;
	proto_item *item;
	proto_tree *tree;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

	/* Reject the packet if data is NULL */
	if (data == NULL)
		return 0;
	session = (struct SESSION_DATA_STRUCTURE*)data;

	if(session->spdu_type == 0 ) {
		proto_tree_add_expert_format(parent_tree, pinfo, &ei_wrong_spdu_type, tvb, 0, -1,
			"Internal error: wrong spdu type %x from session dissector.", session->spdu_type);
		return 0;
	}

	asn1_ctx.private_data = session;

	item = proto_tree_add_item(parent_tree, proto_cmip, tvb, 0, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_cmip);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CMIP");
  	col_clear(pinfo->cinfo, COL_INFO);
	switch(session->spdu_type){
		case SES_CONNECTION_REQUEST:
		case SES_CONNECTION_ACCEPT:
		case SES_DISCONNECT:
		case SES_FINISH:
		case SES_REFUSE:
			dissect_cmip_CMIPUserInfo(false,tvb,0,&asn1_ctx,tree,-1);
			break;
		case SES_ABORT:
			dissect_cmip_CMIPAbortInfo(false,tvb,0,&asn1_ctx,tree,-1);
			break;
		case SES_DATA_TRANSFER:
			dissect_cmip_ROS(false,tvb,0,&asn1_ctx,tree,-1);
			break;
		default:
			;
	}

	return tvb_captured_length(tvb);
}

/*--- proto_register_cmip ----------------------------------------------*/
void proto_register_cmip(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_cmip_actionType_OID,
      { "actionType", "cmip.actionType_OID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_eventType_OID,
      { "eventType", "cmip.eventType_OID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_attributeId_OID,
      { "attributeId", "cmip.attributeId_OID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_errorId_OID,
      { "errorId", "cmip.errorId_OID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},

    { &hf_cmip_BaseManagedObjectId_PDU,
      { "BaseManagedObjectId", "cmip.BaseManagedObjectId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_EventTypeId_PDU,
      { "EventTypeId", "cmip.EventTypeId",
        FT_UINT32, BASE_DEC, VALS(cmip_EventTypeId_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_ObjectClass_PDU,
      { "ObjectClass", "cmip.ObjectClass",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectClass_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_ActiveDestination_PDU,
      { "ActiveDestination", "cmip.ActiveDestination",
        FT_UINT32, BASE_DEC, VALS(cmip_Destination_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_AdditionalText_PDU,
      { "AdditionalText", "cmip.AdditionalText",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_AdditionalInformation_PDU,
      { "AdditionalInformation", "cmip.AdditionalInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_Allomorphs_PDU,
      { "Allomorphs", "cmip.Allomorphs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_AdministrativeState_PDU,
      { "AdministrativeState", "cmip.AdministrativeState",
        FT_UINT32, BASE_DEC, VALS(cmip_AdministrativeState_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_AttributeIdentifierList_PDU,
      { "AttributeIdentifierList", "cmip.AttributeIdentifierList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_AttributeList_PDU,
      { "AttributeList", "cmip.AttributeList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_AttributeValueChangeDefinition_PDU,
      { "AttributeValueChangeDefinition", "cmip.AttributeValueChangeDefinition",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_AlarmStatus_PDU,
      { "AlarmStatus", "cmip.AlarmStatus",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_AvailabilityStatus_PDU,
      { "AvailabilityStatus", "cmip.AvailabilityStatus",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_BackedUpStatus_PDU,
      { "BackedUpStatus", "cmip.BackedUpStatus",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_BackUpDestinationList_PDU,
      { "BackUpDestinationList", "cmip.BackUpDestinationList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_BackUpRelationshipObject_PDU,
      { "BackUpRelationshipObject", "cmip.BackUpRelationshipObject",
        FT_UINT32, BASE_DEC, VALS(cmip_BackUpRelationshipObject_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_CapacityAlarmThreshold_PDU,
      { "CapacityAlarmThreshold", "cmip.CapacityAlarmThreshold",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_ConfirmedMode_PDU,
      { "ConfirmedMode", "cmip.ConfirmedMode",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_ControlStatus_PDU,
      { "ControlStatus", "cmip.ControlStatus",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_CorrelatedNotifications_PDU,
      { "CorrelatedNotifications", "cmip.CorrelatedNotifications",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_CurrentLogSize_PDU,
      { "CurrentLogSize", "cmip.CurrentLogSize",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_Destination_PDU,
      { "Destination", "cmip.Destination",
        FT_UINT32, BASE_DEC, VALS(cmip_Destination_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_DiscriminatorConstruct_PDU,
      { "DiscriminatorConstruct", "cmip.DiscriminatorConstruct",
        FT_UINT32, BASE_DEC, VALS(cmip_CMISFilter_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_EventTime_PDU,
      { "EventTime", "cmip.EventTime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_GroupObjects_PDU,
      { "GroupObjects", "cmip.GroupObjects",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_IntervalsOfDay_PDU,
      { "IntervalsOfDay", "cmip.IntervalsOfDay",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_LifecycleState_PDU,
      { "LifecycleState", "cmip.LifecycleState",
        FT_UINT32, BASE_DEC, VALS(cmip_LifecycleState_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_LogFullAction_PDU,
      { "LogFullAction", "cmip.LogFullAction",
        FT_UINT32, BASE_DEC, VALS(cmip_LogFullAction_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_LoggingTime_PDU,
      { "LoggingTime", "cmip.LoggingTime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_LogRecordId_PDU,
      { "LogRecordId", "cmip.LogRecordId",
        FT_UINT32, BASE_DEC, VALS(cmip_SimpleNameType_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_MaxLogSize_PDU,
      { "MaxLogSize", "cmip.MaxLogSize",
        FT_INT32, BASE_DEC, VALS(cmip_MaxLogSize_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_MonitoredAttributes_PDU,
      { "MonitoredAttributes", "cmip.MonitoredAttributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_NameBinding_PDU,
      { "NameBinding", "cmip.NameBinding",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_NotificationIdentifier_PDU,
      { "NotificationIdentifier", "cmip.NotificationIdentifier",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_NumberOfRecords_PDU,
      { "NumberOfRecords", "cmip.NumberOfRecords",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_OperationalState_PDU,
      { "OperationalState", "cmip.OperationalState",
        FT_UINT32, BASE_DEC, VALS(cmip_OperationalState_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_Packages_PDU,
      { "Packages", "cmip.Packages",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_PerceivedSeverity_PDU,
      { "PerceivedSeverity", "cmip.PerceivedSeverity",
        FT_UINT32, BASE_DEC, VALS(cmip_PerceivedSeverity_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_PrioritisedObject_PDU,
      { "PrioritisedObject", "cmip.PrioritisedObject",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_ProbableCause_PDU,
      { "ProbableCause", "cmip.ProbableCause",
        FT_UINT32, BASE_DEC, VALS(cmip_ProbableCause_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_ProceduralStatus_PDU,
      { "ProceduralStatus", "cmip.ProceduralStatus",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_ProposedRepairActions_PDU,
      { "ProposedRepairActions", "cmip.ProposedRepairActions",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_SecurityAlarmCause_PDU,
      { "SecurityAlarmCause", "cmip.SecurityAlarmCause",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_SecurityAlarmSeverity_PDU,
      { "SecurityAlarmSeverity", "cmip.SecurityAlarmSeverity",
        FT_UINT32, BASE_DEC, VALS(cmip_PerceivedSeverity_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_SecurityAlarmDetector_PDU,
      { "SecurityAlarmDetector", "cmip.SecurityAlarmDetector",
        FT_UINT32, BASE_DEC, VALS(cmip_SecurityAlarmDetector_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_ServiceProvider_PDU,
      { "ServiceProvider", "cmip.ServiceProvider_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_ServiceUser_PDU,
      { "ServiceUser", "cmip.ServiceUser_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_SimpleNameType_PDU,
      { "SimpleNameType", "cmip.SimpleNameType",
        FT_UINT32, BASE_DEC, VALS(cmip_SimpleNameType_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_SourceIndicator_PDU,
      { "SourceIndicator", "cmip.SourceIndicator",
        FT_UINT32, BASE_DEC, VALS(cmip_SourceIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_SpecificProblems_PDU,
      { "SpecificProblems", "cmip.SpecificProblems",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_StandbyStatus_PDU,
      { "StandbyStatus", "cmip.StandbyStatus",
        FT_INT32, BASE_DEC, VALS(cmip_StandbyStatus_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_StartTime_PDU,
      { "StartTime", "cmip.StartTime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_StopTime_PDU,
      { "StopTime", "cmip.StopTime",
        FT_UINT32, BASE_DEC, VALS(cmip_StopTime_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_SupportedFeatures_PDU,
      { "SupportedFeatures", "cmip.SupportedFeatures",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_SystemId_PDU,
      { "SystemId", "cmip.SystemId",
        FT_UINT32, BASE_DEC, VALS(cmip_SystemId_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_SystemTitle_PDU,
      { "SystemTitle", "cmip.SystemTitle",
        FT_UINT32, BASE_DEC, VALS(cmip_SystemTitle_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_ThresholdInfo_PDU,
      { "ThresholdInfo", "cmip.ThresholdInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_TrendIndication_PDU,
      { "TrendIndication", "cmip.TrendIndication",
        FT_UINT32, BASE_DEC, VALS(cmip_TrendIndication_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_UnknownStatus_PDU,
      { "UnknownStatus", "cmip.UnknownStatus",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_UsageState_PDU,
      { "UsageState", "cmip.UsageState",
        FT_UINT32, BASE_DEC, VALS(cmip_UsageState_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_WeekMask_PDU,
      { "WeekMask", "cmip.WeekMask",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_PAR_missingAttributeValue_item,
      { "AttributeId", "cmip.AttributeId",
        FT_UINT32, BASE_DEC, VALS(cmip_AttributeId_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_managedObjectClass,
      { "managedObjectClass", "cmip.managedObjectClass",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectClass_vals), 0,
        "ObjectClass", HFILL }},
    { &hf_cmip_managedObjectInstance,
      { "managedObjectInstance", "cmip.managedObjectInstance",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "ObjectInstance", HFILL }},
    { &hf_cmip_currentTime,
      { "currentTime", "cmip.currentTime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_cmip_actionErroractionErrorInfo,
      { "actionErrorInfo", "cmip.actionErrorInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_actionErrorInfo_errorStatus,
      { "errorStatus", "cmip.errorStatus",
        FT_UINT32, BASE_DEC, VALS(cmip_T_actionErrorInfo_errorStatus_vals), 0,
        "T_actionErrorInfo_errorStatus", HFILL }},
    { &hf_cmip_actionErrorInfo,
      { "errorInfo", "cmip.errorInfo",
        FT_UINT32, BASE_DEC, VALS(cmip_T_actionErrorInfo_vals), 0,
        "T_actionErrorInfo", HFILL }},
    { &hf_cmip_actionType,
      { "actionType", "cmip.actionType",
        FT_UINT32, BASE_DEC, VALS(cmip_ActionTypeId_vals), 0,
        "ActionTypeId", HFILL }},
    { &hf_cmip_actionArgument,
      { "actionArgument", "cmip.actionArgument",
        FT_UINT32, BASE_DEC, VALS(cmip_NoSuchArgument_vals), 0,
        "NoSuchArgument", HFILL }},
    { &hf_cmip_argumentValue,
      { "argumentValue", "cmip.argumentValue",
        FT_UINT32, BASE_DEC, VALS(cmip_InvalidArgumentValue_vals), 0,
        "InvalidArgumentValue", HFILL }},
    { &hf_cmip_actionInfoArg,
      { "actionInfoArg", "cmip.actionInfoArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_actionReplyInfo,
      { "actionReplyInfo", "cmip.actionReplyInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_actionReply,
      { "actionReply", "cmip.actionReply_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_actionTypeId_globalForm,
      { "globalForm", "cmip.globalForm",
        FT_OID, BASE_NONE, NULL, 0,
        "T_actionTypeId_globalForm", HFILL }},
    { &hf_cmip_localForm,
      { "localForm", "cmip.localForm",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_cmip_attributeid,
      { "id", "cmip.attributeid",
        FT_UINT32, BASE_DEC, VALS(cmip_AttributeId_vals), 0,
        "AttributeId", HFILL }},
    { &hf_cmip_value,
      { "value", "cmip.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeValue", HFILL }},
    { &hf_cmip_attributeError_errorStatus,
      { "errorStatus", "cmip.errorStatus",
        FT_UINT32, BASE_DEC, VALS(cmip_T_attributeError_errorStatus_vals), 0,
        "T_attributeError_errorStatus", HFILL }},
    { &hf_cmip_modifyOperator,
      { "modifyOperator", "cmip.modifyOperator",
        FT_INT32, BASE_DEC, VALS(cmip_ModifyOperator_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_attributeId,
      { "attributeId", "cmip.attributeId",
        FT_UINT32, BASE_DEC, VALS(cmip_AttributeId_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_attributeValue,
      { "attributeValue", "cmip.attributeValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_attributeId_globalForm,
      { "globalForm", "cmip.globalForm",
        FT_OID, BASE_NONE, NULL, 0,
        "T_attributeId_globalForm", HFILL }},
    { &hf_cmip_attributeIdlocalForm,
      { "localForm", "cmip.localForm",
        FT_INT32, BASE_DEC, NULL, 0,
        "T_attributeIdlocalForm", HFILL }},
    { &hf_cmip_attributeIdError_errorStatus,
      { "errorStatus", "cmip.errorStatus",
        FT_UINT32, BASE_DEC, VALS(cmip_T_attributeIdError_errorStatus_vals), 0,
        "T_attributeIdError_errorStatus", HFILL }},
    { &hf_cmip_id,
      { "id", "cmip.id",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_attributeValueAssertionvalue,
      { "value", "cmip.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_attributeValueAssertionvalue", HFILL }},
    { &hf_cmip_baseManagedObjectClass,
      { "baseManagedObjectClass", "cmip.baseManagedObjectClass",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectClass_vals), 0,
        "ObjectClass", HFILL }},
    { &hf_cmip_baseManagedObjectInstance,
      { "baseManagedObjectInstance", "cmip.baseManagedObjectInstance",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "ObjectInstance", HFILL }},
    { &hf_cmip_item,
      { "item", "cmip.item",
        FT_UINT32, BASE_DEC, VALS(cmip_FilterItem_vals), 0,
        "FilterItem", HFILL }},
    { &hf_cmip_and,
      { "and", "cmip.and",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_CMISFilter", HFILL }},
    { &hf_cmip_and_item,
      { "CMISFilter", "cmip.CMISFilter",
        FT_UINT32, BASE_DEC, VALS(cmip_CMISFilter_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_or,
      { "or", "cmip.or",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_CMISFilter", HFILL }},
    { &hf_cmip_or_item,
      { "CMISFilter", "cmip.CMISFilter",
        FT_UINT32, BASE_DEC, VALS(cmip_CMISFilter_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_not,
      { "not", "cmip.not",
        FT_UINT32, BASE_DEC, VALS(cmip_CMISFilter_vals), 0,
        "CMISFilter", HFILL }},
    { &hf_cmip_scope,
      { "scope", "cmip.scope",
        FT_UINT32, BASE_DEC, VALS(cmip_Scope_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_filter,
      { "filter", "cmip.filter",
        FT_UINT32, BASE_DEC, VALS(cmip_CMISFilter_vals), 0,
        "CMISFilter", HFILL }},
    { &hf_cmip_sync,
      { "sync", "cmip.sync",
        FT_UINT32, BASE_DEC, VALS(cmip_CMISSync_vals), 0,
        "CMISSync", HFILL }},
    { &hf_cmip_managedOrSuperiorObjectInstance,
      { "managedOrSuperiorObjectInstance", "cmip.managedOrSuperiorObjectInstance",
        FT_UINT32, BASE_DEC, VALS(cmip_T_managedOrSuperiorObjectInstance_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_superiorObjectInstance,
      { "superiorObjectInstance", "cmip.superiorObjectInstance",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "ObjectInstance", HFILL }},
    { &hf_cmip_accessControl,
      { "accessControl", "cmip.accessControl_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_referenceObjectInstance,
      { "referenceObjectInstance", "cmip.referenceObjectInstance",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "ObjectInstance", HFILL }},
    { &hf_cmip_attributeList,
      { "attributeList", "cmip.attributeList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_Attribute", HFILL }},
    { &hf_cmip_attributeList_item,
      { "Attribute", "cmip.Attribute_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_deleteErrorInfo,
      { "deleteErrorInfo", "cmip.deleteErrorInfo",
        FT_UINT32, BASE_DEC, VALS(cmip_T_deleteErrorInfo_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_eventType,
      { "eventType", "cmip.eventType",
        FT_UINT32, BASE_DEC, VALS(cmip_EventTypeId_vals), 0,
        "EventTypeId", HFILL }},
    { &hf_cmip_eventReplyInfo,
      { "eventReplyInfo", "cmip.eventReplyInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_eventTime,
      { "eventTime", "cmip.eventTime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_cmip_eventReportArgumenteventInfo,
      { "eventInfo", "cmip.eventInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventReportArgumentEventInfo", HFILL }},
    { &hf_cmip_eventReply,
      { "eventReply", "cmip.eventReply_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_eventTypeId_globalForm,
      { "globalForm", "cmip.globalForm",
        FT_OID, BASE_NONE, NULL, 0,
        "T_eventTypeId_globalForm", HFILL }},
    { &hf_cmip_equality,
      { "equality", "cmip.equality_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Attribute", HFILL }},
    { &hf_cmip_substrings,
      { "substrings", "cmip.substrings",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_substrings_item,
      { "substrings item", "cmip.substrings_item",
        FT_UINT32, BASE_DEC, VALS(cmip_T_substrings_item_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_initialString,
      { "initialString", "cmip.initialString_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Attribute", HFILL }},
    { &hf_cmip_anyString,
      { "anyString", "cmip.anyString_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Attribute", HFILL }},
    { &hf_cmip_finalString,
      { "finalString", "cmip.finalString_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Attribute", HFILL }},
    { &hf_cmip_greaterOrEqual,
      { "greaterOrEqual", "cmip.greaterOrEqual_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Attribute", HFILL }},
    { &hf_cmip_lessOrEqual,
      { "lessOrEqual", "cmip.lessOrEqual_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Attribute", HFILL }},
    { &hf_cmip_filterItempresent,
      { "present", "cmip.filterItempresent",
        FT_UINT32, BASE_DEC, VALS(cmip_AttributeId_vals), 0,
        "AttributeId", HFILL }},
    { &hf_cmip_subsetOf,
      { "subsetOf", "cmip.subsetOf_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Attribute", HFILL }},
    { &hf_cmip_supersetOf,
      { "supersetOf", "cmip.supersetOf_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Attribute", HFILL }},
    { &hf_cmip_nonNullSetIntersection,
      { "nonNullSetIntersection", "cmip.nonNullSetIntersection_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Attribute", HFILL }},
    { &hf_cmip_attributeIdError,
      { "attributeIdError", "cmip.attributeIdError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_attribute,
      { "attribute", "cmip.attribute_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_getInfoList,
      { "getInfoList", "cmip.getInfoList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_GetInfoStatus", HFILL }},
    { &hf_cmip_getInfoList_item,
      { "GetInfoStatus", "cmip.GetInfoStatus",
        FT_UINT32, BASE_DEC, VALS(cmip_GetInfoStatus_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_actionValue,
      { "actionValue", "cmip.actionValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ActionInfo", HFILL }},
    { &hf_cmip_eventValue,
      { "eventValue", "cmip.eventValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_eventInfo,
      { "eventInfo", "cmip.eventInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_getResult,
      { "getResult", "cmip.getResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_getListError,
      { "getListError", "cmip.getListError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_setResult,
      { "setResult", "cmip.setResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_setListError,
      { "setListError", "cmip.setListError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_actionResult,
      { "actionResult", "cmip.actionResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_processingFailure,
      { "processingFailure", "cmip.processingFailure_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_deleteResult,
      { "deleteResult", "cmip.deleteResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_actionError,
      { "actionError", "cmip.actionError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_deleteError,
      { "deleteError", "cmip.deleteError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_actionId,
      { "actionId", "cmip.actionId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_eventId,
      { "eventId", "cmip.eventId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_objectClass_globalForm,
      { "globalForm", "cmip.globalForm",
        FT_OID, BASE_NONE, NULL, 0,
        "T_objectClass_globalForm", HFILL }},
    { &hf_cmip_objectClasslocalForm,
      { "localForm", "cmip.localForm",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_cmip_distinguishedName,
      { "distinguishedName", "cmip.distinguishedName",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_nonSpecificForm,
      { "nonSpecificForm", "cmip.nonSpecificForm",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_cmip_localDistinguishedName,
      { "localDistinguishedName", "cmip.localDistinguishedName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RDNSequence", HFILL }},
    { &hf_cmip_specificErrorInfo,
      { "specificErrorInfo", "cmip.specificErrorInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_RDNSequence_item,
      { "RelativeDistinguishedName", "cmip.RelativeDistinguishedName",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_RelativeDistinguishedName_item,
      { "AttributeValueAssertion", "cmip.AttributeValueAssertion_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_namedNumbers,
      { "namedNumbers", "cmip.namedNumbers",
        FT_INT32, BASE_DEC, VALS(cmip_T_namedNumbers_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_individualLevels,
      { "individualLevels", "cmip.individualLevels",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_cmip_baseToNthLevel,
      { "baseToNthLevel", "cmip.baseToNthLevel",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_cmip_attributeError,
      { "attributeError", "cmip.attributeError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_setInfoList,
      { "setInfoList", "cmip.setInfoList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_SetInfoStatus", HFILL }},
    { &hf_cmip_setInfoList_item,
      { "SetInfoStatus", "cmip.SetInfoStatus",
        FT_UINT32, BASE_DEC, VALS(cmip_SetInfoStatus_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_errorId,
      { "errorId", "cmip.errorId",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_errorInfo,
      { "errorInfo", "cmip.errorInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_abortSource,
      { "abortSource", "cmip.abortSource",
        FT_UINT32, BASE_DEC, VALS(cmip_CMIPAbortSource_vals), 0,
        "CMIPAbortSource", HFILL }},
    { &hf_cmip_userInfo,
      { "userInfo", "cmip.userInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNAL", HFILL }},
    { &hf_cmip_protocolVersion,
      { "protocolVersion", "cmip.protocolVersion",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_functionalUnits,
      { "functionalUnits", "cmip.functionalUnits",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_cmipUserInfoaccessControl,
      { "accessControl", "cmip.accessControl_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNAL", HFILL }},
    { &hf_cmip_AdditionalInformation_item,
      { "ManagementExtension", "cmip.ManagementExtension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_Allomorphs_item,
      { "ObjectClass", "cmip.ObjectClass",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectClass_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_AttributeIdentifierList_item,
      { "AttributeId", "cmip.AttributeId",
        FT_UINT32, BASE_DEC, VALS(cmip_AttributeId_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_AttributeList_item,
      { "Attribute", "cmip.Attribute_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_AttributeValueChangeDefinition_item,
      { "AttributeValueChangeDefinition item", "cmip.AttributeValueChangeDefinition_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_oldAttributeValue,
      { "oldAttributeValue", "cmip.oldAttributeValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_newAttributeValue,
      { "newAttributeValue", "cmip.newAttributeValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_AlarmStatus_item,
      { "AlarmStatus item", "cmip.AlarmStatus_item",
        FT_INT32, BASE_DEC, VALS(cmip_AlarmStatus_item_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_AvailabilityStatus_item,
      { "AvailabilityStatus item", "cmip.AvailabilityStatus_item",
        FT_INT32, BASE_DEC, VALS(cmip_AvailabilityStatus_item_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_BackUpDestinationList_item,
      { "AE-title", "cmip.AE_title",
        FT_UINT32, BASE_DEC, VALS(acse_AE_title_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_objectName,
      { "objectName", "cmip.objectName",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "ObjectInstance", HFILL }},
    { &hf_cmip_noObject,
      { "noObject", "cmip.noObject_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_CapacityAlarmThreshold_item,
      { "CapacityAlarmThreshold item", "cmip.CapacityAlarmThreshold_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_100", HFILL }},
    { &hf_cmip_ControlStatus_item,
      { "ControlStatus item", "cmip.ControlStatus_item",
        FT_INT32, BASE_DEC, VALS(cmip_ControlStatus_item_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_CorrelatedNotifications_item,
      { "CorrelatedNotifications item", "cmip.CorrelatedNotifications_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_correlatedNotifications,
      { "correlatedNotifications", "cmip.correlatedNotifications",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_NotificationIdentifier", HFILL }},
    { &hf_cmip_correlatedNotifications_item,
      { "NotificationIdentifier", "cmip.NotificationIdentifier",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_sourceObjectInst,
      { "sourceObjectInst", "cmip.sourceObjectInst",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "ObjectInstance", HFILL }},
    { &hf_cmip_single,
      { "single", "cmip.single",
        FT_UINT32, BASE_DEC, VALS(acse_AE_title_vals), 0,
        "AE_title", HFILL }},
    { &hf_cmip_multiple,
      { "multiple", "cmip.multiple",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_AE_title", HFILL }},
    { &hf_cmip_multiple_item,
      { "AE-title", "cmip.AE_title",
        FT_UINT32, BASE_DEC, VALS(acse_AE_title_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_GroupObjects_item,
      { "ObjectInstance", "cmip.ObjectInstance",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_IntervalsOfDay_item,
      { "IntervalsOfDay item", "cmip.IntervalsOfDay_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_intervalStart,
      { "intervalStart", "cmip.intervalStart_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Time24", HFILL }},
    { &hf_cmip_intervalEnd,
      { "intervalEnd", "cmip.intervalEnd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Time24", HFILL }},
    { &hf_cmip_managementExtensionidentifier,
      { "identifier", "cmip.identifier",
        FT_OID, BASE_NONE, NULL, 0,
        "T_managementExtensionidentifier", HFILL }},
    { &hf_cmip_significance,
      { "significance", "cmip.significance",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_cmip_information,
      { "information", "cmip.information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_MonitoredAttributes_item,
      { "Attribute", "cmip.Attribute_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_integer,
      { "integer", "cmip.integer",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_real,
      { "real", "cmip.real",
        FT_DOUBLE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_Packages_item,
      { "Packages item", "cmip.Packages_item",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_cmip_PrioritisedObject_item,
      { "PrioritisedObject item", "cmip.PrioritisedObject_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_object,
      { "object", "cmip.object",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "ObjectInstance", HFILL }},
    { &hf_cmip_priority,
      { "priority", "cmip.priority",
        FT_INT32, BASE_DEC, VALS(cmip_T_priority_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_globalValue,
      { "globalValue", "cmip.globalValue",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_cmip_localValue,
      { "localValue", "cmip.localValue",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_cmip_ProceduralStatus_item,
      { "ProceduralStatus item", "cmip.ProceduralStatus_item",
        FT_INT32, BASE_DEC, VALS(cmip_ProceduralStatus_item_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_ProposedRepairActions_item,
      { "SpecificIdentifier", "cmip.SpecificIdentifier",
        FT_UINT32, BASE_DEC, VALS(cmip_SpecificIdentifier_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_mechanism,
      { "mechanism", "cmip.mechanism",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_cmip_application,
      { "application", "cmip.application",
        FT_UINT32, BASE_DEC, VALS(acse_AE_title_vals), 0,
        "AE_title", HFILL }},
    { &hf_cmip_serviceUseridentifier,
      { "identifier", "cmip.identifier",
        FT_OID, BASE_NONE, NULL, 0,
        "T_serviceUseridentifier", HFILL }},
    { &hf_cmip_details,
      { "details", "cmip.details_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_number,
      { "number", "cmip.number",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_cmip_string,
      { "string", "cmip.string",
        FT_STRING, BASE_NONE, NULL, 0,
        "GraphicString", HFILL }},
    { &hf_cmip_oi,
      { "oi", "cmip.oi",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_cmip_int,
      { "int", "cmip.int",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_cmip_SpecificProblems_item,
      { "SpecificIdentifier", "cmip.SpecificIdentifier",
        FT_UINT32, BASE_DEC, VALS(cmip_SpecificIdentifier_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_specific,
      { "specific", "cmip.specific",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_cmip_continual,
      { "continual", "cmip.continual_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_SupportedFeatures_item,
      { "SupportedFeatures item", "cmip.SupportedFeatures_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_featureIdentifier,
      { "featureIdentifier", "cmip.featureIdentifier",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_featureInfo,
      { "featureInfo", "cmip.featureInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_name,
      { "name", "cmip.name",
        FT_STRING, BASE_NONE, NULL, 0,
        "GraphicString", HFILL }},
    { &hf_cmip_nothing,
      { "nothing", "cmip.nothing_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_oid,
      { "oid", "cmip.oid",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_cmip_hour,
      { "hour", "cmip.hour",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_23", HFILL }},
    { &hf_cmip_minute,
      { "minute", "cmip.minute",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_59", HFILL }},
    { &hf_cmip_triggeredThreshold,
      { "triggeredThreshold", "cmip.triggeredThreshold",
        FT_UINT32, BASE_DEC, VALS(cmip_AttributeId_vals), 0,
        "AttributeId", HFILL }},
    { &hf_cmip_observedValue,
      { "observedValue", "cmip.observedValue",
        FT_UINT32, BASE_DEC, VALS(cmip_ObservedValue_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_thresholdLevel,
      { "thresholdLevel", "cmip.thresholdLevel",
        FT_UINT32, BASE_DEC, VALS(cmip_ThresholdLevelInd_vals), 0,
        "ThresholdLevelInd", HFILL }},
    { &hf_cmip_armTime,
      { "armTime", "cmip.armTime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_cmip_up,
      { "up", "cmip.up_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_high,
      { "high", "cmip.high",
        FT_UINT32, BASE_DEC, VALS(cmip_ObservedValue_vals), 0,
        "ObservedValue", HFILL }},
    { &hf_cmip_low,
      { "low", "cmip.low",
        FT_UINT32, BASE_DEC, VALS(cmip_ObservedValue_vals), 0,
        "ObservedValue", HFILL }},
    { &hf_cmip_down,
      { "down", "cmip.down_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_WeekMask_item,
      { "WeekMask item", "cmip.WeekMask_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_daysOfWeek,
      { "daysOfWeek", "cmip.daysOfWeek",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_intervalsOfDay,
      { "intervalsOfDay", "cmip.intervalsOfDay",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_local,
      { "local", "cmip.local",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_global,
      { "global", "cmip.global",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_cmip_invoke,
      { "invoke", "cmip.invoke_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_returnResult,
      { "returnResult", "cmip.returnResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_returnError,
      { "returnError", "cmip.returnError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_reject,
      { "reject", "cmip.reject_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_invokeId,
      { "invokeId", "cmip.invokeId",
        FT_UINT32, BASE_DEC, VALS(cmip_InvokeId_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_linkedId,
      { "linkedId", "cmip.linkedId",
        FT_UINT32, BASE_DEC, VALS(cmip_T_linkedId_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_linkedIdPresent,
      { "present", "cmip.linkedIdPresent",
        FT_INT32, BASE_DEC, NULL, 0,
        "T_linkedIdPresent", HFILL }},
    { &hf_cmip_absent,
      { "absent", "cmip.absent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_opcode,
      { "opcode", "cmip.opcode",
        FT_UINT32, BASE_DEC, VALS(cmip_Code_vals), 0,
        "Code", HFILL }},
    { &hf_cmip_argument,
      { "argument", "cmip.argument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "InvokeArgument", HFILL }},
    { &hf_cmip_result,
      { "result", "cmip.result_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_resultArgument,
      { "result", "cmip.result_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ResultArgument", HFILL }},
    { &hf_cmip_errcode,
      { "errcode", "cmip.errcode",
        FT_UINT32, BASE_DEC, VALS(cmip_Code_vals), 0,
        "Code", HFILL }},
    { &hf_cmip_parameter,
      { "parameter", "cmip.parameter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_problem,
      { "problem", "cmip.problem",
        FT_UINT32, BASE_DEC, VALS(cmip_T_problem_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_general,
      { "general", "cmip.general",
        FT_INT32, BASE_DEC, VALS(cmip_GeneralProblem_vals), 0,
        "GeneralProblem", HFILL }},
    { &hf_cmip_invokeProblem,
      { "invoke", "cmip.invoke",
        FT_INT32, BASE_DEC, VALS(cmip_InvokeProblem_vals), 0,
        "InvokeProblem", HFILL }},
    { &hf_cmip_returnResultProblem,
      { "returnResult", "cmip.returnResult",
        FT_INT32, BASE_DEC, VALS(cmip_ReturnResultProblem_vals), 0,
        "ReturnResultProblem", HFILL }},
    { &hf_cmip_returnErrorProblem,
      { "returnError", "cmip.returnError",
        FT_INT32, BASE_DEC, VALS(cmip_ReturnErrorProblem_vals), 0,
        "ReturnErrorProblem", HFILL }},
    { &hf_cmip_present,
      { "present", "cmip.present",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_cmip_synchronization,
      { "synchronization", "cmip.synchronization",
        FT_UINT32, BASE_DEC, VALS(cmip_CMISSync_vals), 0,
        "CMISSync", HFILL }},
    { &hf_cmip_actionInfo,
      { "actionInfo", "cmip.actionInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_attributeIdList,
      { "attributeIdList", "cmip.attributeIdList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_AttributeId", HFILL }},
    { &hf_cmip_attributeIdList_item,
      { "AttributeId", "cmip.AttributeId",
        FT_UINT32, BASE_DEC, VALS(cmip_AttributeId_vals), 0,
        NULL, HFILL }},
    { &hf_cmip_modificationList,
      { "modificationList", "cmip.modificationList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_modificationList_item,
      { "modificationList item", "cmip.modificationList_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_modificationList_item", HFILL }},
    { &hf_cmip_attributevalue,
      { "attributeValue", "cmip.attributeValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cmip_InvokeId_present,
      { "InvokeId.present", "cmip.InvokeId_present",
        FT_INT32, BASE_DEC, NULL, 0,
        "InvokeId_present", HFILL }},
    { &hf_cmip_FunctionalUnits_multipleObjectSelection,
      { "multipleObjectSelection", "cmip.FunctionalUnits.multipleObjectSelection",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_cmip_FunctionalUnits_filter,
      { "filter", "cmip.FunctionalUnits.filter",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_cmip_FunctionalUnits_multipleReply,
      { "multipleReply", "cmip.FunctionalUnits.multipleReply",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_cmip_FunctionalUnits_extendedService,
      { "extendedService", "cmip.FunctionalUnits.extendedService",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_cmip_FunctionalUnits_cancelGet,
      { "cancelGet", "cmip.FunctionalUnits.cancelGet",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_cmip_ProtocolVersion_version1,
      { "version1", "cmip.ProtocolVersion.version1",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_cmip_ProtocolVersion_version2,
      { "version2", "cmip.ProtocolVersion.version2",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_cmip_T_daysOfWeek_sunday,
      { "sunday", "cmip.T.daysOfWeek.sunday",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_cmip_T_daysOfWeek_monday,
      { "monday", "cmip.T.daysOfWeek.monday",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_cmip_T_daysOfWeek_tuesday,
      { "tuesday", "cmip.T.daysOfWeek.tuesday",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_cmip_T_daysOfWeek_wednesday,
      { "wednesday", "cmip.T.daysOfWeek.wednesday",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_cmip_T_daysOfWeek_thursday,
      { "thursday", "cmip.T.daysOfWeek.thursday",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_cmip_T_daysOfWeek_friday,
      { "friday", "cmip.T.daysOfWeek.friday",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_cmip_T_daysOfWeek_saturday,
      { "saturday", "cmip.T.daysOfWeek.saturday",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_cmip,
    &ett_cmip_PAR_missingAttributeValue,
    &ett_cmip_ActionArgument,
    &ett_cmip_ActionError,
    &ett_cmip_ActionErrorInfo,
    &ett_cmip_T_actionErrorInfo,
    &ett_cmip_ActionInfo,
    &ett_cmip_ActionReply,
    &ett_cmip_ActionResult,
    &ett_cmip_ActionTypeId,
    &ett_cmip_Attribute,
    &ett_cmip_AttributeError,
    &ett_cmip_AttributeId,
    &ett_cmip_AttributeIdError,
    &ett_cmip_AttributeValueAssertion,
    &ett_cmip_BaseManagedObjectId,
    &ett_cmip_CMISFilter,
    &ett_cmip_SET_OF_CMISFilter,
    &ett_cmip_ComplexityLimitation,
    &ett_cmip_CreateArgument,
    &ett_cmip_T_managedOrSuperiorObjectInstance,
    &ett_cmip_SET_OF_Attribute,
    &ett_cmip_CreateResult,
    &ett_cmip_DeleteArgument,
    &ett_cmip_DeleteError,
    &ett_cmip_DeleteResult,
    &ett_cmip_EventReply,
    &ett_cmip_EventReportArgument,
    &ett_cmip_EventReportResult,
    &ett_cmip_EventTypeId,
    &ett_cmip_FilterItem,
    &ett_cmip_T_substrings,
    &ett_cmip_T_substrings_item,
    &ett_cmip_GetArgument,
    &ett_cmip_GetInfoStatus,
    &ett_cmip_GetListError,
    &ett_cmip_SET_OF_GetInfoStatus,
    &ett_cmip_GetResult,
    &ett_cmip_InvalidArgumentValue,
    &ett_cmip_T_eventValue,
    &ett_cmip_LinkedReplyArgument,
    &ett_cmip_NoSuchAction,
    &ett_cmip_NoSuchArgument,
    &ett_cmip_T_actionId,
    &ett_cmip_T_eventId,
    &ett_cmip_NoSuchEventType,
    &ett_cmip_ObjectClass,
    &ett_cmip_ObjectInstance,
    &ett_cmip_ProcessingFailure,
    &ett_cmip_RDNSequence,
    &ett_cmip_RelativeDistinguishedName,
    &ett_cmip_Scope,
    &ett_cmip_SetArgument,
    &ett_cmip_SetInfoStatus,
    &ett_cmip_SetListError,
    &ett_cmip_SET_OF_SetInfoStatus,
    &ett_cmip_SetResult,
    &ett_cmip_SpecificErrorInfo,
    &ett_cmip_CMIPAbortInfo,
    &ett_cmip_FunctionalUnits,
    &ett_cmip_CMIPUserInfo,
    &ett_cmip_ProtocolVersion,
    &ett_cmip_AdditionalInformation,
    &ett_cmip_Allomorphs,
    &ett_cmip_AttributeIdentifierList,
    &ett_cmip_AttributeList,
    &ett_cmip_AttributeValueChangeDefinition,
    &ett_cmip_AttributeValueChangeDefinition_item,
    &ett_cmip_AlarmStatus,
    &ett_cmip_AvailabilityStatus,
    &ett_cmip_BackUpDestinationList,
    &ett_cmip_BackUpRelationshipObject,
    &ett_cmip_CapacityAlarmThreshold,
    &ett_cmip_ControlStatus,
    &ett_cmip_CorrelatedNotifications,
    &ett_cmip_CorrelatedNotifications_item,
    &ett_cmip_SET_OF_NotificationIdentifier,
    &ett_cmip_Destination,
    &ett_cmip_SET_OF_AE_title,
    &ett_cmip_GroupObjects,
    &ett_cmip_IntervalsOfDay,
    &ett_cmip_IntervalsOfDay_item,
    &ett_cmip_ManagementExtension,
    &ett_cmip_MonitoredAttributes,
    &ett_cmip_ObservedValue,
    &ett_cmip_Packages,
    &ett_cmip_PrioritisedObject,
    &ett_cmip_PrioritisedObject_item,
    &ett_cmip_ProbableCause,
    &ett_cmip_ProceduralStatus,
    &ett_cmip_ProposedRepairActions,
    &ett_cmip_SecurityAlarmDetector,
    &ett_cmip_ServiceUser,
    &ett_cmip_SimpleNameType,
    &ett_cmip_SpecificIdentifier,
    &ett_cmip_SpecificProblems,
    &ett_cmip_StopTime,
    &ett_cmip_SupportedFeatures,
    &ett_cmip_SupportedFeatures_item,
    &ett_cmip_SystemId,
    &ett_cmip_SystemTitle,
    &ett_cmip_Time24,
    &ett_cmip_ThresholdInfo,
    &ett_cmip_ThresholdLevelInd,
    &ett_cmip_T_up,
    &ett_cmip_T_down,
    &ett_cmip_WeekMask,
    &ett_cmip_WeekMask_item,
    &ett_cmip_T_daysOfWeek,
    &ett_cmip_Code,
    &ett_cmip_ROS,
    &ett_cmip_Invoke,
    &ett_cmip_T_linkedId,
    &ett_cmip_ReturnResult,
    &ett_cmip_T_result,
    &ett_cmip_ReturnError,
    &ett_cmip_Reject,
    &ett_cmip_T_problem,
    &ett_cmip_InvokeId,
    &ett_cmip_SET_OF_AttributeId,
    &ett_cmip_T_modificationList,
    &ett_cmip_T_modificationList_item,
  };

  static ei_register_info ei[] = {
     { &ei_wrong_spdu_type, { "cmip.wrong_spdu_type", PI_PROTOCOL, PI_ERROR, "Internal error: wrong spdu type", EXPFILL }},
  };

  expert_module_t* expert_cmip;

  /* Register protocol */
  proto_cmip = proto_register_protocol(PNAME, PSNAME, PFNAME);
  cmip_handle = register_dissector("cmip", dissect_cmip, proto_cmip);

  /* Register fields and subtrees */
  proto_register_field_array(proto_cmip, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_cmip = expert_register_protocol(proto_cmip);
  expert_register_field_array(expert_cmip, ei, array_length(ei));

  register_ber_oid_dissector("2.9.2.21.7.13", dissect_BaseManagedObjectId_PDU, proto_cmip, "BaseManagedObjectId(13)");
  register_ber_oid_dissector("2.9.3.2.7.1", dissect_SimpleNameType_PDU, proto_cmip, "discriminatorId(1)");
  register_ber_oid_dissector("2.9.3.2.7.2", dissect_SimpleNameType_PDU, proto_cmip, "logId(2)");
  register_ber_oid_dissector("2.9.3.2.7.3", dissect_LogRecordId_PDU, proto_cmip, "logRecordId(3)");
  register_ber_oid_dissector("2.9.3.2.7.4", dissect_SystemId_PDU, proto_cmip, "systemId(4)");
  register_ber_oid_dissector("2.9.3.2.7.5", dissect_SystemTitle_PDU, proto_cmip, "systemTitle(5)");
  register_ber_oid_dissector("2.9.3.2.7.6", dissect_AdditionalInformation_PDU, proto_cmip, "additionalInformation(6)");
  register_ber_oid_dissector("2.9.3.2.7.7", dissect_AdditionalText_PDU, proto_cmip, "additionalText(7)");
  register_ber_oid_dissector("2.9.3.2.7.8", dissect_AttributeIdentifierList_PDU, proto_cmip, "attributeIdentifierList(8)");
  register_ber_oid_dissector("2.9.3.2.7.9", dissect_AttributeList_PDU, proto_cmip, "attributeList(9)");
  register_ber_oid_dissector("2.9.3.2.7.10", dissect_AttributeValueChangeDefinition_PDU, proto_cmip, "attributeValueChangeDefinition(10)");
  register_ber_oid_dissector("2.9.3.2.7.11", dissect_BackedUpStatus_PDU, proto_cmip, "backedUpStatus(11)");
  register_ber_oid_dissector("2.9.3.2.7.12", dissect_CorrelatedNotifications_PDU, proto_cmip, "correlatedNotifications(12)");
  register_ber_oid_dissector("2.9.3.2.7.13", dissect_EventTime_PDU, proto_cmip, "eventTime(13)");
  register_ber_oid_dissector("2.9.3.2.7.14", dissect_EventTypeId_PDU, proto_cmip, "eventType(14)");
  register_ber_oid_dissector("2.9.3.2.7.15", dissect_MonitoredAttributes_PDU, proto_cmip, "monitoredAttributes(15)");
  register_ber_oid_dissector("2.9.3.2.7.16", dissect_NotificationIdentifier_PDU, proto_cmip, "notificationIdentifier(16)");
  register_ber_oid_dissector("2.9.3.2.7.17", dissect_PerceivedSeverity_PDU, proto_cmip, "perceivedSeverity(17)");
  register_ber_oid_dissector("2.9.3.2.7.18", dissect_ProbableCause_PDU, proto_cmip, "probableCause(18)");
  register_ber_oid_dissector("2.9.3.2.7.19", dissect_ProposedRepairActions_PDU, proto_cmip, "proposedRepairActions(19)");
  register_ber_oid_dissector("2.9.3.2.7.20", dissect_AttributeValueChangeDefinition_PDU, proto_cmip, "relationshipChangeDefinition(20)");
  register_ber_oid_dissector("2.9.3.2.7.21", dissect_SecurityAlarmCause_PDU, proto_cmip, "securityAlarmCause(21)");
  register_ber_oid_dissector("2.9.3.2.7.22", dissect_SecurityAlarmDetector_PDU, proto_cmip, "securityAlarmDetector(22)");
  register_ber_oid_dissector("2.9.3.2.7.23", dissect_SecurityAlarmSeverity_PDU, proto_cmip, "securityAlarmSeverity(23)");
  register_ber_oid_dissector("2.9.3.2.7.24", dissect_ServiceProvider_PDU, proto_cmip, "serviceProvider(24)");
  register_ber_oid_dissector("2.9.3.2.7.25", dissect_ServiceUser_PDU, proto_cmip, "serviceUser(25)");
  register_ber_oid_dissector("2.9.3.2.7.26", dissect_SourceIndicator_PDU, proto_cmip, "sourceIndicator(26)");
  register_ber_oid_dissector("2.9.3.2.7.27", dissect_SpecificProblems_PDU, proto_cmip, "specificProblems(27)");
  register_ber_oid_dissector("2.9.3.2.7.28", dissect_AttributeValueChangeDefinition_PDU, proto_cmip, "stateChangeDefinition(28)");
  register_ber_oid_dissector("2.9.3.2.7.29", dissect_ThresholdInfo_PDU, proto_cmip, "thresholdInfo(29)");
  register_ber_oid_dissector("2.9.3.2.7.30", dissect_TrendIndication_PDU, proto_cmip, "trendIndication(30)");
  register_ber_oid_dissector("2.9.3.2.7.31", dissect_AdministrativeState_PDU, proto_cmip, "administrativeState(31)");
  register_ber_oid_dissector("2.9.3.2.7.32", dissect_AlarmStatus_PDU, proto_cmip, "alarmStatus(32)");
  register_ber_oid_dissector("2.9.3.2.7.33", dissect_AvailabilityStatus_PDU, proto_cmip, "availabilityStatus(33)");
  register_ber_oid_dissector("2.9.3.2.7.34", dissect_ControlStatus_PDU, proto_cmip, "controlStatus(34)");
  register_ber_oid_dissector("2.9.3.2.7.35", dissect_OperationalState_PDU, proto_cmip, "operationalState(35)");
  register_ber_oid_dissector("2.9.3.2.7.36", dissect_ProceduralStatus_PDU, proto_cmip, "proceduralStatus(36)");
  register_ber_oid_dissector("2.9.3.2.7.37", dissect_StandbyStatus_PDU, proto_cmip, "standbyStatus(37)");
  register_ber_oid_dissector("2.9.3.2.7.38", dissect_UnknownStatus_PDU, proto_cmip, "unknownStatus(38)");
  register_ber_oid_dissector("2.9.3.2.7.39", dissect_UsageState_PDU, proto_cmip, "usageState(39)");
  register_ber_oid_dissector("2.9.3.2.7.40", dissect_BackUpRelationshipObject_PDU, proto_cmip, "backUpObject(40)");
  register_ber_oid_dissector("2.9.3.2.7.41", dissect_BackUpRelationshipObject_PDU, proto_cmip, "backedUpObject(41)");
  register_ber_oid_dissector("2.9.3.2.7.42", dissect_GroupObjects_PDU, proto_cmip, "member(42)");
  register_ber_oid_dissector("2.9.3.2.7.43", dissect_GroupObjects_PDU, proto_cmip, "owner(43)");
  register_ber_oid_dissector("2.9.3.2.7.44", dissect_BackUpRelationshipObject_PDU, proto_cmip, "peer(44)");
  register_ber_oid_dissector("2.9.3.2.7.45", dissect_PrioritisedObject_PDU, proto_cmip, "primary(45)");
  register_ber_oid_dissector("2.9.3.2.7.46", dissect_PrioritisedObject_PDU, proto_cmip, "providerObject(46)");
  register_ber_oid_dissector("2.9.3.2.7.47", dissect_PrioritisedObject_PDU, proto_cmip, "secondary(47)");
  register_ber_oid_dissector("2.9.3.2.7.48", dissect_PrioritisedObject_PDU, proto_cmip, "userObject(48)");
  register_ber_oid_dissector("2.9.3.2.7.49", dissect_ActiveDestination_PDU, proto_cmip, "activeDestination(49)");
  register_ber_oid_dissector("2.9.3.2.7.50", dissect_Allomorphs_PDU, proto_cmip, "allomorphs(50)");
  register_ber_oid_dissector("2.9.3.2.7.51", dissect_BackUpDestinationList_PDU, proto_cmip, "backUpDestinationList(51)");
  register_ber_oid_dissector("2.9.3.2.7.52", dissect_CapacityAlarmThreshold_PDU, proto_cmip, "capacityAlarmThreshold(52)");
  register_ber_oid_dissector("2.9.3.2.7.53", dissect_ConfirmedMode_PDU, proto_cmip, "confirmedMode(53)");
  register_ber_oid_dissector("2.9.3.2.7.54", dissect_CurrentLogSize_PDU, proto_cmip, "currentLogSize(54)");
  register_ber_oid_dissector("2.9.3.2.7.55", dissect_Destination_PDU, proto_cmip, "destination(55)");
  register_ber_oid_dissector("2.9.3.2.7.56", dissect_DiscriminatorConstruct_PDU, proto_cmip, "discriminatorConstruct(56)");
  register_ber_oid_dissector("2.9.3.2.7.57", dissect_IntervalsOfDay_PDU, proto_cmip, "intervalsOfDay(57)");
  register_ber_oid_dissector("2.9.3.2.7.58", dissect_LogFullAction_PDU, proto_cmip, "logFullAction(58)");
  register_ber_oid_dissector("2.9.3.2.7.59", dissect_LoggingTime_PDU, proto_cmip, "loggingTime(59)");
  register_ber_oid_dissector("2.9.3.2.7.62", dissect_MaxLogSize_PDU, proto_cmip, "maxLogSize(62)");
  register_ber_oid_dissector("2.9.3.2.7.63", dissect_NameBinding_PDU, proto_cmip, "nameBinding(63)");
  register_ber_oid_dissector("2.9.3.2.7.64", dissect_NumberOfRecords_PDU, proto_cmip, "numberOfRecords(64)");
  register_ber_oid_dissector("2.9.3.2.7.65", dissect_ObjectClass_PDU, proto_cmip, "objectClass(65)");
  register_ber_oid_dissector("2.9.3.2.7.66", dissect_Packages_PDU, proto_cmip, "packages(66)");
  register_ber_oid_dissector("2.9.3.2.7.68", dissect_StartTime_PDU, proto_cmip, "startTime(68)");
  register_ber_oid_dissector("2.9.3.2.7.69", dissect_StopTime_PDU, proto_cmip, "stopTime(69)");
  register_ber_oid_dissector("2.9.3.2.7.70", dissect_SupportedFeatures_PDU, proto_cmip, "supportedFeatures(70)");
  register_ber_oid_dissector("2.9.3.2.7.71", dissect_WeekMask_PDU, proto_cmip, "weekMask(71)");
  register_ber_oid_dissector("2.9.3.2.7.115", dissect_LifecycleState_PDU, proto_cmip, "lifecycleState(115)");

    oid_add_from_string("discriminatorId(1)","2.9.3.2.7.1");

  attribute_id_dissector_table = register_dissector_table("cmip.attribute_id", "CMIP Attribute Id", proto_cmip, FT_UINT32, BASE_DEC);

}


/*--- proto_reg_handoff_cmip -------------------------------------------*/
void proto_reg_handoff_cmip(void) {
	register_ber_oid_dissector_handle("2.9.0.0.2", cmip_handle, proto_cmip, "cmip");
	register_ber_oid_dissector_handle("2.9.1.1.4", cmip_handle, proto_cmip, "joint-iso-itu-t(2) ms(9) cmip(1) cmip-pci(1) abstractSyntax(4)");

	oid_add_from_string("2.9.3.2.3.1","managedObjectClass(3) alarmRecord(1)");
	oid_add_from_string("2.9.3.2.3.2","managedObjectClass(3) attributeValueChangeRecord(2)");
	oid_add_from_string("2.9.3.2.3.3","managedObjectClass(3) discriminator(3)");
	oid_add_from_string("2.9.3.2.3.4","managedObjectClass(3) eventForwardingDiscriminator(4)");
	oid_add_from_string("2.9.3.2.3.5","managedObjectClass(3) eventLogRecord(5)");
	oid_add_from_string("2.9.3.2.3.6","managedObjectClass(3) log(6)");
	oid_add_from_string("2.9.3.2.3.7","managedObjectClass(3) logRecord(7)");
	oid_add_from_string("2.9.3.2.3.8","managedObjectClass(3) objectCreationRecord(8)");
	oid_add_from_string("2.9.3.2.3.9","managedObjectClass(3) objectDeletionRecord(9)");
	oid_add_from_string("2.9.3.2.3.10","managedObjectClass(3) relationshipChangeRecord(10)");
	oid_add_from_string("2.9.3.2.3.11","managedObjectClass(3) securityAlarmReportRecord(11)");
	oid_add_from_string("2.9.3.2.3.12","managedObjectClass(3) stateChangeRecord(12)");
	oid_add_from_string("2.9.3.2.3.13","managedObjectClass(3) system(13)");
	oid_add_from_string("2.9.3.2.3.14","managedObjectClass(3) top(14)");
	oid_add_from_string("2.9.3.2.4.14","administrativeStatePackage(14)");
	oid_add_from_string("2.9.1.1.4","joint-iso-itu-t(2) ms(9) cmip(1) cmip-pci(1) abstractSyntax(4)");

/*#include "packet-cmip-dis-tab.c" */
}

