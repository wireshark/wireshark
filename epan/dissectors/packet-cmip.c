/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* .\packet-cmip.c                                                            */
/* ../../tools/asn2wrs.py -b -X -T -e -p cmip -c cmip.cnf -s packet-cmip-template CMIP-1.asn CMIP-A-ABORT-Information.asn CMIP-A-ASSOCIATE-Information.asn ../x721/Attribute-ASN1Module.asn ../ros/Remote-Operations-Information-Objects.asn ../ros/Remote-Operations-Generic-ROS-PDUs.asn */

/* Input file: packet-cmip-template.c */

#line 1 "packet-cmip-template.c"
/* packet-cmip.c
 * Routines for X.711 CMIP packet dissection
 *   Ronnie Sahlberg 2004
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
#include <epan/oid_resolv.h>
#include <epan/asn1.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-acse.h"
#include "packet-x509if.h"
#include "packet-cmip.h"

#define PNAME  "X711 CMIP"
#define PSNAME "CMIP"
#define PFNAME "cmip"

/* XXX some stuff we need until we can get rid of it */
#include "packet-ses.h"
#include "packet-pres.h"

/* Initialize the protocol and registered fields */
int proto_cmip = -1;
static int hf_cmip_actionType_OID = -1;
static int hf_cmip_eventType_OID = -1;
static int hf_cmip_attributeId_OID = -1;
static int hf_cmip_errorId_OID = -1;
static int hf_DiscriminatorConstruct = -1;
static int hf_Destination = -1;
static int hf_NameBinding = -1;
static int hf_ObjectClass = -1;

/*--- Included file: packet-cmip-hf.c ---*/
#line 1 "packet-cmip-hf.c"
static int hf_cmip_ObjectClass_PDU = -1;          /* ObjectClass */
static int hf_cmip_AdditionalText_PDU = -1;       /* AdditionalText */
static int hf_cmip_Allomorphs_PDU = -1;           /* Allomorphs */
static int hf_cmip_BackedUpStatus_PDU = -1;       /* BackedUpStatus */
static int hf_cmip_Destination_PDU = -1;          /* Destination */
static int hf_cmip_DiscriminatorConstruct_PDU = -1;  /* DiscriminatorConstruct */
static int hf_cmip_LogRecordId_PDU = -1;          /* LogRecordId */
static int hf_cmip_NameBinding_PDU = -1;          /* NameBinding */
static int hf_cmip_OperationalState_PDU = -1;     /* OperationalState */
static int hf_cmip_SystemId_PDU = -1;             /* SystemId */
static int hf_cmip_SystemTitle_PDU = -1;          /* SystemTitle */
static int hf_cmip_UsageState_PDU = -1;           /* UsageState */
static int hf_cmip_managedObjectClass = -1;       /* ObjectClass */
static int hf_cmip_managedObjectInstance = -1;    /* ObjectInstance */
static int hf_cmip_currentTime = -1;              /* GeneralizedTime */
static int hf_cmip_actionErrorInfo = -1;          /* ActionErrorInfo */
static int hf_cmip_errorStatus = -1;              /* T_errorStatus */
static int hf_cmip_errorInfo = -1;                /* T_errorInfo */
static int hf_cmip_actionType = -1;               /* ActionTypeId */
static int hf_cmip_actionArgument = -1;           /* NoSuchArgument */
static int hf_cmip_argumentValue = -1;            /* InvalidArgumentValue */
static int hf_cmip_actionInfoArg = -1;            /* T_actionInfoArg */
static int hf_cmip_actionReplyInfo = -1;          /* T_actionReplyInfo */
static int hf_cmip_actionReply = -1;              /* ActionReply */
static int hf_cmip_globalForm = -1;               /* T_globalForm */
static int hf_cmip_localForm = -1;                /* INTEGER */
static int hf_cmip_id = -1;                       /* AttributeId */
static int hf_cmip_value = -1;                    /* T_value */
static int hf_cmip_errorStatus_01 = -1;           /* T_errorStatus_01 */
static int hf_cmip_modifyOperator = -1;           /* ModifyOperator */
static int hf_cmip_attributeId = -1;              /* AttributeId */
static int hf_cmip_attributeValue = -1;           /* T_attributeValue */
static int hf_cmip_globalForm_01 = -1;            /* T_globalForm_01 */
static int hf_cmip_localForm_01 = -1;             /* T_localForm */
static int hf_cmip_errorStatus_02 = -1;           /* T_errorStatus_02 */
static int hf_cmip_id_01 = -1;                    /* T_id */
static int hf_cmip_value_01 = -1;                 /* T_value_01 */
static int hf_cmip_baseManagedObjectClass = -1;   /* ObjectClass */
static int hf_cmip_baseManagedObjectInstance = -1;  /* ObjectInstance */
static int hf_cmip_item = -1;                     /* FilterItem */
static int hf_cmip_and = -1;                      /* SET_OF_CMISFilter */
static int hf_cmip_and_item = -1;                 /* CMISFilter */
static int hf_cmip_or = -1;                       /* SET_OF_CMISFilter */
static int hf_cmip_or_item = -1;                  /* CMISFilter */
static int hf_cmip_not = -1;                      /* CMISFilter */
static int hf_cmip_scope = -1;                    /* Scope */
static int hf_cmip_filter = -1;                   /* CMISFilter */
static int hf_cmip_sync = -1;                     /* CMISSync */
static int hf_cmip_managedOrSuperiorObjectInstance = -1;  /* T_managedOrSuperiorObjectInstance */
static int hf_cmip_superiorObjectInstance = -1;   /* ObjectInstance */
static int hf_cmip_accessControl = -1;            /* AccessControl */
static int hf_cmip_referenceObjectInstance = -1;  /* ObjectInstance */
static int hf_cmip_attributeList = -1;            /* SET_OF_Attribute */
static int hf_cmip_attributeList_item = -1;       /* Attribute */
static int hf_cmip_deleteErrorInfo = -1;          /* T_deleteErrorInfo */
static int hf_cmip_eventType = -1;                /* EventTypeId */
static int hf_cmip_eventReplyInfo = -1;           /* T_eventReplyInfo */
static int hf_cmip_eventTime = -1;                /* GeneralizedTime */
static int hf_cmip_eventInfo = -1;                /* T_eventInfo */
static int hf_cmip_eventReply = -1;               /* EventReply */
static int hf_cmip_globalForm_02 = -1;            /* T_globalForm_02 */
static int hf_cmip_equality = -1;                 /* Attribute */
static int hf_cmip_substrings = -1;               /* T_substrings */
static int hf_cmip_substrings_item = -1;          /* T_substrings_item */
static int hf_cmip_initialString = -1;            /* Attribute */
static int hf_cmip_anyString = -1;                /* Attribute */
static int hf_cmip_finalString = -1;              /* Attribute */
static int hf_cmip_greaterOrEqual = -1;           /* Attribute */
static int hf_cmip_lessOrEqual = -1;              /* Attribute */
static int hf_cmip_present = -1;                  /* AttributeId */
static int hf_cmip_subsetOf = -1;                 /* Attribute */
static int hf_cmip_supersetOf = -1;               /* Attribute */
static int hf_cmip_nonNullSetIntersection = -1;   /* Attribute */
static int hf_cmip_attributeIdError = -1;         /* AttributeIdError */
static int hf_cmip_attribute = -1;                /* Attribute */
static int hf_cmip_getInfoList = -1;              /* SET_OF_GetInfoStatus */
static int hf_cmip_getInfoList_item = -1;         /* GetInfoStatus */
static int hf_cmip_actionValue = -1;              /* ActionInfo */
static int hf_cmip_eventValue = -1;               /* T_eventValue */
static int hf_cmip_eventInfo_01 = -1;             /* T_eventInfo_01 */
static int hf_cmip_getResult = -1;                /* GetResult */
static int hf_cmip_getListError = -1;             /* GetListError */
static int hf_cmip_setResult = -1;                /* SetResult */
static int hf_cmip_setListError = -1;             /* SetListError */
static int hf_cmip_actionResult = -1;             /* ActionResult */
static int hf_cmip_processingFailure = -1;        /* ProcessingFailure */
static int hf_cmip_deleteResult = -1;             /* DeleteResult */
static int hf_cmip_actionError = -1;              /* ActionError */
static int hf_cmip_deleteError = -1;              /* DeleteError */
static int hf_cmip_actionId = -1;                 /* T_actionId */
static int hf_cmip_eventId = -1;                  /* T_eventId */
static int hf_cmip_globalForm_03 = -1;            /* T_globalForm_03 */
static int hf_cmip_localForm_02 = -1;             /* T_localForm_01 */
static int hf_cmip_distinguishedName = -1;        /* DistinguishedName */
static int hf_cmip_nonSpecificForm = -1;          /* OCTET_STRING */
static int hf_cmip_localDistinguishedName = -1;   /* RDNSequence */
static int hf_cmip_specificErrorInfo = -1;        /* SpecificErrorInfo */
static int hf_cmip_RDNSequence_item = -1;         /* RelativeDistinguishedName */
static int hf_cmip_RelativeDistinguishedName_item = -1;  /* AttributeValueAssertion */
static int hf_cmip_namedNumbers = -1;             /* T_namedNumbers */
static int hf_cmip_individualLevels = -1;         /* INTEGER */
static int hf_cmip_baseToNthLevel = -1;           /* INTEGER */
static int hf_cmip_attributeError = -1;           /* AttributeError */
static int hf_cmip_setInfoList = -1;              /* SET_OF_SetInfoStatus */
static int hf_cmip_setInfoList_item = -1;         /* SetInfoStatus */
static int hf_cmip_errorId = -1;                  /* T_errorId */
static int hf_cmip_errorInfo_01 = -1;             /* T_errorInfo_01 */
static int hf_cmip_abortSource = -1;              /* CMIPAbortSource */
static int hf_cmip_userInfo = -1;                 /* EXTERNAL */
static int hf_cmip_protocolVersion = -1;          /* ProtocolVersion */
static int hf_cmip_functionalUnits = -1;          /* FunctionalUnits */
static int hf_cmip_accessControl_01 = -1;         /* EXTERNAL */
static int hf_cmip_AdditionalInformation_item = -1;  /* ManagementExtension */
static int hf_cmip_Allomorphs_item = -1;          /* ObjectClass */
static int hf_cmip_AttributeIdentifierList_item = -1;  /* AttributeId */
static int hf_cmip_AttributeList_item = -1;       /* Attribute */
static int hf_cmip_AttributeValueChangeDefinition_item = -1;  /* AttributeValueChangeDefinition_item */
static int hf_cmip_oldAttributeValue = -1;        /* T_oldAttributeValue */
static int hf_cmip_newAttributeValue = -1;        /* T_newAttributeValue */
static int hf_cmip_AlarmStatus_item = -1;         /* AlarmStatus_item */
static int hf_cmip_AvailabilityStatus_item = -1;  /* AvailabilityStatus_item */
static int hf_cmip_BackUpDestinationList_item = -1;  /* AE_title */
static int hf_cmip_objectName = -1;               /* ObjectInstance */
static int hf_cmip_noObject = -1;                 /* NULL */
static int hf_cmip_CapacityAlarmThreshold_item = -1;  /* INTEGER_0_100 */
static int hf_cmip_ControlStatus_item = -1;       /* ControlStatus_item */
static int hf_cmip_CounterThreshold_item = -1;    /* CounterThreshold_item */
static int hf_cmip_comparisonLevel = -1;          /* INTEGER */
static int hf_cmip_offsetValue = -1;              /* INTEGER */
static int hf_cmip_notificationOnOff = -1;        /* BOOLEAN */
static int hf_cmip_CorrelatedNotifications_item = -1;  /* CorrelatedNotifications_item */
static int hf_cmip_correlatedNotifications = -1;  /* SET_OF_NotificationIdentifier */
static int hf_cmip_correlatedNotifications_item = -1;  /* NotificationIdentifier */
static int hf_cmip_sourceObjectInst = -1;         /* ObjectInstance */
static int hf_cmip_single = -1;                   /* AE_title */
static int hf_cmip_multiple = -1;                 /* SET_OF_AE_title */
static int hf_cmip_multiple_item = -1;            /* AE_title */
static int hf_cmip_GaugeThreshold_item = -1;      /* GaugeThreshold_item */
static int hf_cmip_notifyLow = -1;                /* NotifyThreshold */
static int hf_cmip_notifyHigh = -1;               /* NotifyThreshold */
static int hf_cmip_GroupObjects_item = -1;        /* ObjectInstance */
static int hf_cmip_IntervalsOfDay_item = -1;      /* IntervalsOfDay_item */
static int hf_cmip_intervalStart = -1;            /* Time24 */
static int hf_cmip_intervalEnd = -1;              /* Time24 */
static int hf_cmip_identifier = -1;               /* T_identifier */
static int hf_cmip_significance = -1;             /* BOOLEAN */
static int hf_cmip_information = -1;              /* T_information */
static int hf_cmip_MonitoredAttributes_item = -1;  /* Attribute */
static int hf_cmip_threshold = -1;                /* ObservedValue */
static int hf_cmip_notifyOnOff = -1;              /* BOOLEAN */
static int hf_cmip_integer = -1;                  /* INTEGER */
static int hf_cmip_real = -1;                     /* REAL */
static int hf_cmip_Packages_item = -1;            /* OBJECT_IDENTIFIER */
static int hf_cmip_PrioritisedObject_item = -1;   /* PrioritisedObject_item */
static int hf_cmip_object = -1;                   /* ObjectInstance */
static int hf_cmip_priority = -1;                 /* T_priority */
static int hf_cmip_globalValue = -1;              /* OBJECT_IDENTIFIER */
static int hf_cmip_localValue = -1;               /* INTEGER */
static int hf_cmip_ProceduralStatus_item = -1;    /* ProceduralStatus_item */
static int hf_cmip_ProposedRepairActions_item = -1;  /* SpecificIdentifier */
static int hf_cmip_mechanism = -1;                /* OBJECT_IDENTIFIER */
static int hf_cmip_application = -1;              /* AE_title */
static int hf_cmip_identifier_01 = -1;            /* T_identifier_01 */
static int hf_cmip_details = -1;                  /* T_details */
static int hf_cmip_number = -1;                   /* INTEGER */
static int hf_cmip_string = -1;                   /* GraphicString */
static int hf_cmip_oi = -1;                       /* OBJECT_IDENTIFIER */
static int hf_cmip_int = -1;                      /* INTEGER */
static int hf_cmip_SpecificProblems_item = -1;    /* SpecificIdentifier */
static int hf_cmip_specific = -1;                 /* GeneralizedTime */
static int hf_cmip_continual = -1;                /* NULL */
static int hf_cmip_SupportedFeatures_item = -1;   /* SupportedFeatures_item */
static int hf_cmip_featureIdentifier = -1;        /* T_featureIdentifier */
static int hf_cmip_featureInfo = -1;              /* T_featureInfo */
static int hf_cmip_name = -1;                     /* GraphicString */
static int hf_cmip_nothing = -1;                  /* NULL */
static int hf_cmip_oid = -1;                      /* OBJECT_IDENTIFIER */
static int hf_cmip_currentTideMark = -1;          /* TideMark */
static int hf_cmip_previousTideMark = -1;         /* TideMark */
static int hf_cmip_resetTime = -1;                /* GeneralizedTime */
static int hf_cmip_maxTideMar = -1;               /* ObservedValue */
static int hf_cmip_minTideMark = -1;              /* ObservedValue */
static int hf_cmip_hour = -1;                     /* INTEGER_0_23 */
static int hf_cmip_minute = -1;                   /* INTEGER_0_59 */
static int hf_cmip_triggeredThreshold = -1;       /* AttributeId */
static int hf_cmip_observedValue = -1;            /* ObservedValue */
static int hf_cmip_thresholdLevel = -1;           /* ThresholdLevelInd */
static int hf_cmip_armTime = -1;                  /* GeneralizedTime */
static int hf_cmip_up = -1;                       /* T_up */
static int hf_cmip_high = -1;                     /* ObservedValue */
static int hf_cmip_low = -1;                      /* ObservedValue */
static int hf_cmip_down = -1;                     /* T_down */
static int hf_cmip_WeekMask_item = -1;            /* WeekMask_item */
static int hf_cmip_daysOfWeek = -1;               /* T_daysOfWeek */
static int hf_cmip_intervalsOfDay = -1;           /* IntervalsOfDay */
static int hf_cmip_local = -1;                    /* T_local */
static int hf_cmip_global = -1;                   /* OBJECT_IDENTIFIER */
static int hf_cmip_invoke = -1;                   /* Invoke */
static int hf_cmip_returnResult = -1;             /* ReturnResult */
static int hf_cmip_returnError = -1;              /* ReturnError */
static int hf_cmip_reject = -1;                   /* Reject */
static int hf_cmip_invokeId = -1;                 /* InvokeId */
static int hf_cmip_linkedId = -1;                 /* T_linkedId */
static int hf_cmip_linkedIdPresent = -1;          /* T_linkedIdPresent */
static int hf_cmip_absent = -1;                   /* NULL */
static int hf_cmip_opcode = -1;                   /* Code */
static int hf_cmip_argument = -1;                 /* InvokeArgument */
static int hf_cmip_result = -1;                   /* T_result */
static int hf_cmip_resultArgument = -1;           /* ResultArgument */
static int hf_cmip_errcode = -1;                  /* Code */
static int hf_cmip_parameter = -1;                /* T_parameter */
static int hf_cmip_problem = -1;                  /* T_problem */
static int hf_cmip_general = -1;                  /* GeneralProblem */
static int hf_cmip_invokeProblem = -1;            /* InvokeProblem */
static int hf_cmip_returnResultProblem = -1;      /* ReturnResultProblem */
static int hf_cmip_returnErrorProblem = -1;       /* ReturnErrorProblem */
static int hf_cmip_present_01 = -1;               /* INTEGER */
static int hf_cmip_synchronization = -1;          /* CMISSync */
static int hf_cmip_actionInfo = -1;               /* ActionInfo */
static int hf_cmip_attributeIdList = -1;          /* SET_OF_AttributeId */
static int hf_cmip_attributeIdList_item = -1;     /* AttributeId */
static int hf_cmip_modificationList = -1;         /* T_modificationList */
static int hf_cmip_modificationList_item = -1;    /* T_modificationList_item */
static int hf_cmip_attributevalue = -1;           /* T_attributevalue */
static int hf_cmip_InvokeId_present = -1;         /* InvokeId_present */
/* named bits */
static int hf_cmip_FunctionalUnits_multipleObjectSelection = -1;
static int hf_cmip_FunctionalUnits_filter = -1;
static int hf_cmip_FunctionalUnits_multipleReply = -1;
static int hf_cmip_FunctionalUnits_extendedService = -1;
static int hf_cmip_FunctionalUnits_cancelGet = -1;
static int hf_cmip_ProtocolVersion_version1 = -1;
static int hf_cmip_ProtocolVersion_version2 = -1;
static int hf_cmip_T_daysOfWeek_sunday = -1;
static int hf_cmip_T_daysOfWeek_monday = -1;
static int hf_cmip_T_daysOfWeek_tuesday = -1;
static int hf_cmip_T_daysOfWeek_wednesday = -1;
static int hf_cmip_T_daysOfWeek_thursday = -1;
static int hf_cmip_T_daysOfWeek_friday = -1;
static int hf_cmip_T_daysOfWeek_saturday = -1;

/*--- End of included file: packet-cmip-hf.c ---*/
#line 63 "packet-cmip-template.c"

/* Initialize the subtree pointers */
static gint ett_cmip = -1;

/*--- Included file: packet-cmip-ett.c ---*/
#line 1 "packet-cmip-ett.c"
static gint ett_cmip_ActionArgument = -1;
static gint ett_cmip_ActionError = -1;
static gint ett_cmip_ActionErrorInfo = -1;
static gint ett_cmip_T_errorInfo = -1;
static gint ett_cmip_ActionInfo = -1;
static gint ett_cmip_ActionReply = -1;
static gint ett_cmip_ActionResult = -1;
static gint ett_cmip_ActionTypeId = -1;
static gint ett_cmip_Attribute = -1;
static gint ett_cmip_AttributeError = -1;
static gint ett_cmip_AttributeId = -1;
static gint ett_cmip_AttributeIdError = -1;
static gint ett_cmip_AttributeValueAssertion = -1;
static gint ett_cmip_BaseManagedObjectId = -1;
static gint ett_cmip_CMISFilter = -1;
static gint ett_cmip_SET_OF_CMISFilter = -1;
static gint ett_cmip_ComplexityLimitation = -1;
static gint ett_cmip_CreateArgument = -1;
static gint ett_cmip_T_managedOrSuperiorObjectInstance = -1;
static gint ett_cmip_SET_OF_Attribute = -1;
static gint ett_cmip_CreateResult = -1;
static gint ett_cmip_DeleteArgument = -1;
static gint ett_cmip_DeleteError = -1;
static gint ett_cmip_DeleteResult = -1;
static gint ett_cmip_EventReply = -1;
static gint ett_cmip_EventReportArgument = -1;
static gint ett_cmip_EventReportResult = -1;
static gint ett_cmip_EventTypeId = -1;
static gint ett_cmip_FilterItem = -1;
static gint ett_cmip_T_substrings = -1;
static gint ett_cmip_T_substrings_item = -1;
static gint ett_cmip_GetArgument = -1;
static gint ett_cmip_GetInfoStatus = -1;
static gint ett_cmip_GetListError = -1;
static gint ett_cmip_SET_OF_GetInfoStatus = -1;
static gint ett_cmip_GetResult = -1;
static gint ett_cmip_InvalidArgumentValue = -1;
static gint ett_cmip_T_eventValue = -1;
static gint ett_cmip_LinkedReplyArgument = -1;
static gint ett_cmip_NoSuchAction = -1;
static gint ett_cmip_NoSuchArgument = -1;
static gint ett_cmip_T_actionId = -1;
static gint ett_cmip_T_eventId = -1;
static gint ett_cmip_NoSuchEventType = -1;
static gint ett_cmip_ObjectClass = -1;
static gint ett_cmip_ObjectInstance = -1;
static gint ett_cmip_ProcessingFailure = -1;
static gint ett_cmip_RDNSequence = -1;
static gint ett_cmip_RelativeDistinguishedName = -1;
static gint ett_cmip_Scope = -1;
static gint ett_cmip_SetArgument = -1;
static gint ett_cmip_SetInfoStatus = -1;
static gint ett_cmip_SetListError = -1;
static gint ett_cmip_SET_OF_SetInfoStatus = -1;
static gint ett_cmip_SetResult = -1;
static gint ett_cmip_SpecificErrorInfo = -1;
static gint ett_cmip_CMIPAbortInfo = -1;
static gint ett_cmip_FunctionalUnits = -1;
static gint ett_cmip_CMIPUserInfo = -1;
static gint ett_cmip_ProtocolVersion = -1;
static gint ett_cmip_AdditionalInformation = -1;
static gint ett_cmip_Allomorphs = -1;
static gint ett_cmip_AttributeIdentifierList = -1;
static gint ett_cmip_AttributeList = -1;
static gint ett_cmip_AttributeValueChangeDefinition = -1;
static gint ett_cmip_AttributeValueChangeDefinition_item = -1;
static gint ett_cmip_AlarmStatus = -1;
static gint ett_cmip_AvailabilityStatus = -1;
static gint ett_cmip_BackUpDestinationList = -1;
static gint ett_cmip_BackUpRelationshipObject = -1;
static gint ett_cmip_CapacityAlarmThreshold = -1;
static gint ett_cmip_ControlStatus = -1;
static gint ett_cmip_CounterThreshold = -1;
static gint ett_cmip_CounterThreshold_item = -1;
static gint ett_cmip_CorrelatedNotifications = -1;
static gint ett_cmip_CorrelatedNotifications_item = -1;
static gint ett_cmip_SET_OF_NotificationIdentifier = -1;
static gint ett_cmip_Destination = -1;
static gint ett_cmip_SET_OF_AE_title = -1;
static gint ett_cmip_GaugeThreshold = -1;
static gint ett_cmip_GaugeThreshold_item = -1;
static gint ett_cmip_GroupObjects = -1;
static gint ett_cmip_IntervalsOfDay = -1;
static gint ett_cmip_IntervalsOfDay_item = -1;
static gint ett_cmip_ManagementExtension = -1;
static gint ett_cmip_MonitoredAttributes = -1;
static gint ett_cmip_NotifyThreshold = -1;
static gint ett_cmip_ObservedValue = -1;
static gint ett_cmip_Packages = -1;
static gint ett_cmip_PrioritisedObject = -1;
static gint ett_cmip_PrioritisedObject_item = -1;
static gint ett_cmip_ProbableCause = -1;
static gint ett_cmip_ProceduralStatus = -1;
static gint ett_cmip_ProposedRepairActions = -1;
static gint ett_cmip_SecurityAlarmDetector = -1;
static gint ett_cmip_ServiceUser = -1;
static gint ett_cmip_SimpleNameType = -1;
static gint ett_cmip_SpecificIdentifier = -1;
static gint ett_cmip_SpecificProblems = -1;
static gint ett_cmip_StopTime = -1;
static gint ett_cmip_SupportedFeatures = -1;
static gint ett_cmip_SupportedFeatures_item = -1;
static gint ett_cmip_SystemId = -1;
static gint ett_cmip_SystemTitle = -1;
static gint ett_cmip_TideMarkInfo = -1;
static gint ett_cmip_TideMark = -1;
static gint ett_cmip_Time24 = -1;
static gint ett_cmip_ThresholdInfo = -1;
static gint ett_cmip_ThresholdLevelInd = -1;
static gint ett_cmip_T_up = -1;
static gint ett_cmip_T_down = -1;
static gint ett_cmip_WeekMask = -1;
static gint ett_cmip_WeekMask_item = -1;
static gint ett_cmip_T_daysOfWeek = -1;
static gint ett_cmip_Code = -1;
static gint ett_cmip_ROS = -1;
static gint ett_cmip_Invoke = -1;
static gint ett_cmip_T_linkedId = -1;
static gint ett_cmip_ReturnResult = -1;
static gint ett_cmip_T_result = -1;
static gint ett_cmip_ReturnError = -1;
static gint ett_cmip_Reject = -1;
static gint ett_cmip_T_problem = -1;
static gint ett_cmip_InvokeId = -1;
static gint ett_cmip_SET_OF_AttributeId = -1;
static gint ett_cmip_T_modificationList = -1;
static gint ett_cmip_T_modificationList_item = -1;

/*--- End of included file: packet-cmip-ett.c ---*/
#line 67 "packet-cmip-template.c"

static guint32 opcode;

static const value_string cmip_Opcode_vals[] = {
  {   0, "m-EventReport" },
  {   1, "m-EventReport-Confirmed" },
  {   2, "m-Linked-Reply" },
  {   3, "m-Get" },
  {   4, "m-Set" },
  {   5, "m-Set-Confirmed" },
  {   6, "m-Action" },
  {   7, "m-Action-Confirmed" },
  {   8, "m-Create" },
  {   9, "m-Delete" },
  {  10, "m-CancelGet" },
  { 0, NULL }
};

static int opcode_type;
#define OPCODE_INVOKE        1
#define OPCODE_RETURN_RESULT 2
#define OPCODE_RETURN_ERROR  3
#define OPCODE_REJECT        4

static int attributeform;
#define ATTRIBUTE_LOCAL_FORM  0
#define ATTRIBUTE_GLOBAL_FORM 1
static const char *attribute_identifier_id;

static const char *attributevalueassertion_id;

static const char *object_identifier_id;

static int objectclassform;
#define OBJECTCLASS_LOCAL_FORM  0
#define OBJECTCLASS_GLOBAL_FORM 1
static const char *objectclass_identifier_id;


/*--- Included file: packet-cmip-val.h ---*/
#line 1 "packet-cmip-val.h"
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

/*--- End of included file: packet-cmip-val.h ---*/
#line 106 "packet-cmip-template.c"

/*--- Included file: packet-cmip-fn.c ---*/
#line 1 "packet-cmip-fn.c"
/*--- Cyclic dependencies ---*/

/* CMISFilter -> CMISFilter/and -> CMISFilter */
/* CMISFilter -> CMISFilter */
static int dissect_cmip_CMISFilter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);




static int
dissect_cmip_AccessControl(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_external_type(implicit_tag, tree, tvb, offset, actx, hf_index, NULL);

  return offset;
}



static int
dissect_cmip_T_globalForm_03(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 227 "cmip.cnf"
  objectclassform = OBJECTCLASS_GLOBAL_FORM;

  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &objectclass_identifier_id);

  return offset;
}



static int
dissect_cmip_T_localForm_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 232 "cmip.cnf"
  objectclassform = OBJECTCLASS_LOCAL_FORM;


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
  {   0, &hf_cmip_globalForm_03  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_cmip_T_globalForm_03 },
  {   1, &hf_cmip_localForm_02   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_cmip_T_localForm_01 },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_cmip_ObjectClass(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ObjectClass_choice, hf_index, ett_cmip_ObjectClass,
                                 NULL);

  return offset;
}



static int
dissect_cmip_T_id(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &attributevalueassertion_id);

  return offset;
}



static int
dissect_cmip_T_value_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 149 "cmip.cnf"
    offset=call_ber_oid_callback(attributevalueassertion_id, tvb, offset, actx->pinfo, tree);



  return offset;
}


static const ber_sequence_t AttributeValueAssertion_sequence[] = {
  { &hf_cmip_id_01          , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cmip_T_id },
  { &hf_cmip_value_01       , BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_cmip_T_value_01 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_AttributeValueAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttributeValueAssertion_sequence, hf_index, ett_cmip_AttributeValueAssertion);

  return offset;
}


static const ber_sequence_t RelativeDistinguishedName_set_of[1] = {
  { &hf_cmip_RelativeDistinguishedName_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmip_AttributeValueAssertion },
};

static int
dissect_cmip_RelativeDistinguishedName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 RelativeDistinguishedName_set_of, hf_index, ett_cmip_RelativeDistinguishedName);

  return offset;
}


static const ber_sequence_t RDNSequence_sequence_of[1] = {
  { &hf_cmip_RDNSequence_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_cmip_RelativeDistinguishedName },
};

int
dissect_cmip_RDNSequence(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      RDNSequence_sequence_of, hf_index, ett_cmip_RDNSequence);

  return offset;
}



static int
dissect_cmip_DistinguishedName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cmip_RDNSequence(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_cmip_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_ObjectInstance(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_CMISSync(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_T_namedNumbers(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_cmip_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_Scope(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Scope_choice, hf_index, ett_cmip_Scope,
                                 NULL);

  return offset;
}



static int
dissect_cmip_T_globalForm_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 133 "cmip.cnf"
  attributeform = ATTRIBUTE_GLOBAL_FORM;
    offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &attribute_identifier_id);




  return offset;
}



static int
dissect_cmip_T_localForm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 137 "cmip.cnf"
  attributeform = ATTRIBUTE_LOCAL_FORM;
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_cmip_localForm, NULL);



  return offset;
}


static const value_string cmip_AttributeId_vals[] = {
  {   0, "globalForm" },
  {   1, "localForm" },
  { 0, NULL }
};

static const ber_choice_t AttributeId_choice[] = {
  {   0, &hf_cmip_globalForm_01  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_cmip_T_globalForm_01 },
  {   1, &hf_cmip_localForm_01   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_cmip_T_localForm },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_AttributeId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AttributeId_choice, hf_index, ett_cmip_AttributeId,
                                 NULL);

  return offset;
}



static int
dissect_cmip_T_value(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 141 "cmip.cnf"
  /*XXX handle local form here */
  if(attributeform==ATTRIBUTE_GLOBAL_FORM){
    offset=call_ber_oid_callback(attribute_identifier_id, tvb, offset, actx->pinfo, tree);
  }


  return offset;
}


static const ber_sequence_t Attribute_sequence[] = {
  { &hf_cmip_id             , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_AttributeId },
  { &hf_cmip_value          , BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_cmip_T_value },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cmip_Attribute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_T_substrings_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_substrings_item_choice, hf_index, ett_cmip_T_substrings_item,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_substrings_sequence_of[1] = {
  { &hf_cmip_substrings_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_T_substrings_item },
};

static int
dissect_cmip_T_substrings(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
  {   4, &hf_cmip_present        , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_cmip_AttributeId },
  {   5, &hf_cmip_subsetOf       , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_cmip_Attribute },
  {   6, &hf_cmip_supersetOf     , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_cmip_Attribute },
  {   7, &hf_cmip_nonNullSetIntersection, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_cmip_Attribute },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_FilterItem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 FilterItem_choice, hf_index, ett_cmip_FilterItem,
                                 NULL);

  return offset;
}


static const ber_sequence_t SET_OF_CMISFilter_set_of[1] = {
  { &hf_cmip_and_item       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_CMISFilter },
};

static int
dissect_cmip_SET_OF_CMISFilter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_CMISFilter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CMISFilter_choice, hf_index, ett_cmip_CMISFilter,
                                 NULL);

  return offset;
}



static int
dissect_cmip_T_globalForm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_cmip_actionType_OID, &object_identifier_id);

  return offset;
}


static const value_string cmip_ActionTypeId_vals[] = {
  {   2, "globalForm" },
  {   3, "localForm" },
  { 0, NULL }
};

static const ber_choice_t ActionTypeId_choice[] = {
  {   2, &hf_cmip_globalForm     , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_cmip_T_globalForm },
  {   3, &hf_cmip_localForm      , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_cmip_INTEGER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_ActionTypeId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ActionTypeId_choice, hf_index, ett_cmip_ActionTypeId,
                                 NULL);

  return offset;
}



static int
dissect_cmip_T_actionInfoArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 238 "cmip.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);



  return offset;
}


static const ber_sequence_t ActionInfo_sequence[] = {
  { &hf_cmip_actionType     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ActionTypeId },
  { &hf_cmip_actionInfoArg  , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_T_actionInfoArg },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_ActionInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_ActionArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ActionArgument_sequence, hf_index, ett_cmip_ActionArgument);

  return offset;
}



static int
dissect_cmip_GeneralizedTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string cmip_T_errorStatus_vals[] = {
  {   2, "accessDenied" },
  {   9, "noSuchAction" },
  {  14, "noSuchArgument" },
  {  15, "invalidArgumentValue" },
  { 0, NULL }
};


static int
dissect_cmip_T_errorStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_T_actionId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_actionId_sequence, hf_index, ett_cmip_T_actionId);

  return offset;
}



static int
dissect_cmip_T_globalForm_02(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_cmip_eventType_OID, &object_identifier_id);

  return offset;
}


static const value_string cmip_EventTypeId_vals[] = {
  {   6, "globalForm" },
  {   7, "localForm" },
  { 0, NULL }
};

static const ber_choice_t EventTypeId_choice[] = {
  {   6, &hf_cmip_globalForm_02  , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_cmip_T_globalForm_02 },
  {   7, &hf_cmip_localForm      , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_cmip_INTEGER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_EventTypeId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_T_eventId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_NoSuchArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 NoSuchArgument_choice, hf_index, ett_cmip_NoSuchArgument,
                                 NULL);

  return offset;
}



static int
dissect_cmip_T_eventInfo_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 262 "cmip.cnf"

  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);


  return offset;
}


static const ber_sequence_t T_eventValue_sequence[] = {
  { &hf_cmip_eventType      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_EventTypeId },
  { &hf_cmip_eventInfo_01   , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_T_eventInfo_01 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_T_eventValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_InvalidArgumentValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 InvalidArgumentValue_choice, hf_index, ett_cmip_InvalidArgumentValue,
                                 NULL);

  return offset;
}


static const value_string cmip_T_errorInfo_vals[] = {
  {   0, "actionType" },
  {   1, "actionArgument" },
  {   2, "argumentValue" },
  { 0, NULL }
};

static const ber_choice_t T_errorInfo_choice[] = {
  {   0, &hf_cmip_actionType     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_cmip_ActionTypeId },
  {   1, &hf_cmip_actionArgument , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_cmip_NoSuchArgument },
  {   2, &hf_cmip_argumentValue  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_cmip_InvalidArgumentValue },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_T_errorInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_errorInfo_choice, hf_index, ett_cmip_T_errorInfo,
                                 NULL);

  return offset;
}


static const ber_sequence_t ActionErrorInfo_sequence[] = {
  { &hf_cmip_errorStatus    , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_cmip_T_errorStatus },
  { &hf_cmip_errorInfo      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_T_errorInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_ActionErrorInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ActionErrorInfo_sequence, hf_index, ett_cmip_ActionErrorInfo);

  return offset;
}


static const ber_sequence_t ActionError_sequence[] = {
  { &hf_cmip_managedObjectClass, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectClass },
  { &hf_cmip_managedObjectInstance, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectInstance },
  { &hf_cmip_currentTime    , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_GeneralizedTime },
  { &hf_cmip_actionErrorInfo, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_cmip_ActionErrorInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_ActionError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ActionError_sequence, hf_index, ett_cmip_ActionError);

  return offset;
}



static int
dissect_cmip_T_actionReplyInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 265 "cmip.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);




  return offset;
}


static const ber_sequence_t ActionReply_sequence[] = {
  { &hf_cmip_actionType     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ActionTypeId },
  { &hf_cmip_actionReplyInfo, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_cmip_T_actionReplyInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_ActionReply(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_ActionResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ActionResult_sequence, hf_index, ett_cmip_ActionResult);

  return offset;
}


static const value_string cmip_T_errorStatus_01_vals[] = {
  {   2, "accessDenied" },
  {   5, "noSuchAttribute" },
  {   6, "invalidAttributeValue" },
  {  24, "invalidOperation" },
  {  25, "invalidOperator" },
  { 0, NULL }
};


static int
dissect_cmip_T_errorStatus_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_ModifyOperator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_cmip_T_attributeValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 259 "cmip.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);



  return offset;
}


static const ber_sequence_t AttributeError_sequence[] = {
  { &hf_cmip_errorStatus_01 , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_cmip_T_errorStatus_01 },
  { &hf_cmip_modifyOperator , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_ModifyOperator },
  { &hf_cmip_attributeId    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_AttributeId },
  { &hf_cmip_attributeValue , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cmip_T_attributeValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_AttributeError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttributeError_sequence, hf_index, ett_cmip_AttributeError);

  return offset;
}


static const value_string cmip_T_errorStatus_02_vals[] = {
  {   2, "accessDenied" },
  {   5, "noSuchAttribute" },
  { 0, NULL }
};


static int
dissect_cmip_T_errorStatus_02(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t AttributeIdError_sequence[] = {
  { &hf_cmip_errorStatus_02 , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_cmip_T_errorStatus_02 },
  { &hf_cmip_attributeId    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_AttributeId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_AttributeIdError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_BaseManagedObjectId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_ComplexityLimitation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_T_managedOrSuperiorObjectInstance(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_managedOrSuperiorObjectInstance_choice, hf_index, ett_cmip_T_managedOrSuperiorObjectInstance,
                                 NULL);

  return offset;
}


static const ber_sequence_t SET_OF_Attribute_set_of[1] = {
  { &hf_cmip_attributeList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmip_Attribute },
};

static int
dissect_cmip_SET_OF_Attribute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_CreateArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_CreateResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_DeleteArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DeleteArgument_sequence, hf_index, ett_cmip_DeleteArgument);

  return offset;
}


static const value_string cmip_T_deleteErrorInfo_vals[] = {
  {   2, "accessDenied" },
  { 0, NULL }
};


static int
dissect_cmip_T_deleteErrorInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_DeleteError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_DeleteResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DeleteResult_sequence, hf_index, ett_cmip_DeleteResult);

  return offset;
}



static int
dissect_cmip_T_eventReplyInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 247 "cmip.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);



  return offset;
}


static const ber_sequence_t EventReply_sequence[] = {
  { &hf_cmip_eventType      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_EventTypeId },
  { &hf_cmip_eventReplyInfo , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_T_eventReplyInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_EventReply(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EventReply_sequence, hf_index, ett_cmip_EventReply);

  return offset;
}



static int
dissect_cmip_T_eventInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 244 "cmip.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);



  return offset;
}


static const ber_sequence_t EventReportArgument_sequence[] = {
  { &hf_cmip_managedObjectClass, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectClass },
  { &hf_cmip_managedObjectInstance, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectInstance },
  { &hf_cmip_eventTime      , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_GeneralizedTime },
  { &hf_cmip_eventType      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_EventTypeId },
  { &hf_cmip_eventInfo      , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_T_eventInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_EventReportArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_EventReportResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EventReportResult_sequence, hf_index, ett_cmip_EventReportResult);

  return offset;
}


static const ber_sequence_t SET_OF_AttributeId_set_of[1] = {
  { &hf_cmip_attributeIdList_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_AttributeId },
};

static int
dissect_cmip_SET_OF_AttributeId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_GetArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_GetInfoStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 GetInfoStatus_choice, hf_index, ett_cmip_GetInfoStatus,
                                 NULL);

  return offset;
}


static const ber_sequence_t SET_OF_GetInfoStatus_set_of[1] = {
  { &hf_cmip_getInfoList_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_GetInfoStatus },
};

static int
dissect_cmip_SET_OF_GetInfoStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_GetListError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_GetResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetResult_sequence, hf_index, ett_cmip_GetResult);

  return offset;
}



static int
dissect_cmip_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string cmip_InvokeId_vals[] = {
  {   0, "present" },
  {   1, "absent" },
  { 0, NULL }
};

static const ber_choice_t InvokeId_choice[] = {
  {   0, &hf_cmip_present_01     , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmip_INTEGER },
  {   1, &hf_cmip_absent         , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_cmip_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_InvokeId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 InvokeId_choice, hf_index, ett_cmip_InvokeId,
                                 NULL);

  return offset;
}



int
dissect_cmip_InvokeIDType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_SetResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_SetInfoStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SetInfoStatus_choice, hf_index, ett_cmip_SetInfoStatus,
                                 NULL);

  return offset;
}


static const ber_sequence_t SET_OF_SetInfoStatus_set_of[1] = {
  { &hf_cmip_setInfoList_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_SetInfoStatus },
};

static int
dissect_cmip_SET_OF_SetInfoStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_SetListError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SetListError_sequence, hf_index, ett_cmip_SetListError);

  return offset;
}



static int
dissect_cmip_T_errorId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_cmip_errorId_OID, &object_identifier_id);

  return offset;
}



static int
dissect_cmip_T_errorInfo_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 256 "cmip.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);



  return offset;
}


static const ber_sequence_t SpecificErrorInfo_sequence[] = {
  { &hf_cmip_errorId        , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cmip_T_errorId },
  { &hf_cmip_errorInfo_01   , BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_cmip_T_errorInfo_01 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_SpecificErrorInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_ProcessingFailure(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ProcessingFailure_sequence, hf_index, ett_cmip_ProcessingFailure);

  return offset;
}


static const value_string cmip_LinkedReplyArgument_vals[] = {
  {   0, "getResult" },
  {   1, "getListError" },
  {   2, "setResult" },
  {   3, "setListError" },
  {   4, "actionResult" },
  {   5, "processingFailure" },
  {   6, "deleteResult" },
  {   7, "actionError" },
  {   8, "deleteError" },
  { 0, NULL }
};

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
dissect_cmip_LinkedReplyArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_NoSuchAction(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_NoSuchEventType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NoSuchEventType_sequence, hf_index, ett_cmip_NoSuchEventType);

  return offset;
}



static int
dissect_cmip_T_attributevalue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 250 "cmip.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);



  return offset;
}


static const ber_sequence_t T_modificationList_item_sequence[] = {
  { &hf_cmip_modifyOperator , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_ModifyOperator },
  { &hf_cmip_attributeId    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_AttributeId },
  { &hf_cmip_attributevalue , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cmip_T_attributevalue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_T_modificationList_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_modificationList_item_sequence, hf_index, ett_cmip_T_modificationList_item);

  return offset;
}


static const ber_sequence_t T_modificationList_set_of[1] = {
  { &hf_cmip_modificationList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmip_T_modificationList_item },
};

static int
dissect_cmip_T_modificationList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_SetArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SetArgument_sequence, hf_index, ett_cmip_SetArgument);

  return offset;
}



static int
dissect_cmip_InvokeId_present(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_cmip_T_linkedIdPresent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_T_linkedId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_linkedId_choice, hf_index, ett_cmip_T_linkedId,
                                 NULL);

  return offset;
}



static int
dissect_cmip_T_local(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 98 "cmip.cnf"
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  &opcode);

  if(check_col(actx->pinfo->cinfo, COL_INFO)){
    col_prepend_fstr(actx->pinfo->cinfo, COL_INFO, "%s", val_to_str(opcode, cmip_Opcode_vals, " Unknown Opcode:%d"));
  }


  return offset;
}



static int
dissect_cmip_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

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
dissect_cmip_Code(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Code_choice, hf_index, ett_cmip_Code,
                                 NULL);

  return offset;
}



static int
dissect_cmip_InvokeArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 152 "cmip.cnf"
    switch(opcode){
    case 0: /* M-eventreport */
      offset = dissect_cmip_EventReportArgument(FALSE, tvb, offset, actx, tree, -1);
      break;
    case 1: /* M-eventreport-confirmed */
      offset = dissect_cmip_EventReportArgument(FALSE, tvb, offset, actx, tree, -1);
      break;
    case 2: /* M-linkedreply */
      offset = dissect_cmip_LinkedReplyArgument(FALSE, tvb, offset, actx, tree, -1);
      break;
    case 3: /* M-get */
      offset = dissect_cmip_GetArgument(FALSE, tvb, offset,actx, tree, -1);
      break;
    case 4: /* M-set */
      offset = dissect_cmip_SetArgument(FALSE, tvb, offset,actx, tree, -1);
      break;
    case 5: /* M-set-confirmed */
      offset = dissect_cmip_SetArgument(FALSE, tvb, offset,actx, tree, -1);
      break;
    case 6: /* M-action*/
      offset = dissect_cmip_ActionArgument(FALSE, tvb,  offset, actx, tree, -1);
      break;
    case 7: /* M-action-confirmed*/
      offset = dissect_cmip_ActionArgument(FALSE, tvb,  offset, actx, tree, -1);
      break;
    case 8: /* M-create*/
      offset = dissect_cmip_CreateArgument(FALSE, tvb,  offset, actx, tree, -1);
      break;
    case 9: /* M-delete*/
      offset = dissect_cmip_DeleteArgument(FALSE, tvb,  offset, actx, tree, -1);
      break;
    case 10: /* M-cancelget */
      offset = dissect_cmip_InvokeIDType(FALSE, tvb,  offset, actx, tree, -1);
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
dissect_cmip_Invoke(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 105 "cmip.cnf"
  opcode_type=OPCODE_INVOKE;
  if(check_col(actx->pinfo->cinfo, COL_INFO)){
    col_prepend_fstr(actx->pinfo->cinfo, COL_INFO, "Invoke ");
  }

  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Invoke_sequence, hf_index, ett_cmip_Invoke);

  return offset;
}



static int
dissect_cmip_ResultArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 190 "cmip.cnf"

    switch(opcode){
    case 0: /* M-eventreport*/
      break;  /* No return data */
    case 1: /* M-eventreport-confirmed */
      offset = dissect_cmip_EventReportResult(FALSE, tvb, offset, actx, tree, -1);
      break;
    case 2: /* M-linkedreply*/
      break;  /* No return data */
    case 3: /* M-get */
      offset = dissect_cmip_GetResult(FALSE, tvb, offset, actx, tree, -1);
      break;
    case 4: /* M-set */
      break;  /* No return data */
    case 5: /* M-set-confirmed*/
      offset = dissect_cmip_SetResult(FALSE, tvb, offset, actx, tree, -1);
      break;
    case 6: /* M-action*/
      break;  /* No return data */
    case 7: /* M-action-confirmed*/
      offset = dissect_cmip_ActionResult(FALSE, tvb, offset, actx, tree, -1);
      break;
    case 8: /* M-create*/
      offset = dissect_cmip_CreateResult(FALSE, tvb,  offset, actx, tree, -1);
      break;
    case 9: /* M-delete*/
      offset = dissect_cmip_DeleteResult(FALSE, tvb,  offset, actx, tree, -1);
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
dissect_cmip_T_result(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_ReturnResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 112 "cmip.cnf"
  opcode_type=OPCODE_RETURN_RESULT;
  if(check_col(actx->pinfo->cinfo, COL_INFO)){
    col_prepend_fstr(actx->pinfo->cinfo, COL_INFO, "ReturnResult ");
  }

  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReturnResult_sequence, hf_index, ett_cmip_ReturnResult);

  return offset;
}



static int
dissect_cmip_T_parameter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 224 "cmip.cnf"
/* TODO: add code here */



  return offset;
}


static const ber_sequence_t ReturnError_sequence[] = {
  { &hf_cmip_invokeId       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_InvokeId },
  { &hf_cmip_errcode        , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_Code },
  { &hf_cmip_parameter      , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cmip_T_parameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_ReturnError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 119 "cmip.cnf"
  opcode_type=OPCODE_RETURN_ERROR;
  if(check_col(actx->pinfo->cinfo, COL_INFO)){
    col_prepend_fstr(actx->pinfo->cinfo, COL_INFO, "ReturnError ");
  }

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
dissect_cmip_GeneralProblem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_InvokeProblem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_ReturnResultProblem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_ReturnErrorProblem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_T_problem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_Reject(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 126 "cmip.cnf"
  opcode_type=OPCODE_REJECT;
  if(check_col(actx->pinfo->cinfo, COL_INFO)){
    col_prepend_fstr(actx->pinfo->cinfo, COL_INFO, "Reject ");
  }

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
dissect_cmip_ROS(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ROS_choice, hf_index, ett_cmip_ROS,
                                 NULL);

  return offset;
}



static int
dissect_cmip_ROSEapdus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cmip_ROS(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string cmip_CMIPAbortSource_vals[] = {
  {   0, "cmiseServiceUser" },
  {   1, "cmiseServiceProvider" },
  { 0, NULL }
};


static int
dissect_cmip_CMIPAbortSource(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 89 "cmip.cnf"
  guint32 value;

    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  &value);

  if(check_col(actx->pinfo->cinfo, COL_INFO)){
    col_append_fstr(actx->pinfo->cinfo, COL_INFO, " AbortSource:%s", val_to_str(value, cmip_CMIPAbortSource_vals, " Unknown AbortSource:%d"));
  }


  return offset;
}



static int
dissect_cmip_EXTERNAL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_external_type(implicit_tag, tree, tvb, offset, actx, hf_index, NULL);

  return offset;
}


static const ber_sequence_t CMIPAbortInfo_sequence[] = {
  { &hf_cmip_abortSource    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_cmip_CMIPAbortSource },
  { &hf_cmip_userInfo       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_EXTERNAL },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cmip_CMIPAbortInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 77 "cmip.cnf"
  if(check_col(actx->pinfo->cinfo, COL_INFO)){
    col_append_fstr(actx->pinfo->cinfo, COL_INFO, "CMIP-A-ABORT");
  }

  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CMIPAbortInfo_sequence, hf_index, ett_cmip_CMIPAbortInfo);

  return offset;
}


static const asn_namedbit FunctionalUnits_bits[] = {
  {  0, &hf_cmip_FunctionalUnits_multipleObjectSelection, -1, -1, "multipleObjectSelection", NULL },
  {  1, &hf_cmip_FunctionalUnits_filter, -1, -1, "filter", NULL },
  {  2, &hf_cmip_FunctionalUnits_multipleReply, -1, -1, "multipleReply", NULL },
  {  3, &hf_cmip_FunctionalUnits_extendedService, -1, -1, "extendedService", NULL },
  {  4, &hf_cmip_FunctionalUnits_cancelGet, -1, -1, "cancelGet", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_cmip_FunctionalUnits(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    FunctionalUnits_bits, hf_index, ett_cmip_FunctionalUnits,
                                    NULL);

  return offset;
}


static const asn_namedbit ProtocolVersion_bits[] = {
  {  0, &hf_cmip_ProtocolVersion_version1, -1, -1, "version1", NULL },
  {  1, &hf_cmip_ProtocolVersion_version2, -1, -1, "version2", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_cmip_ProtocolVersion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    ProtocolVersion_bits, hf_index, ett_cmip_ProtocolVersion,
                                    NULL);

  return offset;
}


static const ber_sequence_t CMIPUserInfo_sequence[] = {
  { &hf_cmip_protocolVersion, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_ProtocolVersion },
  { &hf_cmip_functionalUnits, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_FunctionalUnits },
  { &hf_cmip_accessControl_01, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_EXTERNAL },
  { &hf_cmip_userInfo       , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_EXTERNAL },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cmip_CMIPUserInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 83 "cmip.cnf"
  if(check_col(actx->pinfo->cinfo, COL_INFO)){
    col_append_fstr(actx->pinfo->cinfo, COL_INFO, "CMIP-A-ASSOCIATE");
  }

  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CMIPUserInfo_sequence, hf_index, ett_cmip_CMIPUserInfo);

  return offset;
}


static const ber_sequence_t SET_OF_AE_title_set_of[1] = {
  { &hf_cmip_multiple_item  , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_acse_AE_title },
};

static int
dissect_cmip_SET_OF_AE_title(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_Destination(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Destination_choice, hf_index, ett_cmip_Destination,
                                 NULL);

  return offset;
}



static int
dissect_cmip_ActiveDestination(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cmip_Destination(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_cmip_AdditionalText(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GraphicString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_cmip_T_identifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &object_identifier_id);

  return offset;
}



static int
dissect_cmip_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_cmip_T_information(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 272 "cmip.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);



  return offset;
}


static const ber_sequence_t ManagementExtension_sequence[] = {
  { &hf_cmip_identifier     , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cmip_T_identifier },
  { &hf_cmip_significance   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_BOOLEAN },
  { &hf_cmip_information    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_cmip_T_information },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_ManagementExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ManagementExtension_sequence, hf_index, ett_cmip_ManagementExtension);

  return offset;
}


static const ber_sequence_t AdditionalInformation_set_of[1] = {
  { &hf_cmip_AdditionalInformation_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmip_ManagementExtension },
};

static int
dissect_cmip_AdditionalInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 AdditionalInformation_set_of, hf_index, ett_cmip_AdditionalInformation);

  return offset;
}


static const ber_sequence_t Allomorphs_set_of[1] = {
  { &hf_cmip_Allomorphs_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectClass },
};

static int
dissect_cmip_Allomorphs(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 Allomorphs_set_of, hf_index, ett_cmip_Allomorphs);

  return offset;
}


static const value_string cmip_AdministrativeState_vals[] = {
  {   0, "locked" },
  {   1, "unlocked" },
  {   2, "shuttingDown" },
  { 0, NULL }
};


static int
dissect_cmip_AdministrativeState(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t AttributeIdentifierList_set_of[1] = {
  { &hf_cmip_AttributeIdentifierList_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_AttributeId },
};

static int
dissect_cmip_AttributeIdentifierList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 AttributeIdentifierList_set_of, hf_index, ett_cmip_AttributeIdentifierList);

  return offset;
}


static const ber_sequence_t AttributeList_set_of[1] = {
  { &hf_cmip_AttributeList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmip_Attribute },
};

static int
dissect_cmip_AttributeList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 AttributeList_set_of, hf_index, ett_cmip_AttributeList);

  return offset;
}



static int
dissect_cmip_T_oldAttributeValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 275 "cmip.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);



  return offset;
}



static int
dissect_cmip_T_newAttributeValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 278 "cmip.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);



  return offset;
}


static const ber_sequence_t AttributeValueChangeDefinition_item_sequence[] = {
  { &hf_cmip_attributeId    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_AttributeId },
  { &hf_cmip_oldAttributeValue, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cmip_T_oldAttributeValue },
  { &hf_cmip_newAttributeValue, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_cmip_T_newAttributeValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_AttributeValueChangeDefinition_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttributeValueChangeDefinition_item_sequence, hf_index, ett_cmip_AttributeValueChangeDefinition_item);

  return offset;
}


static const ber_sequence_t AttributeValueChangeDefinition_set_of[1] = {
  { &hf_cmip_AttributeValueChangeDefinition_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmip_AttributeValueChangeDefinition_item },
};

static int
dissect_cmip_AttributeValueChangeDefinition(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_AlarmStatus_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t AlarmStatus_set_of[1] = {
  { &hf_cmip_AlarmStatus_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmip_AlarmStatus_item },
};

static int
dissect_cmip_AlarmStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_AvailabilityStatus_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t AvailabilityStatus_set_of[1] = {
  { &hf_cmip_AvailabilityStatus_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmip_AvailabilityStatus_item },
};

static int
dissect_cmip_AvailabilityStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 AvailabilityStatus_set_of, hf_index, ett_cmip_AvailabilityStatus);

  return offset;
}



static int
dissect_cmip_BackedUpStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t BackUpDestinationList_sequence_of[1] = {
  { &hf_cmip_BackUpDestinationList_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_acse_AE_title },
};

static int
dissect_cmip_BackUpDestinationList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_BackUpRelationshipObject(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 BackUpRelationshipObject_choice, hf_index, ett_cmip_BackUpRelationshipObject,
                                 NULL);

  return offset;
}



static int
dissect_cmip_INTEGER_0_100(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t CapacityAlarmThreshold_set_of[1] = {
  { &hf_cmip_CapacityAlarmThreshold_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmip_INTEGER_0_100 },
};

static int
dissect_cmip_CapacityAlarmThreshold(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 CapacityAlarmThreshold_set_of, hf_index, ett_cmip_CapacityAlarmThreshold);

  return offset;
}



static int
dissect_cmip_ConfirmedMode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index);

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
dissect_cmip_ControlStatus_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t ControlStatus_set_of[1] = {
  { &hf_cmip_ControlStatus_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmip_ControlStatus_item },
};

static int
dissect_cmip_ControlStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 ControlStatus_set_of, hf_index, ett_cmip_ControlStatus);

  return offset;
}


static const ber_sequence_t CounterThreshold_item_sequence[] = {
  { &hf_cmip_comparisonLevel, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmip_INTEGER },
  { &hf_cmip_offsetValue    , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmip_INTEGER },
  { &hf_cmip_notificationOnOff, BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_NOOWNTAG, dissect_cmip_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_CounterThreshold_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CounterThreshold_item_sequence, hf_index, ett_cmip_CounterThreshold_item);

  return offset;
}


static const ber_sequence_t CounterThreshold_set_of[1] = {
  { &hf_cmip_CounterThreshold_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmip_CounterThreshold_item },
};

static int
dissect_cmip_CounterThreshold(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 CounterThreshold_set_of, hf_index, ett_cmip_CounterThreshold);

  return offset;
}



static int
dissect_cmip_NotificationIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t SET_OF_NotificationIdentifier_set_of[1] = {
  { &hf_cmip_correlatedNotifications_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmip_NotificationIdentifier },
};

static int
dissect_cmip_SET_OF_NotificationIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_CorrelatedNotifications_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CorrelatedNotifications_item_sequence, hf_index, ett_cmip_CorrelatedNotifications_item);

  return offset;
}


static const ber_sequence_t CorrelatedNotifications_set_of[1] = {
  { &hf_cmip_CorrelatedNotifications_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmip_CorrelatedNotifications_item },
};

static int
dissect_cmip_CorrelatedNotifications(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 CorrelatedNotifications_set_of, hf_index, ett_cmip_CorrelatedNotifications);

  return offset;
}



static int
dissect_cmip_CurrentLogSize(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_cmip_DiscriminatorConstruct(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cmip_CMISFilter(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_cmip_EventTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_cmip_REAL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_ObservedValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ObservedValue_choice, hf_index, ett_cmip_ObservedValue,
                                 NULL);

  return offset;
}


static const ber_sequence_t NotifyThreshold_sequence[] = {
  { &hf_cmip_threshold      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObservedValue },
  { &hf_cmip_notifyOnOff    , BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_NOOWNTAG, dissect_cmip_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_NotifyThreshold(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NotifyThreshold_sequence, hf_index, ett_cmip_NotifyThreshold);

  return offset;
}


static const ber_sequence_t GaugeThreshold_item_sequence[] = {
  { &hf_cmip_notifyLow      , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmip_NotifyThreshold },
  { &hf_cmip_notifyHigh     , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmip_NotifyThreshold },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_GaugeThreshold_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GaugeThreshold_item_sequence, hf_index, ett_cmip_GaugeThreshold_item);

  return offset;
}


static const ber_sequence_t GaugeThreshold_set_of[1] = {
  { &hf_cmip_GaugeThreshold_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmip_GaugeThreshold_item },
};

static int
dissect_cmip_GaugeThreshold(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 GaugeThreshold_set_of, hf_index, ett_cmip_GaugeThreshold);

  return offset;
}



static int
dissect_cmip_GaugeThresholdValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cmip_ObservedValue(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t GroupObjects_set_of[1] = {
  { &hf_cmip_GroupObjects_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObjectInstance },
};

static int
dissect_cmip_GroupObjects(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 GroupObjects_set_of, hf_index, ett_cmip_GroupObjects);

  return offset;
}



static int
dissect_cmip_INTEGER_0_23(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_cmip_INTEGER_0_59(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_Time24(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_IntervalsOfDay_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IntervalsOfDay_item_sequence, hf_index, ett_cmip_IntervalsOfDay_item);

  return offset;
}


static const ber_sequence_t IntervalsOfDay_set_of[1] = {
  { &hf_cmip_IntervalsOfDay_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmip_IntervalsOfDay_item },
};

static int
dissect_cmip_IntervalsOfDay(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_LifecycleState(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_cmip_LogAvailability(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cmip_AvailabilityStatus(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string cmip_LogFullAction_vals[] = {
  {   0, "wrap" },
  {   1, "halt" },
  { 0, NULL }
};


static int
dissect_cmip_LogFullAction(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_cmip_LoggingTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_cmip_GraphicString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_SimpleNameType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SimpleNameType_choice, hf_index, ett_cmip_SimpleNameType,
                                 NULL);

  return offset;
}



static int
dissect_cmip_LogRecordId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cmip_SimpleNameType(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string cmip_MaxLogSize_vals[] = {
  {   0, "unlimited" },
  { 0, NULL }
};


static int
dissect_cmip_MaxLogSize(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t MonitoredAttributes_set_of[1] = {
  { &hf_cmip_MonitoredAttributes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmip_Attribute },
};

static int
dissect_cmip_MonitoredAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 MonitoredAttributes_set_of, hf_index, ett_cmip_MonitoredAttributes);

  return offset;
}



static int
dissect_cmip_NameBinding(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_cmip_NumberOfRecords(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string cmip_OperationalState_vals[] = {
  {   0, "disabled" },
  {   1, "enabled" },
  { 0, NULL }
};


static int
dissect_cmip_OperationalState(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t Packages_set_of[1] = {
  { &hf_cmip_Packages_item  , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cmip_OBJECT_IDENTIFIER },
};

static int
dissect_cmip_Packages(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_PerceivedSeverity(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_T_priority(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_PrioritisedObject_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PrioritisedObject_item_sequence, hf_index, ett_cmip_PrioritisedObject_item);

  return offset;
}


static const ber_sequence_t PrioritisedObject_set_of[1] = {
  { &hf_cmip_PrioritisedObject_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmip_PrioritisedObject_item },
};

static int
dissect_cmip_PrioritisedObject(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 PrioritisedObject_set_of, hf_index, ett_cmip_PrioritisedObject);

  return offset;
}


static const value_string cmip_ProbableCause_vals[] = {
  {   0, "globalValue" },
  {   1, "localValue" },
  { 0, NULL }
};

static const ber_choice_t ProbableCause_choice[] = {
  {   0, &hf_cmip_globalValue    , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cmip_OBJECT_IDENTIFIER },
  {   1, &hf_cmip_localValue     , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmip_INTEGER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_ProbableCause(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_ProceduralStatus_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t ProceduralStatus_set_of[1] = {
  { &hf_cmip_ProceduralStatus_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cmip_ProceduralStatus_item },
};

static int
dissect_cmip_ProceduralStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_SpecificIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SpecificIdentifier_choice, hf_index, ett_cmip_SpecificIdentifier,
                                 NULL);

  return offset;
}


static const ber_sequence_t ProposedRepairActions_set_of[1] = {
  { &hf_cmip_ProposedRepairActions_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_SpecificIdentifier },
};

static int
dissect_cmip_ProposedRepairActions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 ProposedRepairActions_set_of, hf_index, ett_cmip_ProposedRepairActions);

  return offset;
}



static int
dissect_cmip_SchedulingAvailability(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cmip_AvailabilityStatus(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_cmip_SecurityAlarmCause(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_cmip_SecurityAlarmSeverity(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_SecurityAlarmDetector(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SecurityAlarmDetector_choice, hf_index, ett_cmip_SecurityAlarmDetector,
                                 NULL);

  return offset;
}



static int
dissect_cmip_T_identifier_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &object_identifier_id);

  return offset;
}



static int
dissect_cmip_T_details(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 283 "cmip.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);



  return offset;
}


static const ber_sequence_t ServiceUser_sequence[] = {
  { &hf_cmip_identifier_01  , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cmip_T_identifier_01 },
  { &hf_cmip_details        , BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_cmip_T_details },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_ServiceUser(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ServiceUser_sequence, hf_index, ett_cmip_ServiceUser);

  return offset;
}



static int
dissect_cmip_ServiceProvider(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_SourceIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t SpecificProblems_set_of[1] = {
  { &hf_cmip_SpecificProblems_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_SpecificIdentifier },
};

static int
dissect_cmip_SpecificProblems(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_StandbyStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_cmip_StartTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_StopTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 StopTime_choice, hf_index, ett_cmip_StopTime,
                                 NULL);

  return offset;
}



static int
dissect_cmip_T_featureIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &object_identifier_id);

  return offset;
}



static int
dissect_cmip_T_featureInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 288 "cmip.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);




  return offset;
}


static const ber_sequence_t SupportedFeatures_item_sequence[] = {
  { &hf_cmip_featureIdentifier, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cmip_T_featureIdentifier },
  { &hf_cmip_featureInfo    , BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_cmip_T_featureInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_SupportedFeatures_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SupportedFeatures_item_sequence, hf_index, ett_cmip_SupportedFeatures_item);

  return offset;
}


static const ber_sequence_t SupportedFeatures_set_of[1] = {
  { &hf_cmip_SupportedFeatures_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmip_SupportedFeatures_item },
};

static int
dissect_cmip_SupportedFeatures(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_SystemId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_SystemTitle(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SystemTitle_choice, hf_index, ett_cmip_SystemTitle,
                                 NULL);

  return offset;
}


static const value_string cmip_TideMark_vals[] = {
  {   0, "maxTideMar" },
  {   1, "minTideMark" },
  { 0, NULL }
};

static const ber_choice_t TideMark_choice[] = {
  {   0, &hf_cmip_maxTideMar     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_cmip_ObservedValue },
  {   1, &hf_cmip_minTideMark    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_cmip_ObservedValue },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_TideMark(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 TideMark_choice, hf_index, ett_cmip_TideMark,
                                 NULL);

  return offset;
}


static const ber_sequence_t TideMarkInfo_sequence[] = {
  { &hf_cmip_currentTideMark, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_TideMark },
  { &hf_cmip_previousTideMark, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_TideMark },
  { &hf_cmip_resetTime      , BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_cmip_GeneralizedTime },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_TideMarkInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TideMarkInfo_sequence, hf_index, ett_cmip_TideMarkInfo);

  return offset;
}


static const ber_sequence_t T_up_sequence[] = {
  { &hf_cmip_high           , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObservedValue },
  { &hf_cmip_low            , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cmip_ObservedValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_T_up(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_T_down(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_ThresholdLevelInd(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_ThresholdInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cmip_TrendIndication(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_cmip_UnknownStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_cmip_UnscheduledLogAvailability(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cmip_AvailabilityStatus(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string cmip_UsageState_vals[] = {
  {   0, "idle" },
  {   1, "active" },
  {   2, "busy" },
  { 0, NULL }
};


static int
dissect_cmip_UsageState(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const asn_namedbit T_daysOfWeek_bits[] = {
  {  0, &hf_cmip_T_daysOfWeek_sunday, -1, -1, "sunday", NULL },
  {  1, &hf_cmip_T_daysOfWeek_monday, -1, -1, "monday", NULL },
  {  2, &hf_cmip_T_daysOfWeek_tuesday, -1, -1, "tuesday", NULL },
  {  3, &hf_cmip_T_daysOfWeek_wednesday, -1, -1, "wednesday", NULL },
  {  4, &hf_cmip_T_daysOfWeek_thursday, -1, -1, "thursday", NULL },
  {  5, &hf_cmip_T_daysOfWeek_friday, -1, -1, "friday", NULL },
  {  6, &hf_cmip_T_daysOfWeek_saturday, -1, -1, "saturday", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_cmip_T_daysOfWeek(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    T_daysOfWeek_bits, hf_index, ett_cmip_T_daysOfWeek,
                                    NULL);

  return offset;
}


static const ber_sequence_t WeekMask_item_sequence[] = {
  { &hf_cmip_daysOfWeek     , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_cmip_T_daysOfWeek },
  { &hf_cmip_intervalsOfDay , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_cmip_IntervalsOfDay },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cmip_WeekMask_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   WeekMask_item_sequence, hf_index, ett_cmip_WeekMask_item);

  return offset;
}


static const ber_sequence_t WeekMask_set_of[1] = {
  { &hf_cmip_WeekMask_item  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cmip_WeekMask_item },
};

static int
dissect_cmip_WeekMask(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 WeekMask_set_of, hf_index, ett_cmip_WeekMask);

  return offset;
}



static int
dissect_cmip_Priority(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string cmip_RejectProblem_vals[] = {
  {   0, "general-unrecognizedPDU" },
  {   1, "general-mistypedPDU" },
  {   2, "general-badlyStructuredPDU" },
  {  10, "invoke-duplicateInvocation" },
  {  11, "invoke-unrecognizedOperation" },
  {  12, "invoke-mistypedArgument" },
  {  13, "invoke-resourceLimitation" },
  {  14, "invoke-releaseInProgress" },
  {  15, "invoke-unrecognizedLinkedId" },
  {  16, "invoke-linkedResponseUnexpected" },
  {  17, "invoke-unexpectedLinkedOperation" },
  {  20, "returnResult-unrecognizedInvocation" },
  {  21, "returnResult-resultResponseUnexpected" },
  {  22, "returnResult-mistypedResult" },
  {  30, "returnError-unrecognizedInvocation" },
  {  31, "returnError-errorResponseUnexpected" },
  {  32, "returnError-unrecognizedError" },
  {  33, "returnError-unexpectedError" },
  {  34, "returnError-mistypedParameter" },
  { 0, NULL }
};


static int
dissect_cmip_RejectProblem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}

/*--- PDUs ---*/

static void dissect_ObjectClass_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cmip_ObjectClass(FALSE, tvb, 0, &asn1_ctx, tree, hf_cmip_ObjectClass_PDU);
}
static void dissect_AdditionalText_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cmip_AdditionalText(FALSE, tvb, 0, &asn1_ctx, tree, hf_cmip_AdditionalText_PDU);
}
static void dissect_Allomorphs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cmip_Allomorphs(FALSE, tvb, 0, &asn1_ctx, tree, hf_cmip_Allomorphs_PDU);
}
static void dissect_BackedUpStatus_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cmip_BackedUpStatus(FALSE, tvb, 0, &asn1_ctx, tree, hf_cmip_BackedUpStatus_PDU);
}
static void dissect_Destination_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cmip_Destination(FALSE, tvb, 0, &asn1_ctx, tree, hf_cmip_Destination_PDU);
}
static void dissect_DiscriminatorConstruct_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cmip_DiscriminatorConstruct(FALSE, tvb, 0, &asn1_ctx, tree, hf_cmip_DiscriminatorConstruct_PDU);
}
static void dissect_LogRecordId_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cmip_LogRecordId(FALSE, tvb, 0, &asn1_ctx, tree, hf_cmip_LogRecordId_PDU);
}
static void dissect_NameBinding_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cmip_NameBinding(FALSE, tvb, 0, &asn1_ctx, tree, hf_cmip_NameBinding_PDU);
}
static void dissect_OperationalState_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cmip_OperationalState(FALSE, tvb, 0, &asn1_ctx, tree, hf_cmip_OperationalState_PDU);
}
static void dissect_SystemId_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cmip_SystemId(FALSE, tvb, 0, &asn1_ctx, tree, hf_cmip_SystemId_PDU);
}
static void dissect_SystemTitle_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cmip_SystemTitle(FALSE, tvb, 0, &asn1_ctx, tree, hf_cmip_SystemTitle_PDU);
}
static void dissect_UsageState_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cmip_UsageState(FALSE, tvb, 0, &asn1_ctx, tree, hf_cmip_UsageState_PDU);
}


/*--- End of included file: packet-cmip-fn.c ---*/
#line 107 "packet-cmip-template.c"




/* XXX this one should be broken out later and moved into the conformance file */
static void
dissect_cmip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	static struct SESSION_DATA_STRUCTURE* session = NULL;
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);


	/* do we have spdu type from the session dissector?  */
	if( !pinfo->private_data ){
		if(tree){
			proto_tree_add_text(tree, tvb, 0, -1,
				"Internal error:can't get spdu type from session dissector.");
			return;
		}
	} else {
		session  = ( (struct SESSION_DATA_STRUCTURE*)(pinfo->private_data) );
		if(session->spdu_type == 0 ){
			if(tree){
				proto_tree_add_text(tree, tvb, 0, -1,
					"Internal error:wrong spdu type %x from session dissector.",session->spdu_type);
				return;
			}
		}
	}

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_cmip, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_cmip);
	}

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "CMIP");
  	if (check_col(pinfo->cinfo, COL_INFO))
  		col_clear(pinfo->cinfo, COL_INFO);
	switch(session->spdu_type){
		case SES_CONNECTION_REQUEST:
		case SES_CONNECTION_ACCEPT:
		case SES_DISCONNECT:
		case SES_FINISH:
		case SES_REFUSE:
			dissect_cmip_CMIPUserInfo(FALSE,tvb,0,&asn1_ctx,tree,-1);
			break;
		case SES_ABORT:
			dissect_cmip_CMIPAbortInfo(FALSE,tvb,0,&asn1_ctx,tree,-1);
			break;
		case SES_DATA_TRANSFER:
			dissect_cmip_ROS(FALSE,tvb,0,&asn1_ctx,tree,-1);
			break;
		default:
			;
	}
}

/*--- proto_register_cmip ----------------------------------------------*/
void proto_register_cmip(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_cmip_actionType_OID,
      { "actionType", "cmip.actionType_OID",
        FT_STRING, BASE_NONE, NULL, 0,
        "actionType", HFILL }},
    { &hf_cmip_eventType_OID,
      { "eventType", "cmip.eventType_OID",
        FT_STRING, BASE_NONE, NULL, 0,
        "eventType", HFILL }},
    { &hf_cmip_attributeId_OID,
      { "attributeId", "cmip.attributeId_OID",
        FT_STRING, BASE_NONE, NULL, 0,
        "attributeId", HFILL }},
    { &hf_cmip_errorId_OID,
      { "errorId", "cmip.errorId_OID",
        FT_STRING, BASE_NONE, NULL, 0,
        "errorId", HFILL }},
   { &hf_DiscriminatorConstruct,
      { "DiscriminatorConstruct", "cmip.DiscriminatorConstruct",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_Destination,
      { "Destination", "cmip.Destination",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_NameBinding,
      { "NameBinding", "cmip.NameBinding",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_ObjectClass,
      { "ObjectClass", "cmip.ObjectClass",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectClass_vals), 0,
        "", HFILL }},


/*--- Included file: packet-cmip-hfarr.c ---*/
#line 1 "packet-cmip-hfarr.c"
    { &hf_cmip_ObjectClass_PDU,
      { "ObjectClass", "cmip.ObjectClass",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectClass_vals), 0,
        "cmip.ObjectClass", HFILL }},
    { &hf_cmip_AdditionalText_PDU,
      { "AdditionalText", "cmip.AdditionalText",
        FT_STRING, BASE_NONE, NULL, 0,
        "cmip.AdditionalText", HFILL }},
    { &hf_cmip_Allomorphs_PDU,
      { "Allomorphs", "cmip.Allomorphs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmip.Allomorphs", HFILL }},
    { &hf_cmip_BackedUpStatus_PDU,
      { "BackedUpStatus", "cmip.BackedUpStatus",
        FT_BOOLEAN, 8, NULL, 0,
        "cmip.BackedUpStatus", HFILL }},
    { &hf_cmip_Destination_PDU,
      { "Destination", "cmip.Destination",
        FT_UINT32, BASE_DEC, VALS(cmip_Destination_vals), 0,
        "cmip.Destination", HFILL }},
    { &hf_cmip_DiscriminatorConstruct_PDU,
      { "DiscriminatorConstruct", "cmip.DiscriminatorConstruct",
        FT_UINT32, BASE_DEC, VALS(cmip_CMISFilter_vals), 0,
        "cmip.DiscriminatorConstruct", HFILL }},
    { &hf_cmip_LogRecordId_PDU,
      { "LogRecordId", "cmip.LogRecordId",
        FT_UINT32, BASE_DEC, VALS(cmip_SimpleNameType_vals), 0,
        "cmip.LogRecordId", HFILL }},
    { &hf_cmip_NameBinding_PDU,
      { "NameBinding", "cmip.NameBinding",
        FT_OID, BASE_NONE, NULL, 0,
        "cmip.NameBinding", HFILL }},
    { &hf_cmip_OperationalState_PDU,
      { "OperationalState", "cmip.OperationalState",
        FT_UINT32, BASE_DEC, VALS(cmip_OperationalState_vals), 0,
        "cmip.OperationalState", HFILL }},
    { &hf_cmip_SystemId_PDU,
      { "SystemId", "cmip.SystemId",
        FT_UINT32, BASE_DEC, VALS(cmip_SystemId_vals), 0,
        "cmip.SystemId", HFILL }},
    { &hf_cmip_SystemTitle_PDU,
      { "SystemTitle", "cmip.SystemTitle",
        FT_UINT32, BASE_DEC, VALS(cmip_SystemTitle_vals), 0,
        "cmip.SystemTitle", HFILL }},
    { &hf_cmip_UsageState_PDU,
      { "UsageState", "cmip.UsageState",
        FT_UINT32, BASE_DEC, VALS(cmip_UsageState_vals), 0,
        "cmip.UsageState", HFILL }},
    { &hf_cmip_managedObjectClass,
      { "managedObjectClass", "cmip.managedObjectClass",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectClass_vals), 0,
        "cmip.ObjectClass", HFILL }},
    { &hf_cmip_managedObjectInstance,
      { "managedObjectInstance", "cmip.managedObjectInstance",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "cmip.ObjectInstance", HFILL }},
    { &hf_cmip_currentTime,
      { "currentTime", "cmip.currentTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "cmip.GeneralizedTime", HFILL }},
    { &hf_cmip_actionErrorInfo,
      { "actionErrorInfo", "cmip.actionErrorInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.ActionErrorInfo", HFILL }},
    { &hf_cmip_errorStatus,
      { "errorStatus", "cmip.errorStatus",
        FT_UINT32, BASE_DEC, VALS(cmip_T_errorStatus_vals), 0,
        "cmip.T_errorStatus", HFILL }},
    { &hf_cmip_errorInfo,
      { "errorInfo", "cmip.errorInfo",
        FT_UINT32, BASE_DEC, VALS(cmip_T_errorInfo_vals), 0,
        "cmip.T_errorInfo", HFILL }},
    { &hf_cmip_actionType,
      { "actionType", "cmip.actionType",
        FT_UINT32, BASE_DEC, VALS(cmip_ActionTypeId_vals), 0,
        "cmip.ActionTypeId", HFILL }},
    { &hf_cmip_actionArgument,
      { "actionArgument", "cmip.actionArgument",
        FT_UINT32, BASE_DEC, VALS(cmip_NoSuchArgument_vals), 0,
        "cmip.NoSuchArgument", HFILL }},
    { &hf_cmip_argumentValue,
      { "argumentValue", "cmip.argumentValue",
        FT_UINT32, BASE_DEC, VALS(cmip_InvalidArgumentValue_vals), 0,
        "cmip.InvalidArgumentValue", HFILL }},
    { &hf_cmip_actionInfoArg,
      { "actionInfoArg", "cmip.actionInfoArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.T_actionInfoArg", HFILL }},
    { &hf_cmip_actionReplyInfo,
      { "actionReplyInfo", "cmip.actionReplyInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.T_actionReplyInfo", HFILL }},
    { &hf_cmip_actionReply,
      { "actionReply", "cmip.actionReply",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.ActionReply", HFILL }},
    { &hf_cmip_globalForm,
      { "globalForm", "cmip.globalForm",
        FT_OID, BASE_NONE, NULL, 0,
        "cmip.T_globalForm", HFILL }},
    { &hf_cmip_localForm,
      { "localForm", "cmip.localForm",
        FT_INT32, BASE_DEC, NULL, 0,
        "cmip.INTEGER", HFILL }},
    { &hf_cmip_id,
      { "id", "cmip.id",
        FT_UINT32, BASE_DEC, VALS(cmip_AttributeId_vals), 0,
        "cmip.AttributeId", HFILL }},
    { &hf_cmip_value,
      { "value", "cmip.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.T_value", HFILL }},
    { &hf_cmip_errorStatus_01,
      { "errorStatus", "cmip.errorStatus",
        FT_UINT32, BASE_DEC, VALS(cmip_T_errorStatus_01_vals), 0,
        "cmip.T_errorStatus_01", HFILL }},
    { &hf_cmip_modifyOperator,
      { "modifyOperator", "cmip.modifyOperator",
        FT_INT32, BASE_DEC, VALS(cmip_ModifyOperator_vals), 0,
        "cmip.ModifyOperator", HFILL }},
    { &hf_cmip_attributeId,
      { "attributeId", "cmip.attributeId",
        FT_UINT32, BASE_DEC, VALS(cmip_AttributeId_vals), 0,
        "cmip.AttributeId", HFILL }},
    { &hf_cmip_attributeValue,
      { "attributeValue", "cmip.attributeValue",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.T_attributeValue", HFILL }},
    { &hf_cmip_globalForm_01,
      { "globalForm", "cmip.globalForm",
        FT_OID, BASE_NONE, NULL, 0,
        "cmip.T_globalForm_01", HFILL }},
    { &hf_cmip_localForm_01,
      { "localForm", "cmip.localForm",
        FT_INT32, BASE_DEC, NULL, 0,
        "cmip.T_localForm", HFILL }},
    { &hf_cmip_errorStatus_02,
      { "errorStatus", "cmip.errorStatus",
        FT_UINT32, BASE_DEC, VALS(cmip_T_errorStatus_02_vals), 0,
        "cmip.T_errorStatus_02", HFILL }},
    { &hf_cmip_id_01,
      { "id", "cmip.id",
        FT_OID, BASE_NONE, NULL, 0,
        "cmip.T_id", HFILL }},
    { &hf_cmip_value_01,
      { "value", "cmip.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.T_value_01", HFILL }},
    { &hf_cmip_baseManagedObjectClass,
      { "baseManagedObjectClass", "cmip.baseManagedObjectClass",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectClass_vals), 0,
        "cmip.ObjectClass", HFILL }},
    { &hf_cmip_baseManagedObjectInstance,
      { "baseManagedObjectInstance", "cmip.baseManagedObjectInstance",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "cmip.ObjectInstance", HFILL }},
    { &hf_cmip_item,
      { "item", "cmip.item",
        FT_UINT32, BASE_DEC, VALS(cmip_FilterItem_vals), 0,
        "cmip.FilterItem", HFILL }},
    { &hf_cmip_and,
      { "and", "cmip.and",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmip.SET_OF_CMISFilter", HFILL }},
    { &hf_cmip_and_item,
      { "Item", "cmip.and_item",
        FT_UINT32, BASE_DEC, VALS(cmip_CMISFilter_vals), 0,
        "cmip.CMISFilter", HFILL }},
    { &hf_cmip_or,
      { "or", "cmip.or",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmip.SET_OF_CMISFilter", HFILL }},
    { &hf_cmip_or_item,
      { "Item", "cmip.or_item",
        FT_UINT32, BASE_DEC, VALS(cmip_CMISFilter_vals), 0,
        "cmip.CMISFilter", HFILL }},
    { &hf_cmip_not,
      { "not", "cmip.not",
        FT_UINT32, BASE_DEC, VALS(cmip_CMISFilter_vals), 0,
        "cmip.CMISFilter", HFILL }},
    { &hf_cmip_scope,
      { "scope", "cmip.scope",
        FT_UINT32, BASE_DEC, VALS(cmip_Scope_vals), 0,
        "cmip.Scope", HFILL }},
    { &hf_cmip_filter,
      { "filter", "cmip.filter",
        FT_UINT32, BASE_DEC, VALS(cmip_CMISFilter_vals), 0,
        "cmip.CMISFilter", HFILL }},
    { &hf_cmip_sync,
      { "sync", "cmip.sync",
        FT_UINT32, BASE_DEC, VALS(cmip_CMISSync_vals), 0,
        "cmip.CMISSync", HFILL }},
    { &hf_cmip_managedOrSuperiorObjectInstance,
      { "managedOrSuperiorObjectInstance", "cmip.managedOrSuperiorObjectInstance",
        FT_UINT32, BASE_DEC, VALS(cmip_T_managedOrSuperiorObjectInstance_vals), 0,
        "cmip.T_managedOrSuperiorObjectInstance", HFILL }},
    { &hf_cmip_superiorObjectInstance,
      { "superiorObjectInstance", "cmip.superiorObjectInstance",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "cmip.ObjectInstance", HFILL }},
    { &hf_cmip_accessControl,
      { "accessControl", "cmip.accessControl",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.AccessControl", HFILL }},
    { &hf_cmip_referenceObjectInstance,
      { "referenceObjectInstance", "cmip.referenceObjectInstance",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "cmip.ObjectInstance", HFILL }},
    { &hf_cmip_attributeList,
      { "attributeList", "cmip.attributeList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmip.SET_OF_Attribute", HFILL }},
    { &hf_cmip_attributeList_item,
      { "Item", "cmip.attributeList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.Attribute", HFILL }},
    { &hf_cmip_deleteErrorInfo,
      { "deleteErrorInfo", "cmip.deleteErrorInfo",
        FT_UINT32, BASE_DEC, VALS(cmip_T_deleteErrorInfo_vals), 0,
        "cmip.T_deleteErrorInfo", HFILL }},
    { &hf_cmip_eventType,
      { "eventType", "cmip.eventType",
        FT_UINT32, BASE_DEC, VALS(cmip_EventTypeId_vals), 0,
        "cmip.EventTypeId", HFILL }},
    { &hf_cmip_eventReplyInfo,
      { "eventReplyInfo", "cmip.eventReplyInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.T_eventReplyInfo", HFILL }},
    { &hf_cmip_eventTime,
      { "eventTime", "cmip.eventTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "cmip.GeneralizedTime", HFILL }},
    { &hf_cmip_eventInfo,
      { "eventInfo", "cmip.eventInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.T_eventInfo", HFILL }},
    { &hf_cmip_eventReply,
      { "eventReply", "cmip.eventReply",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.EventReply", HFILL }},
    { &hf_cmip_globalForm_02,
      { "globalForm", "cmip.globalForm",
        FT_OID, BASE_NONE, NULL, 0,
        "cmip.T_globalForm_02", HFILL }},
    { &hf_cmip_equality,
      { "equality", "cmip.equality",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.Attribute", HFILL }},
    { &hf_cmip_substrings,
      { "substrings", "cmip.substrings",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmip.T_substrings", HFILL }},
    { &hf_cmip_substrings_item,
      { "Item", "cmip.substrings_item",
        FT_UINT32, BASE_DEC, VALS(cmip_T_substrings_item_vals), 0,
        "cmip.T_substrings_item", HFILL }},
    { &hf_cmip_initialString,
      { "initialString", "cmip.initialString",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.Attribute", HFILL }},
    { &hf_cmip_anyString,
      { "anyString", "cmip.anyString",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.Attribute", HFILL }},
    { &hf_cmip_finalString,
      { "finalString", "cmip.finalString",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.Attribute", HFILL }},
    { &hf_cmip_greaterOrEqual,
      { "greaterOrEqual", "cmip.greaterOrEqual",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.Attribute", HFILL }},
    { &hf_cmip_lessOrEqual,
      { "lessOrEqual", "cmip.lessOrEqual",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.Attribute", HFILL }},
    { &hf_cmip_present,
      { "present", "cmip.present",
        FT_UINT32, BASE_DEC, VALS(cmip_AttributeId_vals), 0,
        "cmip.AttributeId", HFILL }},
    { &hf_cmip_subsetOf,
      { "subsetOf", "cmip.subsetOf",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.Attribute", HFILL }},
    { &hf_cmip_supersetOf,
      { "supersetOf", "cmip.supersetOf",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.Attribute", HFILL }},
    { &hf_cmip_nonNullSetIntersection,
      { "nonNullSetIntersection", "cmip.nonNullSetIntersection",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.Attribute", HFILL }},
    { &hf_cmip_attributeIdError,
      { "attributeIdError", "cmip.attributeIdError",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.AttributeIdError", HFILL }},
    { &hf_cmip_attribute,
      { "attribute", "cmip.attribute",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.Attribute", HFILL }},
    { &hf_cmip_getInfoList,
      { "getInfoList", "cmip.getInfoList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmip.SET_OF_GetInfoStatus", HFILL }},
    { &hf_cmip_getInfoList_item,
      { "Item", "cmip.getInfoList_item",
        FT_UINT32, BASE_DEC, VALS(cmip_GetInfoStatus_vals), 0,
        "cmip.GetInfoStatus", HFILL }},
    { &hf_cmip_actionValue,
      { "actionValue", "cmip.actionValue",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.ActionInfo", HFILL }},
    { &hf_cmip_eventValue,
      { "eventValue", "cmip.eventValue",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.T_eventValue", HFILL }},
    { &hf_cmip_eventInfo_01,
      { "eventInfo", "cmip.eventInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.T_eventInfo_01", HFILL }},
    { &hf_cmip_getResult,
      { "getResult", "cmip.getResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.GetResult", HFILL }},
    { &hf_cmip_getListError,
      { "getListError", "cmip.getListError",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.GetListError", HFILL }},
    { &hf_cmip_setResult,
      { "setResult", "cmip.setResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.SetResult", HFILL }},
    { &hf_cmip_setListError,
      { "setListError", "cmip.setListError",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.SetListError", HFILL }},
    { &hf_cmip_actionResult,
      { "actionResult", "cmip.actionResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.ActionResult", HFILL }},
    { &hf_cmip_processingFailure,
      { "processingFailure", "cmip.processingFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.ProcessingFailure", HFILL }},
    { &hf_cmip_deleteResult,
      { "deleteResult", "cmip.deleteResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.DeleteResult", HFILL }},
    { &hf_cmip_actionError,
      { "actionError", "cmip.actionError",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.ActionError", HFILL }},
    { &hf_cmip_deleteError,
      { "deleteError", "cmip.deleteError",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.DeleteError", HFILL }},
    { &hf_cmip_actionId,
      { "actionId", "cmip.actionId",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.T_actionId", HFILL }},
    { &hf_cmip_eventId,
      { "eventId", "cmip.eventId",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.T_eventId", HFILL }},
    { &hf_cmip_globalForm_03,
      { "globalForm", "cmip.globalForm",
        FT_OID, BASE_NONE, NULL, 0,
        "cmip.T_globalForm_03", HFILL }},
    { &hf_cmip_localForm_02,
      { "localForm", "cmip.localForm",
        FT_INT32, BASE_DEC, NULL, 0,
        "cmip.T_localForm_01", HFILL }},
    { &hf_cmip_distinguishedName,
      { "distinguishedName", "cmip.distinguishedName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmip.DistinguishedName", HFILL }},
    { &hf_cmip_nonSpecificForm,
      { "nonSpecificForm", "cmip.nonSpecificForm",
        FT_BYTES, BASE_HEX, NULL, 0,
        "cmip.OCTET_STRING", HFILL }},
    { &hf_cmip_localDistinguishedName,
      { "localDistinguishedName", "cmip.localDistinguishedName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmip.RDNSequence", HFILL }},
    { &hf_cmip_specificErrorInfo,
      { "specificErrorInfo", "cmip.specificErrorInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.SpecificErrorInfo", HFILL }},
    { &hf_cmip_RDNSequence_item,
      { "Item", "cmip.RDNSequence_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmip.RelativeDistinguishedName", HFILL }},
    { &hf_cmip_RelativeDistinguishedName_item,
      { "Item", "cmip.RelativeDistinguishedName_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.AttributeValueAssertion", HFILL }},
    { &hf_cmip_namedNumbers,
      { "namedNumbers", "cmip.namedNumbers",
        FT_INT32, BASE_DEC, VALS(cmip_T_namedNumbers_vals), 0,
        "cmip.T_namedNumbers", HFILL }},
    { &hf_cmip_individualLevels,
      { "individualLevels", "cmip.individualLevels",
        FT_INT32, BASE_DEC, NULL, 0,
        "cmip.INTEGER", HFILL }},
    { &hf_cmip_baseToNthLevel,
      { "baseToNthLevel", "cmip.baseToNthLevel",
        FT_INT32, BASE_DEC, NULL, 0,
        "cmip.INTEGER", HFILL }},
    { &hf_cmip_attributeError,
      { "attributeError", "cmip.attributeError",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.AttributeError", HFILL }},
    { &hf_cmip_setInfoList,
      { "setInfoList", "cmip.setInfoList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmip.SET_OF_SetInfoStatus", HFILL }},
    { &hf_cmip_setInfoList_item,
      { "Item", "cmip.setInfoList_item",
        FT_UINT32, BASE_DEC, VALS(cmip_SetInfoStatus_vals), 0,
        "cmip.SetInfoStatus", HFILL }},
    { &hf_cmip_errorId,
      { "errorId", "cmip.errorId",
        FT_OID, BASE_NONE, NULL, 0,
        "cmip.T_errorId", HFILL }},
    { &hf_cmip_errorInfo_01,
      { "errorInfo", "cmip.errorInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.T_errorInfo_01", HFILL }},
    { &hf_cmip_abortSource,
      { "abortSource", "cmip.abortSource",
        FT_UINT32, BASE_DEC, VALS(cmip_CMIPAbortSource_vals), 0,
        "cmip.CMIPAbortSource", HFILL }},
    { &hf_cmip_userInfo,
      { "userInfo", "cmip.userInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.EXTERNAL", HFILL }},
    { &hf_cmip_protocolVersion,
      { "protocolVersion", "cmip.protocolVersion",
        FT_BYTES, BASE_HEX, NULL, 0,
        "cmip.ProtocolVersion", HFILL }},
    { &hf_cmip_functionalUnits,
      { "functionalUnits", "cmip.functionalUnits",
        FT_BYTES, BASE_HEX, NULL, 0,
        "cmip.FunctionalUnits", HFILL }},
    { &hf_cmip_accessControl_01,
      { "accessControl", "cmip.accessControl",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.EXTERNAL", HFILL }},
    { &hf_cmip_AdditionalInformation_item,
      { "Item", "cmip.AdditionalInformation_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.ManagementExtension", HFILL }},
    { &hf_cmip_Allomorphs_item,
      { "Item", "cmip.Allomorphs_item",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectClass_vals), 0,
        "cmip.ObjectClass", HFILL }},
    { &hf_cmip_AttributeIdentifierList_item,
      { "Item", "cmip.AttributeIdentifierList_item",
        FT_UINT32, BASE_DEC, VALS(cmip_AttributeId_vals), 0,
        "cmip.AttributeId", HFILL }},
    { &hf_cmip_AttributeList_item,
      { "Item", "cmip.AttributeList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.Attribute", HFILL }},
    { &hf_cmip_AttributeValueChangeDefinition_item,
      { "Item", "cmip.AttributeValueChangeDefinition_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.AttributeValueChangeDefinition_item", HFILL }},
    { &hf_cmip_oldAttributeValue,
      { "oldAttributeValue", "cmip.oldAttributeValue",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.T_oldAttributeValue", HFILL }},
    { &hf_cmip_newAttributeValue,
      { "newAttributeValue", "cmip.newAttributeValue",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.T_newAttributeValue", HFILL }},
    { &hf_cmip_AlarmStatus_item,
      { "Item", "cmip.AlarmStatus_item",
        FT_INT32, BASE_DEC, VALS(cmip_AlarmStatus_item_vals), 0,
        "cmip.AlarmStatus_item", HFILL }},
    { &hf_cmip_AvailabilityStatus_item,
      { "Item", "cmip.AvailabilityStatus_item",
        FT_INT32, BASE_DEC, VALS(cmip_AvailabilityStatus_item_vals), 0,
        "cmip.AvailabilityStatus_item", HFILL }},
    { &hf_cmip_BackUpDestinationList_item,
      { "Item", "cmip.BackUpDestinationList_item",
        FT_UINT32, BASE_DEC, VALS(acse_AE_title_vals), 0,
        "acse.AE_title", HFILL }},
    { &hf_cmip_objectName,
      { "objectName", "cmip.objectName",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "cmip.ObjectInstance", HFILL }},
    { &hf_cmip_noObject,
      { "noObject", "cmip.noObject",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.NULL", HFILL }},
    { &hf_cmip_CapacityAlarmThreshold_item,
      { "Item", "cmip.CapacityAlarmThreshold_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmip.INTEGER_0_100", HFILL }},
    { &hf_cmip_ControlStatus_item,
      { "Item", "cmip.ControlStatus_item",
        FT_INT32, BASE_DEC, VALS(cmip_ControlStatus_item_vals), 0,
        "cmip.ControlStatus_item", HFILL }},
    { &hf_cmip_CounterThreshold_item,
      { "Item", "cmip.CounterThreshold_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.CounterThreshold_item", HFILL }},
    { &hf_cmip_comparisonLevel,
      { "comparisonLevel", "cmip.comparisonLevel",
        FT_INT32, BASE_DEC, NULL, 0,
        "cmip.INTEGER", HFILL }},
    { &hf_cmip_offsetValue,
      { "offsetValue", "cmip.offsetValue",
        FT_INT32, BASE_DEC, NULL, 0,
        "cmip.INTEGER", HFILL }},
    { &hf_cmip_notificationOnOff,
      { "notificationOnOff", "cmip.notificationOnOff",
        FT_BOOLEAN, 8, NULL, 0,
        "cmip.BOOLEAN", HFILL }},
    { &hf_cmip_CorrelatedNotifications_item,
      { "Item", "cmip.CorrelatedNotifications_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.CorrelatedNotifications_item", HFILL }},
    { &hf_cmip_correlatedNotifications,
      { "correlatedNotifications", "cmip.correlatedNotifications",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmip.SET_OF_NotificationIdentifier", HFILL }},
    { &hf_cmip_correlatedNotifications_item,
      { "Item", "cmip.correlatedNotifications_item",
        FT_INT32, BASE_DEC, NULL, 0,
        "cmip.NotificationIdentifier", HFILL }},
    { &hf_cmip_sourceObjectInst,
      { "sourceObjectInst", "cmip.sourceObjectInst",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "cmip.ObjectInstance", HFILL }},
    { &hf_cmip_single,
      { "single", "cmip.single",
        FT_UINT32, BASE_DEC, VALS(acse_AE_title_vals), 0,
        "acse.AE_title", HFILL }},
    { &hf_cmip_multiple,
      { "multiple", "cmip.multiple",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmip.SET_OF_AE_title", HFILL }},
    { &hf_cmip_multiple_item,
      { "Item", "cmip.multiple_item",
        FT_UINT32, BASE_DEC, VALS(acse_AE_title_vals), 0,
        "acse.AE_title", HFILL }},
    { &hf_cmip_GaugeThreshold_item,
      { "Item", "cmip.GaugeThreshold_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.GaugeThreshold_item", HFILL }},
    { &hf_cmip_notifyLow,
      { "notifyLow", "cmip.notifyLow",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.NotifyThreshold", HFILL }},
    { &hf_cmip_notifyHigh,
      { "notifyHigh", "cmip.notifyHigh",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.NotifyThreshold", HFILL }},
    { &hf_cmip_GroupObjects_item,
      { "Item", "cmip.GroupObjects_item",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "cmip.ObjectInstance", HFILL }},
    { &hf_cmip_IntervalsOfDay_item,
      { "Item", "cmip.IntervalsOfDay_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.IntervalsOfDay_item", HFILL }},
    { &hf_cmip_intervalStart,
      { "intervalStart", "cmip.intervalStart",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.Time24", HFILL }},
    { &hf_cmip_intervalEnd,
      { "intervalEnd", "cmip.intervalEnd",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.Time24", HFILL }},
    { &hf_cmip_identifier,
      { "identifier", "cmip.identifier",
        FT_OID, BASE_NONE, NULL, 0,
        "cmip.T_identifier", HFILL }},
    { &hf_cmip_significance,
      { "significance", "cmip.significance",
        FT_BOOLEAN, 8, NULL, 0,
        "cmip.BOOLEAN", HFILL }},
    { &hf_cmip_information,
      { "information", "cmip.information",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.T_information", HFILL }},
    { &hf_cmip_MonitoredAttributes_item,
      { "Item", "cmip.MonitoredAttributes_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.Attribute", HFILL }},
    { &hf_cmip_threshold,
      { "threshold", "cmip.threshold",
        FT_UINT32, BASE_DEC, VALS(cmip_ObservedValue_vals), 0,
        "cmip.ObservedValue", HFILL }},
    { &hf_cmip_notifyOnOff,
      { "notifyOnOff", "cmip.notifyOnOff",
        FT_BOOLEAN, 8, NULL, 0,
        "cmip.BOOLEAN", HFILL }},
    { &hf_cmip_integer,
      { "integer", "cmip.integer",
        FT_INT32, BASE_DEC, NULL, 0,
        "cmip.INTEGER", HFILL }},
    { &hf_cmip_real,
      { "real", "cmip.real",
        FT_DOUBLE, BASE_NONE, NULL, 0,
        "cmip.REAL", HFILL }},
    { &hf_cmip_Packages_item,
      { "Item", "cmip.Packages_item",
        FT_OID, BASE_NONE, NULL, 0,
        "cmip.OBJECT_IDENTIFIER", HFILL }},
    { &hf_cmip_PrioritisedObject_item,
      { "Item", "cmip.PrioritisedObject_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.PrioritisedObject_item", HFILL }},
    { &hf_cmip_object,
      { "object", "cmip.object",
        FT_UINT32, BASE_DEC, VALS(cmip_ObjectInstance_vals), 0,
        "cmip.ObjectInstance", HFILL }},
    { &hf_cmip_priority,
      { "priority", "cmip.priority",
        FT_INT32, BASE_DEC, VALS(cmip_T_priority_vals), 0,
        "cmip.T_priority", HFILL }},
    { &hf_cmip_globalValue,
      { "globalValue", "cmip.globalValue",
        FT_OID, BASE_NONE, NULL, 0,
        "cmip.OBJECT_IDENTIFIER", HFILL }},
    { &hf_cmip_localValue,
      { "localValue", "cmip.localValue",
        FT_INT32, BASE_DEC, NULL, 0,
        "cmip.INTEGER", HFILL }},
    { &hf_cmip_ProceduralStatus_item,
      { "Item", "cmip.ProceduralStatus_item",
        FT_INT32, BASE_DEC, VALS(cmip_ProceduralStatus_item_vals), 0,
        "cmip.ProceduralStatus_item", HFILL }},
    { &hf_cmip_ProposedRepairActions_item,
      { "Item", "cmip.ProposedRepairActions_item",
        FT_UINT32, BASE_DEC, VALS(cmip_SpecificIdentifier_vals), 0,
        "cmip.SpecificIdentifier", HFILL }},
    { &hf_cmip_mechanism,
      { "mechanism", "cmip.mechanism",
        FT_OID, BASE_NONE, NULL, 0,
        "cmip.OBJECT_IDENTIFIER", HFILL }},
    { &hf_cmip_application,
      { "application", "cmip.application",
        FT_UINT32, BASE_DEC, VALS(acse_AE_title_vals), 0,
        "acse.AE_title", HFILL }},
    { &hf_cmip_identifier_01,
      { "identifier", "cmip.identifier",
        FT_OID, BASE_NONE, NULL, 0,
        "cmip.T_identifier_01", HFILL }},
    { &hf_cmip_details,
      { "details", "cmip.details",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.T_details", HFILL }},
    { &hf_cmip_number,
      { "number", "cmip.number",
        FT_INT32, BASE_DEC, NULL, 0,
        "cmip.INTEGER", HFILL }},
    { &hf_cmip_string,
      { "string", "cmip.string",
        FT_STRING, BASE_NONE, NULL, 0,
        "cmip.GraphicString", HFILL }},
    { &hf_cmip_oi,
      { "oi", "cmip.oi",
        FT_OID, BASE_NONE, NULL, 0,
        "cmip.OBJECT_IDENTIFIER", HFILL }},
    { &hf_cmip_int,
      { "int", "cmip.int",
        FT_INT32, BASE_DEC, NULL, 0,
        "cmip.INTEGER", HFILL }},
    { &hf_cmip_SpecificProblems_item,
      { "Item", "cmip.SpecificProblems_item",
        FT_UINT32, BASE_DEC, VALS(cmip_SpecificIdentifier_vals), 0,
        "cmip.SpecificIdentifier", HFILL }},
    { &hf_cmip_specific,
      { "specific", "cmip.specific",
        FT_STRING, BASE_NONE, NULL, 0,
        "cmip.GeneralizedTime", HFILL }},
    { &hf_cmip_continual,
      { "continual", "cmip.continual",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.NULL", HFILL }},
    { &hf_cmip_SupportedFeatures_item,
      { "Item", "cmip.SupportedFeatures_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.SupportedFeatures_item", HFILL }},
    { &hf_cmip_featureIdentifier,
      { "featureIdentifier", "cmip.featureIdentifier",
        FT_OID, BASE_NONE, NULL, 0,
        "cmip.T_featureIdentifier", HFILL }},
    { &hf_cmip_featureInfo,
      { "featureInfo", "cmip.featureInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.T_featureInfo", HFILL }},
    { &hf_cmip_name,
      { "name", "cmip.name",
        FT_STRING, BASE_NONE, NULL, 0,
        "cmip.GraphicString", HFILL }},
    { &hf_cmip_nothing,
      { "nothing", "cmip.nothing",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.NULL", HFILL }},
    { &hf_cmip_oid,
      { "oid", "cmip.oid",
        FT_OID, BASE_NONE, NULL, 0,
        "cmip.OBJECT_IDENTIFIER", HFILL }},
    { &hf_cmip_currentTideMark,
      { "currentTideMark", "cmip.currentTideMark",
        FT_UINT32, BASE_DEC, VALS(cmip_TideMark_vals), 0,
        "cmip.TideMark", HFILL }},
    { &hf_cmip_previousTideMark,
      { "previousTideMark", "cmip.previousTideMark",
        FT_UINT32, BASE_DEC, VALS(cmip_TideMark_vals), 0,
        "cmip.TideMark", HFILL }},
    { &hf_cmip_resetTime,
      { "resetTime", "cmip.resetTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "cmip.GeneralizedTime", HFILL }},
    { &hf_cmip_maxTideMar,
      { "maxTideMar", "cmip.maxTideMar",
        FT_UINT32, BASE_DEC, VALS(cmip_ObservedValue_vals), 0,
        "cmip.ObservedValue", HFILL }},
    { &hf_cmip_minTideMark,
      { "minTideMark", "cmip.minTideMark",
        FT_UINT32, BASE_DEC, VALS(cmip_ObservedValue_vals), 0,
        "cmip.ObservedValue", HFILL }},
    { &hf_cmip_hour,
      { "hour", "cmip.hour",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmip.INTEGER_0_23", HFILL }},
    { &hf_cmip_minute,
      { "minute", "cmip.minute",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmip.INTEGER_0_59", HFILL }},
    { &hf_cmip_triggeredThreshold,
      { "triggeredThreshold", "cmip.triggeredThreshold",
        FT_UINT32, BASE_DEC, VALS(cmip_AttributeId_vals), 0,
        "cmip.AttributeId", HFILL }},
    { &hf_cmip_observedValue,
      { "observedValue", "cmip.observedValue",
        FT_UINT32, BASE_DEC, VALS(cmip_ObservedValue_vals), 0,
        "cmip.ObservedValue", HFILL }},
    { &hf_cmip_thresholdLevel,
      { "thresholdLevel", "cmip.thresholdLevel",
        FT_UINT32, BASE_DEC, VALS(cmip_ThresholdLevelInd_vals), 0,
        "cmip.ThresholdLevelInd", HFILL }},
    { &hf_cmip_armTime,
      { "armTime", "cmip.armTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "cmip.GeneralizedTime", HFILL }},
    { &hf_cmip_up,
      { "up", "cmip.up",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.T_up", HFILL }},
    { &hf_cmip_high,
      { "high", "cmip.high",
        FT_UINT32, BASE_DEC, VALS(cmip_ObservedValue_vals), 0,
        "cmip.ObservedValue", HFILL }},
    { &hf_cmip_low,
      { "low", "cmip.low",
        FT_UINT32, BASE_DEC, VALS(cmip_ObservedValue_vals), 0,
        "cmip.ObservedValue", HFILL }},
    { &hf_cmip_down,
      { "down", "cmip.down",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.T_down", HFILL }},
    { &hf_cmip_WeekMask_item,
      { "Item", "cmip.WeekMask_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.WeekMask_item", HFILL }},
    { &hf_cmip_daysOfWeek,
      { "daysOfWeek", "cmip.daysOfWeek",
        FT_BYTES, BASE_HEX, NULL, 0,
        "cmip.T_daysOfWeek", HFILL }},
    { &hf_cmip_intervalsOfDay,
      { "intervalsOfDay", "cmip.intervalsOfDay",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmip.IntervalsOfDay", HFILL }},
    { &hf_cmip_local,
      { "local", "cmip.local",
        FT_INT32, BASE_DEC, NULL, 0,
        "cmip.T_local", HFILL }},
    { &hf_cmip_global,
      { "global", "cmip.global",
        FT_OID, BASE_NONE, NULL, 0,
        "cmip.OBJECT_IDENTIFIER", HFILL }},
    { &hf_cmip_invoke,
      { "invoke", "cmip.invoke",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.Invoke", HFILL }},
    { &hf_cmip_returnResult,
      { "returnResult", "cmip.returnResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.ReturnResult", HFILL }},
    { &hf_cmip_returnError,
      { "returnError", "cmip.returnError",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.ReturnError", HFILL }},
    { &hf_cmip_reject,
      { "reject", "cmip.reject",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.Reject", HFILL }},
    { &hf_cmip_invokeId,
      { "invokeId", "cmip.invokeId",
        FT_UINT32, BASE_DEC, VALS(cmip_InvokeId_vals), 0,
        "cmip.InvokeId", HFILL }},
    { &hf_cmip_linkedId,
      { "linkedId", "cmip.linkedId",
        FT_UINT32, BASE_DEC, VALS(cmip_T_linkedId_vals), 0,
        "cmip.T_linkedId", HFILL }},
    { &hf_cmip_linkedIdPresent,
      { "present", "cmip.present",
        FT_INT32, BASE_DEC, NULL, 0,
        "cmip.T_linkedIdPresent", HFILL }},
    { &hf_cmip_absent,
      { "absent", "cmip.absent",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.NULL", HFILL }},
    { &hf_cmip_opcode,
      { "opcode", "cmip.opcode",
        FT_UINT32, BASE_DEC, VALS(cmip_Code_vals), 0,
        "cmip.Code", HFILL }},
    { &hf_cmip_argument,
      { "argument", "cmip.argument",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.InvokeArgument", HFILL }},
    { &hf_cmip_result,
      { "result", "cmip.result",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.T_result", HFILL }},
    { &hf_cmip_resultArgument,
      { "result", "cmip.result",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.ResultArgument", HFILL }},
    { &hf_cmip_errcode,
      { "errcode", "cmip.errcode",
        FT_UINT32, BASE_DEC, VALS(cmip_Code_vals), 0,
        "cmip.Code", HFILL }},
    { &hf_cmip_parameter,
      { "parameter", "cmip.parameter",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.T_parameter", HFILL }},
    { &hf_cmip_problem,
      { "problem", "cmip.problem",
        FT_UINT32, BASE_DEC, VALS(cmip_T_problem_vals), 0,
        "cmip.T_problem", HFILL }},
    { &hf_cmip_general,
      { "general", "cmip.general",
        FT_INT32, BASE_DEC, VALS(cmip_GeneralProblem_vals), 0,
        "cmip.GeneralProblem", HFILL }},
    { &hf_cmip_invokeProblem,
      { "invoke", "cmip.invoke",
        FT_INT32, BASE_DEC, VALS(cmip_InvokeProblem_vals), 0,
        "cmip.InvokeProblem", HFILL }},
    { &hf_cmip_returnResultProblem,
      { "returnResult", "cmip.returnResult",
        FT_INT32, BASE_DEC, VALS(cmip_ReturnResultProblem_vals), 0,
        "cmip.ReturnResultProblem", HFILL }},
    { &hf_cmip_returnErrorProblem,
      { "returnError", "cmip.returnError",
        FT_INT32, BASE_DEC, VALS(cmip_ReturnErrorProblem_vals), 0,
        "cmip.ReturnErrorProblem", HFILL }},
    { &hf_cmip_present_01,
      { "present", "cmip.present",
        FT_INT32, BASE_DEC, NULL, 0,
        "cmip.INTEGER", HFILL }},
    { &hf_cmip_synchronization,
      { "synchronization", "cmip.synchronization",
        FT_UINT32, BASE_DEC, VALS(cmip_CMISSync_vals), 0,
        "cmip.CMISSync", HFILL }},
    { &hf_cmip_actionInfo,
      { "actionInfo", "cmip.actionInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.ActionInfo", HFILL }},
    { &hf_cmip_attributeIdList,
      { "attributeIdList", "cmip.attributeIdList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmip.SET_OF_AttributeId", HFILL }},
    { &hf_cmip_attributeIdList_item,
      { "Item", "cmip.attributeIdList_item",
        FT_UINT32, BASE_DEC, VALS(cmip_AttributeId_vals), 0,
        "cmip.AttributeId", HFILL }},
    { &hf_cmip_modificationList,
      { "modificationList", "cmip.modificationList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cmip.T_modificationList", HFILL }},
    { &hf_cmip_modificationList_item,
      { "Item", "cmip.modificationList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.T_modificationList_item", HFILL }},
    { &hf_cmip_attributevalue,
      { "attributeValue", "cmip.attributeValue",
        FT_NONE, BASE_NONE, NULL, 0,
        "cmip.T_attributevalue", HFILL }},
    { &hf_cmip_InvokeId_present,
      { "InvokeId.present", "cmip.InvokeId_present",
        FT_INT32, BASE_DEC, NULL, 0,
        "cmip.InvokeId_present", HFILL }},
    { &hf_cmip_FunctionalUnits_multipleObjectSelection,
      { "multipleObjectSelection", "cmip.multipleObjectSelection",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_cmip_FunctionalUnits_filter,
      { "filter", "cmip.filter",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_cmip_FunctionalUnits_multipleReply,
      { "multipleReply", "cmip.multipleReply",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_cmip_FunctionalUnits_extendedService,
      { "extendedService", "cmip.extendedService",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_cmip_FunctionalUnits_cancelGet,
      { "cancelGet", "cmip.cancelGet",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_cmip_ProtocolVersion_version1,
      { "version1", "cmip.version1",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_cmip_ProtocolVersion_version2,
      { "version2", "cmip.version2",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_cmip_T_daysOfWeek_sunday,
      { "sunday", "cmip.sunday",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_cmip_T_daysOfWeek_monday,
      { "monday", "cmip.monday",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_cmip_T_daysOfWeek_tuesday,
      { "tuesday", "cmip.tuesday",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_cmip_T_daysOfWeek_wednesday,
      { "wednesday", "cmip.wednesday",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_cmip_T_daysOfWeek_thursday,
      { "thursday", "cmip.thursday",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_cmip_T_daysOfWeek_friday,
      { "friday", "cmip.friday",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_cmip_T_daysOfWeek_saturday,
      { "saturday", "cmip.saturday",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},

/*--- End of included file: packet-cmip-hfarr.c ---*/
#line 207 "packet-cmip-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_cmip,

/*--- Included file: packet-cmip-ettarr.c ---*/
#line 1 "packet-cmip-ettarr.c"
    &ett_cmip_ActionArgument,
    &ett_cmip_ActionError,
    &ett_cmip_ActionErrorInfo,
    &ett_cmip_T_errorInfo,
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
    &ett_cmip_CounterThreshold,
    &ett_cmip_CounterThreshold_item,
    &ett_cmip_CorrelatedNotifications,
    &ett_cmip_CorrelatedNotifications_item,
    &ett_cmip_SET_OF_NotificationIdentifier,
    &ett_cmip_Destination,
    &ett_cmip_SET_OF_AE_title,
    &ett_cmip_GaugeThreshold,
    &ett_cmip_GaugeThreshold_item,
    &ett_cmip_GroupObjects,
    &ett_cmip_IntervalsOfDay,
    &ett_cmip_IntervalsOfDay_item,
    &ett_cmip_ManagementExtension,
    &ett_cmip_MonitoredAttributes,
    &ett_cmip_NotifyThreshold,
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
    &ett_cmip_TideMarkInfo,
    &ett_cmip_TideMark,
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

/*--- End of included file: packet-cmip-ettarr.c ---*/
#line 213 "packet-cmip-template.c"
  };

  /* Register protocol */
  proto_cmip = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_cmip, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

/*--- Included file: packet-cmip-dis-tab.c ---*/
#line 1 "packet-cmip-dis-tab.c"
  register_ber_oid_dissector("2.9.3.2.7.3", dissect_LogRecordId_PDU, proto_cmip, "logRecordId(3)");
  register_ber_oid_dissector("2.9.3.2.7.4", dissect_SystemId_PDU, proto_cmip, "systemId(4)");
  register_ber_oid_dissector("2.9.3.2.7.5", dissect_SystemTitle_PDU, proto_cmip, "systemTitle(5)");
  register_ber_oid_dissector("2.9.3.2.7.7", dissect_AdditionalText_PDU, proto_cmip, "additionalText(7)");
  register_ber_oid_dissector("2.9.3.2.7.11", dissect_BackedUpStatus_PDU, proto_cmip, "backedUpStatus(11)");
  register_ber_oid_dissector("2.9.3.2.7.39", dissect_UsageState_PDU, proto_cmip, "usageState(39)");
  register_ber_oid_dissector("2.9.3.2.7.35", dissect_OperationalState_PDU, proto_cmip, "operationalState(35)");
  register_ber_oid_dissector("2.9.3.2.7.50", dissect_Allomorphs_PDU, proto_cmip, "allomorphs(50)");
  register_ber_oid_dissector("2.9.3.2.7.55", dissect_Destination_PDU, proto_cmip, "destination(55)");
  register_ber_oid_dissector("2.9.3.2.7.56", dissect_DiscriminatorConstruct_PDU, proto_cmip, "discriminatorConstruct(56)");
  register_ber_oid_dissector("2.9.3.2.7.63", dissect_NameBinding_PDU, proto_cmip, "nameBinding(63)");
  register_ber_oid_dissector("2.9.3.2.7.65", dissect_ObjectClass_PDU, proto_cmip, "objectClass(65)");


/*--- End of included file: packet-cmip-dis-tab.c ---*/
#line 222 "packet-cmip-template.c"
    add_oid_str_name("2.9.3.2.7.1","discriminatorId(1) ");

}


/*--- proto_reg_handoff_cmip -------------------------------------------*/
void proto_reg_handoff_cmip(void) {
	register_ber_oid_dissector("2.9.0.0.2", dissect_cmip, proto_cmip, "cmip");
	register_ber_oid_dissector("2.9.1.1.4", dissect_cmip, proto_cmip, "joint-iso-itu-t(2) ms(9) cmip(1) cmip-pci(1) abstractSyntax(4)");

	add_oid_str_name("2.9.3.2.3.1","managedObjectClass(3) alarmRecord(1)");  
	add_oid_str_name("2.9.3.2.3.2","managedObjectClass(3) attributeValueChangeRecord(2)");
	add_oid_str_name("2.9.3.2.3.3","managedObjectClass(3) discriminator(3)");
	add_oid_str_name("2.9.3.2.3.4","managedObjectClass(3) eventForwardingDiscriminator(4)");
	add_oid_str_name("2.9.3.2.3.5","managedObjectClass(3) eventLogRecord(5)");
	add_oid_str_name("2.9.3.2.3.6","managedObjectClass(3) log(6)");
	add_oid_str_name("2.9.3.2.3.7","managedObjectClass(3) logRecord(7)");
	add_oid_str_name("2.9.3.2.3.8","managedObjectClass(3) objectCreationRecord(8)");
	add_oid_str_name("2.9.3.2.3.9","managedObjectClass(3) objectDeletionRecord(9)");
	add_oid_str_name("2.9.3.2.3.10","managedObjectClass(3) relationshipChangeRecord(10)");
	add_oid_str_name("2.9.3.2.3.11","managedObjectClass(3) securityAlarmReportRecord(11)");
	add_oid_str_name("2.9.3.2.3.12","managedObjectClass(3) stateChangeRecord(12)");
	add_oid_str_name("2.9.3.2.3.13","managedObjectClass(3) system(13)");
	add_oid_str_name("2.9.3.2.3.14","managedObjectClass(3) top(14)");
	add_oid_str_name("2.9.3.2.4.14","administrativeStatePackage(14)");
	add_oid_str_name("2.9.1.1.4","joint-iso-itu-t(2) ms(9) cmip(1) cmip-pci(1) abstractSyntax(4)");

/*#include "packet-cmip-dis-tab.c" */
}

