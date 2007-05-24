/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* .\packet-inap.c                                                            */
/* ../../tools/asn2wrs.py -b -e -p inap -c inap.cnf -s packet-inap-template inap.asn */

/* Input file: packet-inap-template.c */

#line 1 "packet-inap-template.c"
/* packet-inap-template.c
 * Routines for INAP
 * Copyright 2004, Tim Endean <endeant@hotmail.com>
 * Built from the gsm-map dissector Copyright 2004, Anders Broman <anders.broman@ericsson.com>
 *
 * $Id$
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
 * References: ETSI 300 374
 * ITU Q.1218
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include "epan/expert.h"
#include <epan/asn1.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-inap.h"
#include "packet-q931.h"
#include "packet-e164.h"
#include "packet-isup.h"
#include "packet-tcap.h"

#define PNAME  "Intelligent Network Application Protocol"
#define PSNAME "INAP"
#define PFNAME "inap"

/* Initialize the protocol and registered fields */
int proto_inap = -1;


/*--- Included file: packet-inap-hf.c ---*/
#line 1 "packet-inap-hf.c"
static int hf_inap_Component_PDU = -1;            /* Component */
static int hf_inap_ActivateServiceFilteringArg_PDU = -1;  /* ActivateServiceFilteringArg */
static int hf_inap_AnalysedInformationArg_PDU = -1;  /* AnalysedInformationArg */
static int hf_inap_AnalyseInformationArg_PDU = -1;  /* AnalyseInformationArg */
static int hf_inap_ApplyChargingArg_PDU = -1;     /* ApplyChargingArg */
static int hf_inap_ApplyChargingReportArg_PDU = -1;  /* ApplyChargingReportArg */
static int hf_inap_AssistRequestInstructionsArg_PDU = -1;  /* AssistRequestInstructionsArg */
static int hf_inap_CallGapArg_PDU = -1;           /* CallGapArg */
static int hf_inap_CallInformationReportArg_PDU = -1;  /* CallInformationReportArg */
static int hf_inap_CallInformationRequestArg_PDU = -1;  /* CallInformationRequestArg */
static int hf_inap_CancelArg_PDU = -1;            /* CancelArg */
static int hf_inap_CollectedInformationArg_PDU = -1;  /* CollectedInformationArg */
static int hf_inap_CollectInformationArg_PDU = -1;  /* CollectInformationArg */
static int hf_inap_ConnectArg_PDU = -1;           /* ConnectArg */
static int hf_inap_ConnectToResourceArg_PDU = -1;  /* ConnectToResourceArg */
static int hf_inap_EstablishTemporaryConnectionArg_PDU = -1;  /* EstablishTemporaryConnectionArg */
static int hf_inap_EventNotificationChargingArg_PDU = -1;  /* EventNotificationChargingArg */
static int hf_inap_EventReportBCSMArg_PDU = -1;   /* EventReportBCSMArg */
static int hf_inap_FurnishChargingInformationArg_PDU = -1;  /* FurnishChargingInformationArg */
static int hf_inap_HoldCallInNetworkArg_PDU = -1;  /* HoldCallInNetworkArg */
static int hf_inap_InitialDP_PDU = -1;            /* InitialDP */
static int hf_inap_InitiateCallAttemptArg_PDU = -1;  /* InitiateCallAttemptArg */
static int hf_inap_MidCallArg_PDU = -1;           /* MidCallArg */
static int hf_inap_OAnswerArg_PDU = -1;           /* OAnswerArg */
static int hf_inap_OCalledPartyBusyArg_PDU = -1;  /* OCalledPartyBusyArg */
static int hf_inap_ODisconnectArg_PDU = -1;       /* ODisconnectArg */
static int hf_inap_ONoAnswer_PDU = -1;            /* ONoAnswer */
static int hf_inap_OriginationAttemptAuthorizedArg_PDU = -1;  /* OriginationAttemptAuthorizedArg */
static int hf_inap_PlayAnnouncementArg_PDU = -1;  /* PlayAnnouncementArg */
static int hf_inap_PromptAndCollectUserInformationArg_PDU = -1;  /* PromptAndCollectUserInformationArg */
static int hf_inap_ReceivedInformationArg_PDU = -1;  /* ReceivedInformationArg */
static int hf_inap_ReleaseCallArg_PDU = -1;       /* ReleaseCallArg */
static int hf_inap_RequestCurrentStatusReportArg_PDU = -1;  /* RequestCurrentStatusReportArg */
static int hf_inap_RequestCurrentStatusReportResultArg_PDU = -1;  /* RequestCurrentStatusReportResultArg */
static int hf_inap_RequestEveryStatusChangeReportArg_PDU = -1;  /* RequestEveryStatusChangeReportArg */
static int hf_inap_RequestFirstStatusMatchReportArg_PDU = -1;  /* RequestFirstStatusMatchReportArg */
static int hf_inap_RequestNotificationChargingEvent_PDU = -1;  /* RequestNotificationChargingEvent */
static int hf_inap_RequestReportBCSMEventArg_PDU = -1;  /* RequestReportBCSMEventArg */
static int hf_inap_ResetTimerArg_PDU = -1;        /* ResetTimerArg */
static int hf_inap_RouteSelectFailureArg_PDU = -1;  /* RouteSelectFailureArg */
static int hf_inap_SelectFacilityArg_PDU = -1;    /* SelectFacilityArg */
static int hf_inap_SelectRouteArg_PDU = -1;       /* SelectRouteArg */
static int hf_inap_ServiceFilteringResponseArg_PDU = -1;  /* ServiceFilteringResponseArg */
static int hf_inap_SpecializedResourceReportArg_PDU = -1;  /* SpecializedResourceReportArg */
static int hf_inap_StatusReportArg_PDU = -1;      /* StatusReportArg */
static int hf_inap_TAnswerArg_PDU = -1;           /* TAnswerArg */
static int hf_inap_TBusyArg_PDU = -1;             /* TBusyArg */
static int hf_inap_TDisconnectArg_PDU = -1;       /* TDisconnectArg */
static int hf_inap_TermAttemptAuthorizedArg_PDU = -1;  /* TermAttemptAuthorizedArg */
static int hf_inap_TNoAnswerArg_PDU = -1;         /* TNoAnswerArg */
static int hf_inap_invoke = -1;                   /* Invoke */
static int hf_inap_returnResultLast = -1;         /* ReturnResult */
static int hf_inap_returnError = -1;              /* ReturnError */
static int hf_inap_reject = -1;                   /* Reject */
static int hf_inap_returnResultNotLast = -1;      /* ReturnResult */
static int hf_inap_invokeID = -1;                 /* InvokeIdType */
static int hf_inap_linkedID = -1;                 /* InvokeIdType */
static int hf_inap_opCode = -1;                   /* OPERATION */
static int hf_inap_invokeparameter = -1;          /* InvokeParameter */
static int hf_inap_resultretres = -1;             /* T_resultretres */
static int hf_inap_returnparameter = -1;          /* ReturnResultParameter */
static int hf_inap_errorCode = -1;                /* ERROR */
static int hf_inap_parameter = -1;                /* ReturnErrorParameter */
static int hf_inap_invokeIDRej = -1;              /* T_invokeIDRej */
static int hf_inap_derivable = -1;                /* InvokeIdType */
static int hf_inap_not_derivable = -1;            /* NULL */
static int hf_inap_problem = -1;                  /* T_problem */
static int hf_inap_generalProblem = -1;           /* GeneralProblem */
static int hf_inap_invokeProblem = -1;            /* InvokeProblem */
static int hf_inap_returnResultProblem = -1;      /* ReturnResultProblem */
static int hf_inap_returnErrorProblem = -1;       /* ReturnErrorProblem */
static int hf_inap_localValue = -1;               /* OperationLocalvalue */
static int hf_inap_globalValue = -1;              /* OBJECT_IDENTIFIER */
static int hf_inap_localValue_01 = -1;            /* LocalErrorcode */
static int hf_inap_originalCallID = -1;           /* CallID */
static int hf_inap_destinationCallID = -1;        /* CallID */
static int hf_inap_newLegID = -1;                 /* OCTET_STRING */
static int hf_inap_correlationidentifier = -1;    /* OCTET_STRING */
static int hf_inap_CallPartyHandlingResultsArg_item = -1;  /* LegInformation */
static int hf_inap_callID = -1;                   /* CallID */
static int hf_inap_targetCallID = -1;             /* CallID */
static int hf_inap_legToBeConnectedID = -1;       /* OCTET_STRING */
static int hf_inap_legToBeDetached = -1;          /* OCTET_STRING */
static int hf_inap_legID = -1;                    /* LegID */
static int hf_inap_heldLegID = -1;                /* LegID */
static int hf_inap_legToBeReleased = -1;          /* LegID */
static int hf_inap_releaseCause = -1;             /* Cause */
static int hf_inap_legStatus = -1;                /* LegStatus */
static int hf_inap_Extensions_item = -1;          /* Extensions_item */
static int hf_inap_type = -1;                     /* INTEGER */
static int hf_inap_criticality = -1;              /* T_criticality */
static int hf_inap_value = -1;                    /* OCTET_STRING */
static int hf_inap_filteredCallTreatment = -1;    /* FilteredCallTreatment */
static int hf_inap_filteringCharacteristics = -1;  /* FilteringCharacteristics */
static int hf_inap_filteringTimeOut = -1;         /* FilteringTimeOut */
static int hf_inap_filteringCriteria = -1;        /* FilteringCriteria */
static int hf_inap_startTime = -1;                /* DateAndTime */
static int hf_inap_extensions = -1;               /* Extensions */
static int hf_inap_dpSpecificCommonParameters = -1;  /* DpSpecificCommonParameters */
static int hf_inap_dialledDigits = -1;            /* CalledPartyNumber */
static int hf_inap_callingPartyBusinessGroupID = -1;  /* CallingPartyBusinessGroupID */
static int hf_inap_callingPartySubaddress = -1;   /* CallingPartySubaddress */
static int hf_inap_callingFacilityGroup = -1;     /* FacilityGroup */
static int hf_inap_callingFacilityGroupMember = -1;  /* FacilityGroupMember */
static int hf_inap_originalCalledPartyID = -1;    /* OriginalCalledPartyID */
static int hf_inap_prefix = -1;                   /* Digits */
static int hf_inap_redirectingPartyID = -1;       /* RedirectingPartyID */
static int hf_inap_redirectionInformation = -1;   /* RedirectionInformation */
static int hf_inap_routeList = -1;                /* RouteList */
static int hf_inap_travellingClassMark = -1;      /* TravellingClassMark */
static int hf_inap_featureCode = -1;              /* FeatureCode */
static int hf_inap_accessCode = -1;               /* AccessCode */
static int hf_inap_carrier = -1;                  /* Carrier */
static int hf_inap_destinationRoutingAddress = -1;  /* DestinationRoutingAddress */
static int hf_inap_alertingPattern = -1;          /* AlertingPattern */
static int hf_inap_iSDNAccessRelatedInformation = -1;  /* ISDNAccessRelatedInformation */
static int hf_inap_callingPartyNumber = -1;       /* CallingPartyNumber */
static int hf_inap_callingPartysCategory = -1;    /* CallingPartysCategory */
static int hf_inap_calledPartyNumber = -1;        /* CalledPartyNumber */
static int hf_inap_chargeNumber = -1;             /* ChargeNumber */
static int hf_inap_aChBillingChargingCharacteristics = -1;  /* AChBillingChargingCharacteristics */
static int hf_inap_partyToCharge = -1;            /* LegID */
static int hf_inap_correlationID = -1;            /* CorrelationID */
static int hf_inap_iPAvailable = -1;              /* IPAvailable */
static int hf_inap_iPSSPCapabilities = -1;        /* IPSSPCapabilities */
static int hf_inap_gapCriteria = -1;              /* GapCriteria */
static int hf_inap_gapIndicators = -1;            /* GapIndicators */
static int hf_inap_controlType = -1;              /* ControlType */
static int hf_inap_gapTreatment = -1;             /* GapTreatment */
static int hf_inap_requestedInformationTypeList = -1;  /* RequestedInformationTypeList */
static int hf_inap_invokeID_01 = -1;              /* InvokeID */
static int hf_inap_allRequests = -1;              /* NULL */
static int hf_inap_resourceID = -1;               /* ResourceID */
static int hf_inap_numberingPlan = -1;            /* NumberingPlan */
static int hf_inap_cutAndPaste = -1;              /* CutAndPaste */
static int hf_inap_forwardingCondition = -1;      /* ForwardingCondition */
static int hf_inap_scfID = -1;                    /* ScfID */
static int hf_inap_serviceInteractionIndicators = -1;  /* ServiceInteractionIndicators */
static int hf_inap_resourceAddress = -1;          /* T_resourceAddress */
static int hf_inap_ipRoutingAddress = -1;         /* IPRoutingAddress */
static int hf_inap_both2 = -1;                    /* T_both2 */
static int hf_inap_none = -1;                     /* NULL */
static int hf_inap_serviceAddressInformation = -1;  /* ServiceAddressInformation */
static int hf_inap_bearerCapability = -1;         /* BearerCapability */
static int hf_inap_cGEncountered = -1;            /* CGEncountered */
static int hf_inap_locationNumber = -1;           /* LocationNumber */
static int hf_inap_serviceProfileIdentifier = -1;  /* ServiceProfileIdentifier */
static int hf_inap_terminalType = -1;             /* TerminalType */
static int hf_inap_servingAreaID = -1;            /* ServingAreaID */
static int hf_inap_assistingSSPIPRoutingAddress = -1;  /* AssistingSSPIPRoutingAddress */
static int hf_inap_eventTypeCharging = -1;        /* EventTypeCharging */
static int hf_inap_eventSpecificInformationCharging = -1;  /* EventSpecificInformationCharging */
static int hf_inap_monitorMode = -1;              /* MonitorMode */
static int hf_inap_eventTypeBCSM = -1;            /* EventTypeBCSM */
static int hf_inap_bcsmEventCorrelationID = -1;   /* CorrelationID */
static int hf_inap_eventSpecificInformationBCSM = -1;  /* EventSpecificInformationBCSM */
static int hf_inap_miscCallInfo = -1;             /* MiscCallInfo */
static int hf_inap_holdcause = -1;                /* HoldCause */
static int hf_inap_empty = -1;                    /* NULL */
static int hf_inap_serviceKey = -1;               /* ServiceKey */
static int hf_inap_triggerType = -1;              /* TriggerType */
static int hf_inap_highLayerCompatibility = -1;   /* HighLayerCompatibility */
static int hf_inap_additionalCallingPartyNumber = -1;  /* AdditionalCallingPartyNumber */
static int hf_inap_forwardCallIndicators = -1;    /* ForwardCallIndicators */
static int hf_inap_calledPartyBusinessGroupID = -1;  /* CalledPartyBusinessGroupID */
static int hf_inap_calledPartySubaddress = -1;    /* CalledPartySubaddress */
static int hf_inap_featureRequestIndicator = -1;  /* FeatureRequestIndicator */
static int hf_inap_busyCause = -1;                /* Cause */
static int hf_inap_connectTime = -1;              /* Integer4 */
static int hf_inap_informationToSend = -1;        /* InformationToSend */
static int hf_inap_disconnectFromIPForbidden = -1;  /* BOOLEAN */
static int hf_inap_requestAnnouncementComplete = -1;  /* BOOLEAN */
static int hf_inap_collectedInfo = -1;            /* CollectedInfo */
static int hf_inap_digitsResponse = -1;           /* Digits */
static int hf_inap_iA5Response = -1;              /* IA5String */
static int hf_inap_initialCallSegment = -1;       /* Cause */
static int hf_inap_allCallSegments = -1;          /* T_allCallSegments */
static int hf_inap_resourceStatus = -1;           /* ResourceStatus */
static int hf_inap_monitorDuration = -1;          /* Duration */
static int hf_inap_RequestNotificationChargingEvent_item = -1;  /* RequestNotificationChargingEvent_item */
static int hf_inap_eventTypeCharging2 = -1;       /* OCTET_STRING */
static int hf_inap_bcsmEvents = -1;               /* SEQUENCE_SIZE_1_numOfBCSMEvents_OF_BCSMEvent */
static int hf_inap_bcsmEvents_item = -1;          /* BCSMEvent */
static int hf_inap_timerID = -1;                  /* TimerID */
static int hf_inap_timervalue = -1;               /* TimerValue */
static int hf_inap_failureCause = -1;             /* Cause */
static int hf_inap_destinationNumberRoutingAddress = -1;  /* CalledPartyNumber */
static int hf_inap_calledFacilityGroup = -1;      /* FacilityGroup */
static int hf_inap_calledFacilityGroupMember = -1;  /* FacilityGroupMember */
static int hf_inap_sCIBillingChargingCharacteristics = -1;  /* SCIBillingChargingCharacteristics */
static int hf_inap_countersValue = -1;            /* CountersValue */
static int hf_inap_responseCondition = -1;        /* ResponseCondition */
static int hf_inap_reportCondition = -1;          /* ReportCondition */
static int hf_inap_dpSpecificCriteria = -1;       /* DpSpecificCriteria */
static int hf_inap_bearerCap = -1;                /* BearerCap */
static int hf_inap_tmr = -1;                      /* OCTET_STRING_SIZE_1 */
static int hf_inap_minimumNbOfDigits = -1;        /* INTEGER_1_127 */
static int hf_inap_maximumNbOfDigits = -1;        /* INTEGER_1_127 */
static int hf_inap_endOfReplyDigit = -1;          /* OCTET_STRING_SIZE_1_2 */
static int hf_inap_cancelDigit = -1;              /* OCTET_STRING_SIZE_1_2 */
static int hf_inap_startDigit = -1;               /* OCTET_STRING_SIZE_1_2 */
static int hf_inap_firstDigitTimeOut = -1;        /* INTEGER_1_127 */
static int hf_inap_interDigitTimeOut = -1;        /* INTEGER_1_127 */
static int hf_inap_errorTreatment = -1;           /* ErrorTreatment */
static int hf_inap_interruptableAnnInd = -1;      /* BOOLEAN */
static int hf_inap_voiceInformation = -1;         /* BOOLEAN */
static int hf_inap_voiceBack = -1;                /* BOOLEAN */
static int hf_inap_collectedDigits = -1;          /* CollectedDigits */
static int hf_inap_iA5Information = -1;           /* BOOLEAN */
static int hf_inap_counterID = -1;                /* CounterID */
static int hf_inap_counterValue = -1;             /* Integer4 */
static int hf_inap_CountersValue_item = -1;       /* CounterAndValue */
static int hf_inap_DestinationRoutingAddress_item = -1;  /* CalledPartyNumber */
static int hf_inap_numberOfDigits = -1;           /* NumberOfDigits */
static int hf_inap_applicationTimer = -1;         /* ApplicationTimer */
static int hf_inap_collectedInfoSpecificInfo = -1;  /* T_collectedInfoSpecificInfo */
static int hf_inap_calledPartynumber = -1;        /* CalledPartyNumber */
static int hf_inap_analyzedInfoSpecificInfo = -1;  /* T_analyzedInfoSpecificInfo */
static int hf_inap_routeSelectFailureSpecificInfo = -1;  /* T_routeSelectFailureSpecificInfo */
static int hf_inap_oCalledPartyBusySpecificInfo = -1;  /* T_oCalledPartyBusySpecificInfo */
static int hf_inap_oNoAnswerSpecificInfo = -1;    /* T_oNoAnswerSpecificInfo */
static int hf_inap_oAnswerSpecificInfo = -1;      /* T_oAnswerSpecificInfo */
static int hf_inap_oMidCallSpecificInfo = -1;     /* T_oMidCallSpecificInfo */
static int hf_inap_oDisconnectSpecificInfo = -1;  /* T_oDisconnectSpecificInfo */
static int hf_inap_tBusySpecificInfo = -1;        /* T_tBusySpecificInfo */
static int hf_inap_tNoAnswerSpecificInfo = -1;    /* T_tNoAnswerSpecificInfo */
static int hf_inap_tAnswerSpecificInfo = -1;      /* T_tAnswerSpecificInfo */
static int hf_inap_tMidCallSpecificInfo = -1;     /* T_tMidCallSpecificInfo */
static int hf_inap_tDisconnectSpecificInfo = -1;  /* T_tDisconnectSpecificInfo */
static int hf_inap_trunkGroupID = -1;             /* INTEGER */
static int hf_inap_privateFacilityID = -1;        /* INTEGER */
static int hf_inap_huntGroup = -1;                /* OCTET_STRING */
static int hf_inap_routeIndex = -1;               /* OCTET_STRING */
static int hf_inap_sFBillingChargingCharacteristics = -1;  /* SFBillingChargingCharacteristics */
static int hf_inap_maximumNumberOfCounters = -1;  /* MaximumNumberOfCounters */
static int hf_inap_interval1 = -1;                /* INTEGER_M1_32000 */
static int hf_inap_numberOfCalls = -1;            /* Integer4 */
static int hf_inap_dialledNumber = -1;            /* Digits */
static int hf_inap_callingLineID = -1;            /* Digits */
static int hf_inap_addressAndService = -1;        /* T_addressAndService */
static int hf_inap_calledAddressValue = -1;       /* Digits */
static int hf_inap_callingAddressValue = -1;      /* Digits */
static int hf_inap_duration = -1;                 /* Duration */
static int hf_inap_stopTime = -1;                 /* DateAndTime */
static int hf_inap_gapOnService = -1;             /* GapOnService */
static int hf_inap_calledAddressAndService = -1;  /* T_calledAddressAndService */
static int hf_inap_callingAddressAndService = -1;  /* T_callingAddressAndService */
static int hf_inap_dpCriteria = -1;               /* EventTypeBCSM */
static int hf_inap_gapInterval = -1;              /* Interval */
static int hf_inap_both = -1;                     /* T_both */
static int hf_inap_messageID = -1;                /* MessageID */
static int hf_inap_numberOfRepetitions = -1;      /* INTEGER_1_127 */
static int hf_inap_duration3 = -1;                /* INTEGER_0_32767 */
static int hf_inap_interval = -1;                 /* INTEGER_0_32767 */
static int hf_inap_inbandInfo = -1;               /* InbandInfo */
static int hf_inap_tone = -1;                     /* Tone */
static int hf_inap_displayInformation = -1;       /* DisplayInformation */
static int hf_inap_sendingSideID = -1;            /* LegType */
static int hf_inap_receivingSideID = -1;          /* LegType */
static int hf_inap_elementaryMessageID = -1;      /* Integer4 */
static int hf_inap_text = -1;                     /* T_text */
static int hf_inap_messageContent = -1;           /* IA5String_SIZE_minMessageContentLength_maxMessageContentLength */
static int hf_inap_attributes = -1;               /* OCTET_STRING_SIZE_minAttributesLength_maxAttributesLength */
static int hf_inap_elementaryMessageIDs = -1;     /* SEQUENCE_SIZE_1_numOfMessageIDs_OF_Integer4 */
static int hf_inap_elementaryMessageIDs_item = -1;  /* Integer4 */
static int hf_inap_variableMessage = -1;          /* T_variableMessage */
static int hf_inap_variableParts = -1;            /* SEQUENCE_SIZE_1_5_OF_VariablePart */
static int hf_inap_variableParts_item = -1;       /* VariablePart */
static int hf_inap_messageType = -1;              /* T_messageType */
static int hf_inap_dpAssignment = -1;             /* T_dpAssignment */
static int hf_inap_RequestedInformationList_item = -1;  /* RequestedInformation */
static int hf_inap_RequestedInformationTypeList_item = -1;  /* RequestedInformationType */
static int hf_inap_requestedInformationType = -1;  /* RequestedInformationType */
static int hf_inap_requestedInformationValue = -1;  /* RequestedInformationValue */
static int hf_inap_callAttemptElapsedTimeValue = -1;  /* INTEGER_0_255 */
static int hf_inap_callStopTimeValue = -1;        /* DateAndTime */
static int hf_inap_callConnectedElapsedTimeValue = -1;  /* Integer4 */
static int hf_inap_releaseCauseValue = -1;        /* Cause */
static int hf_inap_lineID = -1;                   /* Digits */
static int hf_inap_facilityGroupID = -1;          /* FacilityGroup */
static int hf_inap_facilityGroupMemberID = -1;    /* INTEGER */
static int hf_inap_RouteList_item = -1;           /* OCTET_STRING */
static int hf_inap_toneID = -1;                   /* Integer4 */
static int hf_inap_tone_duration = -1;            /* Integer4 */
static int hf_inap_integer = -1;                  /* Integer4 */
static int hf_inap_number = -1;                   /* Digits */
static int hf_inap_time = -1;                     /* OCTET_STRING_SIZE_2 */
static int hf_inap_date2 = -1;                    /* OCTET_STRING_SIZE_3 */
static int hf_inap_price = -1;                    /* OCTET_STRING_SIZE_4 */
static int hf_inap_problem_01 = -1;               /* T_problem_01 */
static int hf_inap_operation = -1;                /* INTEGER_M128_127 */

/*--- End of included file: packet-inap-hf.c ---*/
#line 57 "packet-inap-template.c"

#define MAX_SSN 254
static range_t *global_ssn_range;
static range_t *ssn_range;

static dissector_handle_t	inap_handle;

/* Global variables */
static guint32 opcode=0;
static guint32 errorCode;

/* Initialize the subtree pointers */
static gint ett_inap = -1;
static gint ett_inapisup_parameter = -1;

/*--- Included file: packet-inap-ett.c ---*/
#line 1 "packet-inap-ett.c"
static gint ett_inap_Component = -1;
static gint ett_inap_Invoke = -1;
static gint ett_inap_ReturnResult = -1;
static gint ett_inap_T_resultretres = -1;
static gint ett_inap_ReturnError = -1;
static gint ett_inap_Reject = -1;
static gint ett_inap_T_invokeIDRej = -1;
static gint ett_inap_T_problem = -1;
static gint ett_inap_OPERATION = -1;
static gint ett_inap_ERROR = -1;
static gint ett_inap_AddPartyArg = -1;
static gint ett_inap_AttachArg = -1;
static gint ett_inap_CallPartyHandlingResultsArg = -1;
static gint ett_inap_ChangePartiesArg = -1;
static gint ett_inap_DetachArg = -1;
static gint ett_inap_HoldCallPartyConnectionArg = -1;
static gint ett_inap_ReconnectArg = -1;
static gint ett_inap_ReleaseCallPartyConnectionArg = -1;
static gint ett_inap_LegInformation = -1;
static gint ett_inap_Extensions = -1;
static gint ett_inap_Extensions_item = -1;
static gint ett_inap_ActivateServiceFilteringArg = -1;
static gint ett_inap_AnalysedInformationArg = -1;
static gint ett_inap_AnalyseInformationArg = -1;
static gint ett_inap_ApplyChargingArg = -1;
static gint ett_inap_AssistRequestInstructionsArg = -1;
static gint ett_inap_CallGapArg = -1;
static gint ett_inap_CallInformationReportArg = -1;
static gint ett_inap_CallInformationRequestArg = -1;
static gint ett_inap_CancelArg = -1;
static gint ett_inap_CancelStatusReportRequestArg = -1;
static gint ett_inap_CollectedInformationArg = -1;
static gint ett_inap_CollectInformationArg = -1;
static gint ett_inap_ConnectArg = -1;
static gint ett_inap_ConnectToResourceArg = -1;
static gint ett_inap_T_resourceAddress = -1;
static gint ett_inap_T_both2 = -1;
static gint ett_inap_DpSpecificCommonParameters = -1;
static gint ett_inap_EstablishTemporaryConnectionArg = -1;
static gint ett_inap_EventNotificationChargingArg = -1;
static gint ett_inap_EventReportBCSMArg = -1;
static gint ett_inap_HoldCallInNetworkArg = -1;
static gint ett_inap_InitialDP = -1;
static gint ett_inap_InitiateCallAttemptArg = -1;
static gint ett_inap_MidCallArg = -1;
static gint ett_inap_OAnswerArg = -1;
static gint ett_inap_OCalledPartyBusyArg = -1;
static gint ett_inap_ODisconnectArg = -1;
static gint ett_inap_ONoAnswer = -1;
static gint ett_inap_OriginationAttemptAuthorizedArg = -1;
static gint ett_inap_PlayAnnouncementArg = -1;
static gint ett_inap_PromptAndCollectUserInformationArg = -1;
static gint ett_inap_ReceivedInformationArg = -1;
static gint ett_inap_ReleaseCallArg = -1;
static gint ett_inap_T_allCallSegments = -1;
static gint ett_inap_RequestCurrentStatusReportResultArg = -1;
static gint ett_inap_RequestEveryStatusChangeReportArg = -1;
static gint ett_inap_RequestFirstStatusMatchReportArg = -1;
static gint ett_inap_RequestNotificationChargingEvent = -1;
static gint ett_inap_RequestNotificationChargingEvent_item = -1;
static gint ett_inap_RequestReportBCSMEventArg = -1;
static gint ett_inap_SEQUENCE_SIZE_1_numOfBCSMEvents_OF_BCSMEvent = -1;
static gint ett_inap_ResetTimerArg = -1;
static gint ett_inap_RouteSelectFailureArg = -1;
static gint ett_inap_SelectFacilityArg = -1;
static gint ett_inap_SelectRouteArg = -1;
static gint ett_inap_SendChargingInformationArg = -1;
static gint ett_inap_ServiceFilteringResponseArg = -1;
static gint ett_inap_StatusReportArg = -1;
static gint ett_inap_TAnswerArg = -1;
static gint ett_inap_TBusyArg = -1;
static gint ett_inap_TDisconnectArg = -1;
static gint ett_inap_TermAttemptAuthorizedArg = -1;
static gint ett_inap_TNoAnswerArg = -1;
static gint ett_inap_BCSMEvent = -1;
static gint ett_inap_BearerCapability = -1;
static gint ett_inap_ChargingEvent = -1;
static gint ett_inap_CollectedDigits = -1;
static gint ett_inap_CollectedInfo = -1;
static gint ett_inap_CounterAndValue = -1;
static gint ett_inap_CountersValue = -1;
static gint ett_inap_DestinationRoutingAddress = -1;
static gint ett_inap_DpSpecificCriteria = -1;
static gint ett_inap_EventSpecificInformationBCSM = -1;
static gint ett_inap_T_collectedInfoSpecificInfo = -1;
static gint ett_inap_T_analyzedInfoSpecificInfo = -1;
static gint ett_inap_T_routeSelectFailureSpecificInfo = -1;
static gint ett_inap_T_oCalledPartyBusySpecificInfo = -1;
static gint ett_inap_T_oNoAnswerSpecificInfo = -1;
static gint ett_inap_T_oAnswerSpecificInfo = -1;
static gint ett_inap_T_oMidCallSpecificInfo = -1;
static gint ett_inap_T_oDisconnectSpecificInfo = -1;
static gint ett_inap_T_tBusySpecificInfo = -1;
static gint ett_inap_T_tNoAnswerSpecificInfo = -1;
static gint ett_inap_T_tAnswerSpecificInfo = -1;
static gint ett_inap_T_tMidCallSpecificInfo = -1;
static gint ett_inap_T_tDisconnectSpecificInfo = -1;
static gint ett_inap_FacilityGroup = -1;
static gint ett_inap_FilteredCallTreatment = -1;
static gint ett_inap_FilteringCharacteristics = -1;
static gint ett_inap_FilteringCriteria = -1;
static gint ett_inap_T_addressAndService = -1;
static gint ett_inap_FilteringTimeOut = -1;
static gint ett_inap_GapCriteria = -1;
static gint ett_inap_T_calledAddressAndService = -1;
static gint ett_inap_T_callingAddressAndService = -1;
static gint ett_inap_GapOnService = -1;
static gint ett_inap_GapIndicators = -1;
static gint ett_inap_GapTreatment = -1;
static gint ett_inap_T_both = -1;
static gint ett_inap_InbandInfo = -1;
static gint ett_inap_InformationToSend = -1;
static gint ett_inap_LegID = -1;
static gint ett_inap_MessageID = -1;
static gint ett_inap_T_text = -1;
static gint ett_inap_SEQUENCE_SIZE_1_numOfMessageIDs_OF_Integer4 = -1;
static gint ett_inap_T_variableMessage = -1;
static gint ett_inap_SEQUENCE_SIZE_1_5_OF_VariablePart = -1;
static gint ett_inap_MiscCallInfo = -1;
static gint ett_inap_RequestedInformationList = -1;
static gint ett_inap_RequestedInformationTypeList = -1;
static gint ett_inap_RequestedInformation = -1;
static gint ett_inap_RequestedInformationValue = -1;
static gint ett_inap_ResourceID = -1;
static gint ett_inap_RouteList = -1;
static gint ett_inap_ServiceAddressInformation = -1;
static gint ett_inap_Tone = -1;
static gint ett_inap_VariablePart = -1;
static gint ett_inap_CancelFailed = -1;

/*--- End of included file: packet-inap-ett.c ---*/
#line 72 "packet-inap-template.c"

const value_string inap_opr_code_strings[] = {

	{0,"InitialDP"},
	{1, "OriginationAttemptAuthorized"},
	{2, "CollectedInformation"},
	{3, "AnalysedInformation"},
	{4, "RouteSelectFailure"},
	{5, "oCalledPartyBusy"},
	{6, "oNoAnswer"},
	{7, "oAnswer"},
	{8, "oDisconnect"},
	{9, "TermAttemptAuthorized"},
	{10, "tBusy"},
	{11, "tNoAnswer"},
	{12, "tAnswer"},
	{13, "tDisconnect"},
	{14, "oMidCall"},
	{15, "tMidCall"},
	{16, "AssistRequestInstructions"},
	{17,"EstablishTemporaryConnection"},
	{18, "DisconnectForwardConnection"},
	{19,"ConnectToResource"},
	{20, "Connect"},
	{21,"HoldCallInNetwork"},
	{22, "ReleaseCall"},
	{23, "RequestReportBCSMEven"},
	{23,"RequestReportBCSMEvent"},
	{24,"EventReportBCSM"},
	{25, "RequestNotificationChargingEvent"},
	{26, "EventNotificationCharging"},
	{27, "CollectInformation"},
	{28, "AnalyseInformation"},
	{29, "SelectRoute"},
	{30, "SelectFacility"},
	{31, "Continue"},
	{32, "InitiateCallAttempt"},
	{33,"ResetTimer"},
	{34,"FurnishChargingInformation"},
	{35, "ApplyCharging"},
	{36, "ApplyChargingReport"},
	{37, "RequestCurrentStatusReport"},
	{38, "RequestEveryStatusChangeReport"},
	{39, "RequestFirstStatusMatchReport"},
	{40, "StatusReport"},
	{41, "CallGap"},
	{42, "ActivateServiceFiltering"},
	{43, "ServiceFilteringResponse"},
	{44, "CallInformationReport"},
	{45, "CallInformationRequest"},
	{46, "SendChargingInformation"},
	{47,"PlayAnnouncement"},
	{48,"PromptAndCollectUserInformation"},
	{49,"SpecializedResourceReport"},
	{53, "Cancel"},
	{55, "ActivityTest"},
	{99,"ReceivedInformation"}, /*???????*/
	{0, NULL}
};

const value_string inap_error_code_strings[] = {

{0,"cancelled"},
{1,"cancelFailed"},
{3,"etcFailed"},
{4,"improperCallerResponse"},
{6,"missingCustomerRecord"},
{7,"missingParameter"},
{8,"parameterOutOfRange"},
{10,"RequestedInfoError"},
{11,"SystemFailure"},
{12,"TaskRefused"},
{13,"UnavailableResource"},
{14,"UnexpectedComponentSequence"},
{15,"UnexpectedDataValue"},
{16,"UnexpectedParameter"},
{17,"UnknownLegID"},
{18,"UnknownResource"},
{0, NULL}
};

const value_string inap_general_problem_strings[] = {
{0,"General Problem Unrecognized Component"},
{1,"General Problem Mistyped Component"},
{3,"General Problem Badly Structured Component"},
{0, NULL}
};

/* Forvard declarations */
static int dissect_invokeData(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_);
static int dissect_returnResultData(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_);
static int dissect_returnErrorData(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx);


/*--- Included file: packet-inap-fn.c ---*/
#line 1 "packet-inap-fn.c"
/*--- Fields for imported types ---*/




static int
dissect_inap_InvokeIdType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_invokeID(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_InvokeIdType(FALSE, tvb, offset, actx, tree, hf_inap_invokeID);
}
static int dissect_linkedID_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_InvokeIdType(TRUE, tvb, offset, actx, tree, hf_inap_linkedID);
}
static int dissect_derivable(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_InvokeIdType(FALSE, tvb, offset, actx, tree, hf_inap_derivable);
}



static int
dissect_inap_INAPOperationLocalvalue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 89 "inap.cnf"
  offset = dissect_ber_integer(FALSE, actx, tree, tvb, offset, hf_index, &opcode);

  if (check_col(actx->pinfo->cinfo, COL_INFO)){
    col_add_fstr(actx->pinfo->cinfo, COL_INFO, "%s ", val_to_str(opcode, inap_opr_code_strings, "Unknown Inap (%u)"));
  }



  return offset;
}



static int
dissect_inap_OperationLocalvalue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_inap_INAPOperationLocalvalue(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_localValue(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_OperationLocalvalue(FALSE, tvb, offset, actx, tree, hf_inap_localValue);
}



static int
dissect_inap_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_globalValue(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_OBJECT_IDENTIFIER(FALSE, tvb, offset, actx, tree, hf_inap_globalValue);
}


static const value_string inap_OPERATION_vals[] = {
  {   0, "localValue" },
  {   1, "globalValue" },
  { 0, NULL }
};

static const ber_old_choice_t OPERATION_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_localValue },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_globalValue },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_OPERATION(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_choice(actx, tree, tvb, offset,
                                     OPERATION_choice, hf_index, ett_inap_OPERATION,
                                     NULL);

  return offset;
}
static int dissect_opCode(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_OPERATION(FALSE, tvb, offset, actx, tree, hf_inap_opCode);
}



static int
dissect_inap_InvokeParameter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 73 "inap.cnf"
	offset = dissect_invokeData(tree, tvb, offset, actx);



  return offset;
}
static int dissect_invokeparameter(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_InvokeParameter(FALSE, tvb, offset, actx, tree, hf_inap_invokeparameter);
}


static const ber_old_sequence_t Invoke_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_invokeID },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_linkedID_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_opCode },
  { BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_invokeparameter },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_Invoke(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       Invoke_sequence, hf_index, ett_inap_Invoke);

  return offset;
}
static int dissect_invoke_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_Invoke(TRUE, tvb, offset, actx, tree, hf_inap_invoke);
}



static int
dissect_inap_ReturnResultParameter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 76 "inap.cnf"
	offset = dissect_returnResultData(tree, tvb, offset, actx);



  return offset;
}
static int dissect_returnparameter(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_ReturnResultParameter(FALSE, tvb, offset, actx, tree, hf_inap_returnparameter);
}


static const ber_old_sequence_t T_resultretres_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_opCode },
  { BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_returnparameter },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_resultretres(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       T_resultretres_sequence, hf_index, ett_inap_T_resultretres);

  return offset;
}
static int dissect_resultretres(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_T_resultretres(FALSE, tvb, offset, actx, tree, hf_inap_resultretres);
}


static const ber_old_sequence_t ReturnResult_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_invokeID },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_resultretres },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_ReturnResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       ReturnResult_sequence, hf_index, ett_inap_ReturnResult);

  return offset;
}
static int dissect_returnResultLast_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_ReturnResult(TRUE, tvb, offset, actx, tree, hf_inap_returnResultLast);
}
static int dissect_returnResultNotLast_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_ReturnResult(TRUE, tvb, offset, actx, tree, hf_inap_returnResultNotLast);
}



static int
dissect_inap_INAPLocalErrorcode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 82 "inap.cnf"
  offset = dissect_ber_integer(FALSE, actx, tree, tvb, offset, hf_index, &errorCode);

  if (check_col(actx->pinfo->cinfo, COL_INFO)){
    col_set_str(actx->pinfo->cinfo, COL_INFO, val_to_str(errorCode, inap_error_code_strings, "Unknown Inap (%u)"));
  }



  return offset;
}



static int
dissect_inap_LocalErrorcode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_inap_INAPLocalErrorcode(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_localValue_01(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_LocalErrorcode(FALSE, tvb, offset, actx, tree, hf_inap_localValue_01);
}


static const value_string inap_ERROR_vals[] = {
  {   0, "localValue" },
  {   1, "globalValue" },
  { 0, NULL }
};

static const ber_old_choice_t ERROR_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_localValue_01 },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_globalValue },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_ERROR(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_choice(actx, tree, tvb, offset,
                                     ERROR_choice, hf_index, ett_inap_ERROR,
                                     NULL);

  return offset;
}
static int dissect_errorCode(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_ERROR(FALSE, tvb, offset, actx, tree, hf_inap_errorCode);
}



static int
dissect_inap_ReturnErrorParameter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 79 "inap.cnf"
	offset = dissect_returnErrorData(tree, tvb, offset, actx);



  return offset;
}
static int dissect_parameter(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_ReturnErrorParameter(FALSE, tvb, offset, actx, tree, hf_inap_parameter);
}


static const ber_old_sequence_t ReturnError_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_invokeID },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_errorCode },
  { BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_parameter },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_ReturnError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       ReturnError_sequence, hf_index, ett_inap_ReturnError);

  return offset;
}
static int dissect_returnError_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_ReturnError(TRUE, tvb, offset, actx, tree, hf_inap_returnError);
}



static int
dissect_inap_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_not_derivable(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_NULL(FALSE, tvb, offset, actx, tree, hf_inap_not_derivable);
}
static int dissect_allRequests_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_NULL(TRUE, tvb, offset, actx, tree, hf_inap_allRequests);
}
static int dissect_none_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_NULL(TRUE, tvb, offset, actx, tree, hf_inap_none);
}
static int dissect_empty_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_NULL(TRUE, tvb, offset, actx, tree, hf_inap_empty);
}


static const value_string inap_T_invokeIDRej_vals[] = {
  {   0, "derivable" },
  {   1, "not-derivable" },
  { 0, NULL }
};

static const ber_old_choice_t T_invokeIDRej_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_derivable },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_not_derivable },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_T_invokeIDRej(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_choice(actx, tree, tvb, offset,
                                     T_invokeIDRej_choice, hf_index, ett_inap_T_invokeIDRej,
                                     NULL);

  return offset;
}
static int dissect_invokeIDRej(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_T_invokeIDRej(FALSE, tvb, offset, actx, tree, hf_inap_invokeIDRej);
}


static const value_string inap_GeneralProblem_vals[] = {
  {   0, "unrecognizedComponent" },
  {   1, "mistypedComponent" },
  {   2, "badlyStructuredComponent" },
  { 0, NULL }
};


static int
dissect_inap_GeneralProblem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_generalProblem_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_GeneralProblem(TRUE, tvb, offset, actx, tree, hf_inap_generalProblem);
}


static const value_string inap_InvokeProblem_vals[] = {
  {   0, "duplicateInvokeID" },
  {   1, "unrecognizedOperation" },
  {   2, "mistypedParameter" },
  {   3, "resourceLimitation" },
  {   4, "initiatingRelease" },
  {   5, "unrecognizedLinkedID" },
  {   6, "linkedResponseUnexpected" },
  {   7, "unexpectedLinkedOperation" },
  { 0, NULL }
};


static int
dissect_inap_InvokeProblem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_invokeProblem_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_InvokeProblem(TRUE, tvb, offset, actx, tree, hf_inap_invokeProblem);
}


static const value_string inap_ReturnResultProblem_vals[] = {
  {   0, "unrecognizedInvokeID" },
  {   1, "returnResultUnexpected" },
  {   2, "mistypedParameter" },
  { 0, NULL }
};


static int
dissect_inap_ReturnResultProblem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_returnResultProblem_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_ReturnResultProblem(TRUE, tvb, offset, actx, tree, hf_inap_returnResultProblem);
}


static const value_string inap_ReturnErrorProblem_vals[] = {
  {   0, "unrecognizedInvokeID" },
  {   1, "returnErrorUnexpected" },
  {   2, "unrecognizedError" },
  {   3, "unexpectedError" },
  {   4, "mistypedParameter" },
  { 0, NULL }
};


static int
dissect_inap_ReturnErrorProblem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_returnErrorProblem_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_ReturnErrorProblem(TRUE, tvb, offset, actx, tree, hf_inap_returnErrorProblem);
}


static const value_string inap_T_problem_vals[] = {
  {   0, "generalProblem" },
  {   1, "invokeProblem" },
  {   2, "returnResultProblem" },
  {   3, "returnErrorProblem" },
  { 0, NULL }
};

static const ber_old_choice_t T_problem_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_generalProblem_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_invokeProblem_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_returnResultProblem_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_returnErrorProblem_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_T_problem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_choice(actx, tree, tvb, offset,
                                     T_problem_choice, hf_index, ett_inap_T_problem,
                                     NULL);

  return offset;
}
static int dissect_problem(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_T_problem(FALSE, tvb, offset, actx, tree, hf_inap_problem);
}


static const ber_old_sequence_t Reject_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_invokeIDRej },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_problem },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_Reject(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       Reject_sequence, hf_index, ett_inap_Reject);

  return offset;
}
static int dissect_reject_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_Reject(TRUE, tvb, offset, actx, tree, hf_inap_reject);
}


static const value_string inap_Component_vals[] = {
  {   1, "invoke" },
  {   2, "returnResultLast" },
  {   3, "returnError" },
  {   4, "reject" },
  {   7, "returnResultNotLast" },
  { 0, NULL }
};

static const ber_old_choice_t Component_choice[] = {
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_invoke_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_returnResultLast_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_returnError_impl },
  {   4, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_reject_impl },
  {   7, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_returnResultNotLast_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_Component(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_choice(actx, tree, tvb, offset,
                                     Component_choice, hf_index, ett_inap_Component,
                                     NULL);

  return offset;
}



static int
dissect_inap_CallID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_originalCallID_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_CallID(TRUE, tvb, offset, actx, tree, hf_inap_originalCallID);
}
static int dissect_destinationCallID_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_CallID(TRUE, tvb, offset, actx, tree, hf_inap_destinationCallID);
}
static int dissect_callID_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_CallID(TRUE, tvb, offset, actx, tree, hf_inap_callID);
}
static int dissect_targetCallID_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_CallID(TRUE, tvb, offset, actx, tree, hf_inap_targetCallID);
}


static const ber_old_sequence_t AddPartyArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_originalCallID_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_destinationCallID_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_AddPartyArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       AddPartyArg_sequence, hf_index, ett_inap_AddPartyArg);

  return offset;
}



static int
dissect_inap_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_newLegID_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, actx, tree, hf_inap_newLegID);
}
static int dissect_correlationidentifier_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, actx, tree, hf_inap_correlationidentifier);
}
static int dissect_legToBeConnectedID_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, actx, tree, hf_inap_legToBeConnectedID);
}
static int dissect_legToBeDetached_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, actx, tree, hf_inap_legToBeDetached);
}
static int dissect_value_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, actx, tree, hf_inap_value);
}
static int dissect_eventTypeCharging2_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, actx, tree, hf_inap_eventTypeCharging2);
}
static int dissect_huntGroup_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, actx, tree, hf_inap_huntGroup);
}
static int dissect_routeIndex_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, actx, tree, hf_inap_routeIndex);
}
static int dissect_RouteList_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_OCTET_STRING(FALSE, tvb, offset, actx, tree, hf_inap_RouteList_item);
}


static const ber_old_sequence_t AttachArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_newLegID_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_correlationidentifier_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_AttachArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       AttachArg_sequence, hf_index, ett_inap_AttachArg);

  return offset;
}



static int
dissect_inap_LegType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_sendingSideID_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_LegType(TRUE, tvb, offset, actx, tree, hf_inap_sendingSideID);
}
static int dissect_receivingSideID_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_LegType(TRUE, tvb, offset, actx, tree, hf_inap_receivingSideID);
}


static const value_string inap_LegID_vals[] = {
  {   0, "sendingSideID" },
  {   1, "receivingSideID" },
  { 0, NULL }
};

static const ber_old_choice_t LegID_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sendingSideID_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_receivingSideID_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_LegID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_choice(actx, tree, tvb, offset,
                                     LegID_choice, hf_index, ett_inap_LegID,
                                     NULL);

  return offset;
}
static int dissect_legID_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_LegID(TRUE, tvb, offset, actx, tree, hf_inap_legID);
}
static int dissect_heldLegID_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_LegID(TRUE, tvb, offset, actx, tree, hf_inap_heldLegID);
}
static int dissect_legToBeReleased_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_LegID(TRUE, tvb, offset, actx, tree, hf_inap_legToBeReleased);
}
static int dissect_partyToCharge_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_LegID(TRUE, tvb, offset, actx, tree, hf_inap_partyToCharge);
}


static const value_string inap_LegStatus_vals[] = {
  {   0, "connected" },
  {   1, "unconnected" },
  {   2, "pending" },
  {   3, "interacting" },
  { 0, NULL }
};


static int
dissect_inap_LegStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_legStatus_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_LegStatus(TRUE, tvb, offset, actx, tree, hf_inap_legStatus);
}


static const ber_old_sequence_t LegInformation_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_legID_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_legStatus_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_LegInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       LegInformation_sequence, hf_index, ett_inap_LegInformation);

  return offset;
}
static int dissect_CallPartyHandlingResultsArg_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_LegInformation(FALSE, tvb, offset, actx, tree, hf_inap_CallPartyHandlingResultsArg_item);
}


static const ber_old_sequence_t CallPartyHandlingResultsArg_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_CallPartyHandlingResultsArg_item },
};

static int
dissect_inap_CallPartyHandlingResultsArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                          CallPartyHandlingResultsArg_sequence_of, hf_index, ett_inap_CallPartyHandlingResultsArg);

  return offset;
}


static const ber_old_sequence_t ChangePartiesArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callID_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_targetCallID_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_legToBeConnectedID_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_ChangePartiesArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       ChangePartiesArg_sequence, hf_index, ett_inap_ChangePartiesArg);

  return offset;
}


static const ber_old_sequence_t DetachArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_legToBeDetached_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_correlationidentifier_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_DetachArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       DetachArg_sequence, hf_index, ett_inap_DetachArg);

  return offset;
}


static const ber_old_sequence_t HoldCallPartyConnectionArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callID_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_legID_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_HoldCallPartyConnectionArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       HoldCallPartyConnectionArg_sequence, hf_index, ett_inap_HoldCallPartyConnectionArg);

  return offset;
}


static const ber_old_sequence_t ReconnectArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callID_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_heldLegID_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_ReconnectArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       ReconnectArg_sequence, hf_index, ett_inap_ReconnectArg);

  return offset;
}



static int
dissect_inap_Cause(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_releaseCause_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_Cause(TRUE, tvb, offset, actx, tree, hf_inap_releaseCause);
}
static int dissect_busyCause_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_Cause(TRUE, tvb, offset, actx, tree, hf_inap_busyCause);
}
static int dissect_initialCallSegment(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_Cause(FALSE, tvb, offset, actx, tree, hf_inap_initialCallSegment);
}
static int dissect_failureCause_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_Cause(TRUE, tvb, offset, actx, tree, hf_inap_failureCause);
}
static int dissect_releaseCauseValue_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_Cause(TRUE, tvb, offset, actx, tree, hf_inap_releaseCauseValue);
}


static const ber_old_sequence_t ReleaseCallPartyConnectionArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_legToBeReleased_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callID_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_releaseCause_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_ReleaseCallPartyConnectionArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       ReleaseCallPartyConnectionArg_sequence, hf_index, ett_inap_ReleaseCallPartyConnectionArg);

  return offset;
}



static int
dissect_inap_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_type(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_INTEGER(FALSE, tvb, offset, actx, tree, hf_inap_type);
}
static int dissect_trunkGroupID_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_INTEGER(TRUE, tvb, offset, actx, tree, hf_inap_trunkGroupID);
}
static int dissect_privateFacilityID_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_INTEGER(TRUE, tvb, offset, actx, tree, hf_inap_privateFacilityID);
}
static int dissect_facilityGroupMemberID_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_INTEGER(TRUE, tvb, offset, actx, tree, hf_inap_facilityGroupMemberID);
}


static const value_string inap_T_criticality_vals[] = {
  {   0, "ignore" },
  {   1, "abort" },
  { 0, NULL }
};


static int
dissect_inap_T_criticality(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_criticality(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_T_criticality(FALSE, tvb, offset, actx, tree, hf_inap_criticality);
}


static const ber_old_sequence_t Extensions_item_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_type },
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_criticality },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_value_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_Extensions_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       Extensions_item_sequence, hf_index, ett_inap_Extensions_item);

  return offset;
}
static int dissect_Extensions_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_Extensions_item(FALSE, tvb, offset, actx, tree, hf_inap_Extensions_item);
}


static const ber_old_sequence_t Extensions_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_Extensions_item },
};

static int
dissect_inap_Extensions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                          Extensions_sequence_of, hf_index, ett_inap_Extensions);

  return offset;
}
static int dissect_extensions_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_Extensions(TRUE, tvb, offset, actx, tree, hf_inap_extensions);
}



static int
dissect_inap_SFBillingChargingCharacteristics(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_sFBillingChargingCharacteristics_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_SFBillingChargingCharacteristics(TRUE, tvb, offset, actx, tree, hf_inap_sFBillingChargingCharacteristics);
}



static int
dissect_inap_Integer4(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_connectTime_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_Integer4(TRUE, tvb, offset, actx, tree, hf_inap_connectTime);
}
static int dissect_counterValue_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_Integer4(TRUE, tvb, offset, actx, tree, hf_inap_counterValue);
}
static int dissect_numberOfCalls_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_Integer4(TRUE, tvb, offset, actx, tree, hf_inap_numberOfCalls);
}
static int dissect_elementaryMessageID_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_Integer4(TRUE, tvb, offset, actx, tree, hf_inap_elementaryMessageID);
}
static int dissect_elementaryMessageIDs_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_Integer4(FALSE, tvb, offset, actx, tree, hf_inap_elementaryMessageIDs_item);
}
static int dissect_callConnectedElapsedTimeValue_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_Integer4(TRUE, tvb, offset, actx, tree, hf_inap_callConnectedElapsedTimeValue);
}
static int dissect_toneID_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_Integer4(TRUE, tvb, offset, actx, tree, hf_inap_toneID);
}
static int dissect_tone_duration_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_Integer4(TRUE, tvb, offset, actx, tree, hf_inap_tone_duration);
}
static int dissect_integer_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_Integer4(TRUE, tvb, offset, actx, tree, hf_inap_integer);
}



static int
dissect_inap_IA5String_SIZE_minMessageContentLength_maxMessageContentLength(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_messageContent_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_IA5String_SIZE_minMessageContentLength_maxMessageContentLength(TRUE, tvb, offset, actx, tree, hf_inap_messageContent);
}



static int
dissect_inap_OCTET_STRING_SIZE_minAttributesLength_maxAttributesLength(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_attributes_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_OCTET_STRING_SIZE_minAttributesLength_maxAttributesLength(TRUE, tvb, offset, actx, tree, hf_inap_attributes);
}


static const ber_old_sequence_t T_text_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_messageContent_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_attributes_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_text(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       T_text_sequence, hf_index, ett_inap_T_text);

  return offset;
}
static int dissect_text_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_T_text(TRUE, tvb, offset, actx, tree, hf_inap_text);
}


static const ber_old_sequence_t SEQUENCE_SIZE_1_numOfMessageIDs_OF_Integer4_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_elementaryMessageIDs_item },
};

static int
dissect_inap_SEQUENCE_SIZE_1_numOfMessageIDs_OF_Integer4(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                          SEQUENCE_SIZE_1_numOfMessageIDs_OF_Integer4_sequence_of, hf_index, ett_inap_SEQUENCE_SIZE_1_numOfMessageIDs_OF_Integer4);

  return offset;
}
static int dissect_elementaryMessageIDs_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_SEQUENCE_SIZE_1_numOfMessageIDs_OF_Integer4(TRUE, tvb, offset, actx, tree, hf_inap_elementaryMessageIDs);
}



static int
dissect_inap_Digits(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_prefix_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_Digits(TRUE, tvb, offset, actx, tree, hf_inap_prefix);
}
static int dissect_digitsResponse_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_Digits(TRUE, tvb, offset, actx, tree, hf_inap_digitsResponse);
}
static int dissect_dialledNumber_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_Digits(TRUE, tvb, offset, actx, tree, hf_inap_dialledNumber);
}
static int dissect_callingLineID_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_Digits(TRUE, tvb, offset, actx, tree, hf_inap_callingLineID);
}
static int dissect_calledAddressValue_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_Digits(TRUE, tvb, offset, actx, tree, hf_inap_calledAddressValue);
}
static int dissect_callingAddressValue_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_Digits(TRUE, tvb, offset, actx, tree, hf_inap_callingAddressValue);
}
static int dissect_lineID_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_Digits(TRUE, tvb, offset, actx, tree, hf_inap_lineID);
}
static int dissect_number_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_Digits(TRUE, tvb, offset, actx, tree, hf_inap_number);
}



static int
dissect_inap_OCTET_STRING_SIZE_2(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_time_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_OCTET_STRING_SIZE_2(TRUE, tvb, offset, actx, tree, hf_inap_time);
}



static int
dissect_inap_OCTET_STRING_SIZE_3(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_date2_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_OCTET_STRING_SIZE_3(TRUE, tvb, offset, actx, tree, hf_inap_date2);
}



static int
dissect_inap_OCTET_STRING_SIZE_4(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_price_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_OCTET_STRING_SIZE_4(TRUE, tvb, offset, actx, tree, hf_inap_price);
}


static const value_string inap_VariablePart_vals[] = {
  {   0, "integer" },
  {   1, "number" },
  {   2, "time" },
  {   3, "date2" },
  {   4, "price" },
  { 0, NULL }
};

static const ber_old_choice_t VariablePart_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_integer_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_number_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_time_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_date2_impl },
  {   4, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_price_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_VariablePart(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_choice(actx, tree, tvb, offset,
                                     VariablePart_choice, hf_index, ett_inap_VariablePart,
                                     NULL);

  return offset;
}
static int dissect_variableParts_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_VariablePart(FALSE, tvb, offset, actx, tree, hf_inap_variableParts_item);
}


static const ber_old_sequence_t SEQUENCE_SIZE_1_5_OF_VariablePart_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_variableParts_item },
};

static int
dissect_inap_SEQUENCE_SIZE_1_5_OF_VariablePart(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                          SEQUENCE_SIZE_1_5_OF_VariablePart_sequence_of, hf_index, ett_inap_SEQUENCE_SIZE_1_5_OF_VariablePart);

  return offset;
}
static int dissect_variableParts_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_SEQUENCE_SIZE_1_5_OF_VariablePart(TRUE, tvb, offset, actx, tree, hf_inap_variableParts);
}


static const ber_old_sequence_t T_variableMessage_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_elementaryMessageID_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_variableParts_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_variableMessage(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       T_variableMessage_sequence, hf_index, ett_inap_T_variableMessage);

  return offset;
}
static int dissect_variableMessage_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_T_variableMessage(TRUE, tvb, offset, actx, tree, hf_inap_variableMessage);
}


static const value_string inap_MessageID_vals[] = {
  {   0, "elementaryMessageID" },
  {   1, "text" },
  {  29, "elementaryMessageIDs" },
  {  30, "variableMessage" },
  { 0, NULL }
};

static const ber_old_choice_t MessageID_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_elementaryMessageID_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_text_impl },
  {  29, BER_CLASS_CON, 29, BER_FLAGS_IMPLTAG, dissect_elementaryMessageIDs_impl },
  {  30, BER_CLASS_CON, 30, BER_FLAGS_IMPLTAG, dissect_variableMessage_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_MessageID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_choice(actx, tree, tvb, offset,
                                     MessageID_choice, hf_index, ett_inap_MessageID,
                                     NULL);

  return offset;
}
static int dissect_messageID_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_MessageID(TRUE, tvb, offset, actx, tree, hf_inap_messageID);
}



static int
dissect_inap_INTEGER_1_127(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_minimumNbOfDigits_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_INTEGER_1_127(TRUE, tvb, offset, actx, tree, hf_inap_minimumNbOfDigits);
}
static int dissect_maximumNbOfDigits_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_INTEGER_1_127(TRUE, tvb, offset, actx, tree, hf_inap_maximumNbOfDigits);
}
static int dissect_firstDigitTimeOut_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_INTEGER_1_127(TRUE, tvb, offset, actx, tree, hf_inap_firstDigitTimeOut);
}
static int dissect_interDigitTimeOut_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_INTEGER_1_127(TRUE, tvb, offset, actx, tree, hf_inap_interDigitTimeOut);
}
static int dissect_numberOfRepetitions_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_INTEGER_1_127(TRUE, tvb, offset, actx, tree, hf_inap_numberOfRepetitions);
}



static int
dissect_inap_INTEGER_0_32767(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_duration3_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_INTEGER_0_32767(TRUE, tvb, offset, actx, tree, hf_inap_duration3);
}
static int dissect_interval_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_INTEGER_0_32767(TRUE, tvb, offset, actx, tree, hf_inap_interval);
}


static const ber_old_sequence_t InbandInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_messageID_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_numberOfRepetitions_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_duration3_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_interval_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_InbandInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       InbandInfo_sequence, hf_index, ett_inap_InbandInfo);

  return offset;
}
static int dissect_inbandInfo_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_InbandInfo(TRUE, tvb, offset, actx, tree, hf_inap_inbandInfo);
}


static const ber_old_sequence_t Tone_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_toneID_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tone_duration_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_Tone(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       Tone_sequence, hf_index, ett_inap_Tone);

  return offset;
}
static int dissect_tone_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_Tone(TRUE, tvb, offset, actx, tree, hf_inap_tone);
}



static int
dissect_inap_DisplayInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_displayInformation_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_DisplayInformation(TRUE, tvb, offset, actx, tree, hf_inap_displayInformation);
}


static const value_string inap_InformationToSend_vals[] = {
  {   0, "inbandInfo" },
  {   1, "tone" },
  {   2, "displayInformation" },
  { 0, NULL }
};

static const ber_old_choice_t InformationToSend_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inbandInfo_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_tone_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_displayInformation_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_InformationToSend(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_choice(actx, tree, tvb, offset,
                                     InformationToSend_choice, hf_index, ett_inap_InformationToSend,
                                     NULL);

  return offset;
}
static int dissect_informationToSend_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_InformationToSend(TRUE, tvb, offset, actx, tree, hf_inap_informationToSend);
}



static int
dissect_inap_MaximumNumberOfCounters(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_maximumNumberOfCounters_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_MaximumNumberOfCounters(TRUE, tvb, offset, actx, tree, hf_inap_maximumNumberOfCounters);
}


static const ber_old_sequence_t FilteredCallTreatment_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sFBillingChargingCharacteristics_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_informationToSend_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_maximumNumberOfCounters_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_releaseCause_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_FilteredCallTreatment(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       FilteredCallTreatment_sequence, hf_index, ett_inap_FilteredCallTreatment);

  return offset;
}
static int dissect_filteredCallTreatment_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_FilteredCallTreatment(TRUE, tvb, offset, actx, tree, hf_inap_filteredCallTreatment);
}



static int
dissect_inap_INTEGER_M1_32000(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_interval1_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_INTEGER_M1_32000(TRUE, tvb, offset, actx, tree, hf_inap_interval1);
}


static const value_string inap_FilteringCharacteristics_vals[] = {
  {   0, "interval1" },
  {   1, "numberOfCalls" },
  { 0, NULL }
};

static const ber_old_choice_t FilteringCharacteristics_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_interval1_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_numberOfCalls_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_FilteringCharacteristics(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_choice(actx, tree, tvb, offset,
                                     FilteringCharacteristics_choice, hf_index, ett_inap_FilteringCharacteristics,
                                     NULL);

  return offset;
}
static int dissect_filteringCharacteristics_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_FilteringCharacteristics(TRUE, tvb, offset, actx, tree, hf_inap_filteringCharacteristics);
}



static int
dissect_inap_Duration(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_monitorDuration_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_Duration(TRUE, tvb, offset, actx, tree, hf_inap_monitorDuration);
}
static int dissect_duration_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_Duration(TRUE, tvb, offset, actx, tree, hf_inap_duration);
}



static int
dissect_inap_DateAndTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_startTime_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_DateAndTime(TRUE, tvb, offset, actx, tree, hf_inap_startTime);
}
static int dissect_stopTime_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_DateAndTime(TRUE, tvb, offset, actx, tree, hf_inap_stopTime);
}
static int dissect_callStopTimeValue_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_DateAndTime(TRUE, tvb, offset, actx, tree, hf_inap_callStopTimeValue);
}


static const value_string inap_FilteringTimeOut_vals[] = {
  {   0, "duration" },
  {   1, "stopTime" },
  { 0, NULL }
};

static const ber_old_choice_t FilteringTimeOut_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_duration_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_stopTime_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_FilteringTimeOut(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_choice(actx, tree, tvb, offset,
                                     FilteringTimeOut_choice, hf_index, ett_inap_FilteringTimeOut,
                                     NULL);

  return offset;
}
static int dissect_filteringTimeOut_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_FilteringTimeOut(TRUE, tvb, offset, actx, tree, hf_inap_filteringTimeOut);
}



static int
dissect_inap_ServiceKey(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_inap_Integer4(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_serviceKey_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_ServiceKey(TRUE, tvb, offset, actx, tree, hf_inap_serviceKey);
}



static int
dissect_inap_LocationNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_locationNumber_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_LocationNumber(TRUE, tvb, offset, actx, tree, hf_inap_locationNumber);
}


static const ber_old_sequence_t T_addressAndService_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_calledAddressValue_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_serviceKey_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingAddressValue_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationNumber_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_addressAndService(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       T_addressAndService_sequence, hf_index, ett_inap_T_addressAndService);

  return offset;
}
static int dissect_addressAndService_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_T_addressAndService(TRUE, tvb, offset, actx, tree, hf_inap_addressAndService);
}


static const value_string inap_FilteringCriteria_vals[] = {
  {   0, "dialledNumber" },
  {   1, "callingLineID" },
  {   2, "serviceKey" },
  {  30, "addressAndService" },
  { 0, NULL }
};

static const ber_old_choice_t FilteringCriteria_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_dialledNumber_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_callingLineID_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_serviceKey_impl },
  {  30, BER_CLASS_CON, 30, BER_FLAGS_IMPLTAG, dissect_addressAndService_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_FilteringCriteria(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_choice(actx, tree, tvb, offset,
                                     FilteringCriteria_choice, hf_index, ett_inap_FilteringCriteria,
                                     NULL);

  return offset;
}
static int dissect_filteringCriteria_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_FilteringCriteria(TRUE, tvb, offset, actx, tree, hf_inap_filteringCriteria);
}


static const ber_old_sequence_t ActivateServiceFilteringArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_filteredCallTreatment_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_filteringCharacteristics_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_filteringTimeOut_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_filteringCriteria_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_startTime_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_ActivateServiceFilteringArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       ActivateServiceFilteringArg_sequence, hf_index, ett_inap_ActivateServiceFilteringArg);

  return offset;
}


static const value_string inap_T_messageType_vals[] = {
  {   0, "request" },
  {   1, "notification" },
  { 0, NULL }
};


static int
dissect_inap_T_messageType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_messageType_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_T_messageType(TRUE, tvb, offset, actx, tree, hf_inap_messageType);
}


static const value_string inap_T_dpAssignment_vals[] = {
  {   0, "individualLine" },
  {   1, "groupBased" },
  {   2, "officeBased" },
  { 0, NULL }
};


static int
dissect_inap_T_dpAssignment(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_dpAssignment_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_T_dpAssignment(TRUE, tvb, offset, actx, tree, hf_inap_dpAssignment);
}


static const ber_old_sequence_t MiscCallInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_messageType_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dpAssignment_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_MiscCallInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       MiscCallInfo_sequence, hf_index, ett_inap_MiscCallInfo);

  return offset;
}
static int dissect_miscCallInfo_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_MiscCallInfo(TRUE, tvb, offset, actx, tree, hf_inap_miscCallInfo);
}


static const value_string inap_TriggerType_vals[] = {
  {   0, "featureActivation" },
  {   1, "verticalServiceCode" },
  {   2, "customizedAccess" },
  {   3, "customizedIntercom" },
  {  12, "emergencyService" },
  {  13, "aFR" },
  {  14, "sharedIOTrunk" },
  {  17, "offHookDelay" },
  {  18, "channelSetupPRI" },
  {  25, "tNoAnswer" },
  {  26, "tBusy" },
  {  27, "oCalledPartyBusy" },
  {  29, "oNoAnswer" },
  {  30, "originationAttemptAuthorized" },
  {  31, "oAnswer" },
  {  32, "oDisconnect" },
  {  33, "termAttemptAuthorized" },
  {  34, "tAnswer" },
  {  35, "tDisconnect" },
  { 0, NULL }
};


static int
dissect_inap_TriggerType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_triggerType_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_TriggerType(TRUE, tvb, offset, actx, tree, hf_inap_triggerType);
}


static const ber_old_sequence_t ServiceAddressInformation_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_serviceKey_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_miscCallInfo_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_triggerType_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_ServiceAddressInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       ServiceAddressInformation_sequence, hf_index, ett_inap_ServiceAddressInformation);

  return offset;
}
static int dissect_serviceAddressInformation_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_ServiceAddressInformation(TRUE, tvb, offset, actx, tree, hf_inap_serviceAddressInformation);
}



static int
dissect_inap_BearerCap(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 128 "inap.cnf"

 tvbuff_t	*parameter_tvb;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


 if (!parameter_tvb)
	return offset;

 dissect_q931_bearer_capability_ie(parameter_tvb, 0, tvb_length_remaining(parameter_tvb,0), tree);



  return offset;
}
static int dissect_bearerCap_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_BearerCap(TRUE, tvb, offset, actx, tree, hf_inap_bearerCap);
}



static int
dissect_inap_OCTET_STRING_SIZE_1(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_tmr_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_OCTET_STRING_SIZE_1(TRUE, tvb, offset, actx, tree, hf_inap_tmr);
}


static const value_string inap_BearerCapability_vals[] = {
  {   0, "bearerCap" },
  {   1, "tmr" },
  { 0, NULL }
};

static const ber_old_choice_t BearerCapability_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_bearerCap_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_tmr_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_BearerCapability(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_choice(actx, tree, tvb, offset,
                                     BearerCapability_choice, hf_index, ett_inap_BearerCapability,
                                     NULL);

  return offset;
}
static int dissect_bearerCapability_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_BearerCapability(TRUE, tvb, offset, actx, tree, hf_inap_bearerCapability);
}



static int
dissect_inap_CalledPartyNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 99 "inap.cnf"
  tvbuff_t *parameter_tvb;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


 if (!parameter_tvb)
	return offset;

dissect_isup_called_party_number_parameter(parameter_tvb, tree, NULL);



  return offset;
}
static int dissect_dialledDigits_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_CalledPartyNumber(TRUE, tvb, offset, actx, tree, hf_inap_dialledDigits);
}
static int dissect_calledPartyNumber_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_CalledPartyNumber(TRUE, tvb, offset, actx, tree, hf_inap_calledPartyNumber);
}
static int dissect_destinationNumberRoutingAddress_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_CalledPartyNumber(TRUE, tvb, offset, actx, tree, hf_inap_destinationNumberRoutingAddress);
}
static int dissect_DestinationRoutingAddress_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_CalledPartyNumber(FALSE, tvb, offset, actx, tree, hf_inap_DestinationRoutingAddress_item);
}
static int dissect_calledPartynumber_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_CalledPartyNumber(TRUE, tvb, offset, actx, tree, hf_inap_calledPartynumber);
}



static int
dissect_inap_CallingPartyNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 113 "inap.cnf"
  tvbuff_t *parameter_tvb;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


 if (!parameter_tvb)
	return offset;

	dissect_isup_calling_party_number_parameter(parameter_tvb, tree, NULL);




  return offset;
}
static int dissect_callingPartyNumber_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_CallingPartyNumber(TRUE, tvb, offset, actx, tree, hf_inap_callingPartyNumber);
}



static int
dissect_inap_CallingPartysCategory(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_callingPartysCategory_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_CallingPartysCategory(TRUE, tvb, offset, actx, tree, hf_inap_callingPartysCategory);
}



static int
dissect_inap_IPSSPCapabilities(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_iPSSPCapabilities_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_IPSSPCapabilities(TRUE, tvb, offset, actx, tree, hf_inap_iPSSPCapabilities);
}



static int
dissect_inap_IPAvailable(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_iPAvailable_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_IPAvailable(TRUE, tvb, offset, actx, tree, hf_inap_iPAvailable);
}



static int
dissect_inap_ISDNAccessRelatedInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_iSDNAccessRelatedInformation_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_ISDNAccessRelatedInformation(TRUE, tvb, offset, actx, tree, hf_inap_iSDNAccessRelatedInformation);
}


static const value_string inap_CGEncountered_vals[] = {
  {   0, "noCGencountered" },
  {   1, "manualCGencountered" },
  {   2, "scpOverload" },
  { 0, NULL }
};


static int
dissect_inap_CGEncountered(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_cGEncountered_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_CGEncountered(TRUE, tvb, offset, actx, tree, hf_inap_cGEncountered);
}



static int
dissect_inap_ServiceProfileIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_serviceProfileIdentifier_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_ServiceProfileIdentifier(TRUE, tvb, offset, actx, tree, hf_inap_serviceProfileIdentifier);
}


static const value_string inap_TerminalType_vals[] = {
  {   0, "unknown" },
  {   1, "dialPulse" },
  {   2, "dtmf" },
  {   3, "isdn" },
  {   4, "isdnNoDtmf" },
  {  16, "spare" },
  { 0, NULL }
};


static int
dissect_inap_TerminalType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_terminalType_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_TerminalType(TRUE, tvb, offset, actx, tree, hf_inap_terminalType);
}



static int
dissect_inap_ChargeNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_inap_LocationNumber(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_chargeNumber_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_ChargeNumber(TRUE, tvb, offset, actx, tree, hf_inap_chargeNumber);
}



static int
dissect_inap_ServingAreaID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_inap_LocationNumber(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_servingAreaID_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_ServingAreaID(TRUE, tvb, offset, actx, tree, hf_inap_servingAreaID);
}


static const ber_old_sequence_t DpSpecificCommonParameters_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_serviceAddressInformation_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_bearerCapability_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_calledPartyNumber_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumber_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartysCategory_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iPSSPCapabilities_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iPAvailable_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iSDNAccessRelatedInformation_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cGEncountered_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationNumber_impl },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_serviceProfileIdentifier_impl },
  { BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminalType_impl },
  { BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_chargeNumber_impl },
  { BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_servingAreaID_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_DpSpecificCommonParameters(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       DpSpecificCommonParameters_sequence, hf_index, ett_inap_DpSpecificCommonParameters);

  return offset;
}
static int dissect_dpSpecificCommonParameters_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_DpSpecificCommonParameters(TRUE, tvb, offset, actx, tree, hf_inap_dpSpecificCommonParameters);
}



static int
dissect_inap_CallingPartyBusinessGroupID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_callingPartyBusinessGroupID_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_CallingPartyBusinessGroupID(TRUE, tvb, offset, actx, tree, hf_inap_callingPartyBusinessGroupID);
}



static int
dissect_inap_CallingPartySubaddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_callingPartySubaddress_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_CallingPartySubaddress(TRUE, tvb, offset, actx, tree, hf_inap_callingPartySubaddress);
}


static const value_string inap_FacilityGroup_vals[] = {
  {   0, "trunkGroupID" },
  {   1, "privateFacilityID" },
  {   2, "huntGroup" },
  {   3, "routeIndex" },
  { 0, NULL }
};

static const ber_old_choice_t FacilityGroup_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_trunkGroupID_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_privateFacilityID_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_huntGroup_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_routeIndex_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_FacilityGroup(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_choice(actx, tree, tvb, offset,
                                     FacilityGroup_choice, hf_index, ett_inap_FacilityGroup,
                                     NULL);

  return offset;
}
static int dissect_callingFacilityGroup_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_FacilityGroup(TRUE, tvb, offset, actx, tree, hf_inap_callingFacilityGroup);
}
static int dissect_calledFacilityGroup_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_FacilityGroup(TRUE, tvb, offset, actx, tree, hf_inap_calledFacilityGroup);
}
static int dissect_facilityGroupID_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_FacilityGroup(TRUE, tvb, offset, actx, tree, hf_inap_facilityGroupID);
}



static int
dissect_inap_FacilityGroupMember(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_callingFacilityGroupMember_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_FacilityGroupMember(TRUE, tvb, offset, actx, tree, hf_inap_callingFacilityGroupMember);
}
static int dissect_calledFacilityGroupMember_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_FacilityGroupMember(TRUE, tvb, offset, actx, tree, hf_inap_calledFacilityGroupMember);
}



static int
dissect_inap_OriginalCalledPartyID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 158 "inap.cnf"

 tvbuff_t	*parameter_tvb;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


 if (!parameter_tvb)
	return offset;
 dissect_isup_original_called_number_parameter(parameter_tvb, tree, NULL);



  return offset;
}
static int dissect_originalCalledPartyID_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_OriginalCalledPartyID(TRUE, tvb, offset, actx, tree, hf_inap_originalCalledPartyID);
}



static int
dissect_inap_RedirectingPartyID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 172 "inap.cnf"

 tvbuff_t	*parameter_tvb;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


 if (!parameter_tvb)
	return offset;
 dissect_isup_redirecting_number_parameter(parameter_tvb, tree, NULL);




  return offset;
}
static int dissect_redirectingPartyID_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_RedirectingPartyID(TRUE, tvb, offset, actx, tree, hf_inap_redirectingPartyID);
}



static int
dissect_inap_RedirectionInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 143 "inap.cnf"

 tvbuff_t	*parameter_tvb;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


 if (!parameter_tvb)
	return offset;

 dissect_isup_redirection_information_parameter(parameter_tvb, tree, NULL);



  return offset;
}
static int dissect_redirectionInformation_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_RedirectionInformation(TRUE, tvb, offset, actx, tree, hf_inap_redirectionInformation);
}


static const ber_old_sequence_t RouteList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_RouteList_item },
};

static int
dissect_inap_RouteList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                          RouteList_sequence_of, hf_index, ett_inap_RouteList);

  return offset;
}
static int dissect_routeList_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_RouteList(TRUE, tvb, offset, actx, tree, hf_inap_routeList);
}



static int
dissect_inap_TravellingClassMark(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_inap_LocationNumber(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_travellingClassMark_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_TravellingClassMark(TRUE, tvb, offset, actx, tree, hf_inap_travellingClassMark);
}



static int
dissect_inap_FeatureCode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_inap_LocationNumber(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_featureCode_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_FeatureCode(TRUE, tvb, offset, actx, tree, hf_inap_featureCode);
}



static int
dissect_inap_AccessCode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_inap_LocationNumber(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_accessCode_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_AccessCode(TRUE, tvb, offset, actx, tree, hf_inap_accessCode);
}



static int
dissect_inap_Carrier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_carrier_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_Carrier(TRUE, tvb, offset, actx, tree, hf_inap_carrier);
}


static const ber_old_sequence_t AnalysedInformationArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_dpSpecificCommonParameters_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dialledDigits_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyBusinessGroupID_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartySubaddress_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_callingFacilityGroup_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingFacilityGroupMember_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_originalCalledPartyID_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_prefix_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingPartyID_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectionInformation_impl },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_routeList_impl },
  { BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_travellingClassMark_impl },
  { BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_featureCode_impl },
  { BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_accessCode_impl },
  { BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_carrier_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_AnalysedInformationArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       AnalysedInformationArg_sequence, hf_index, ett_inap_AnalysedInformationArg);

  return offset;
}


static const ber_old_sequence_t DestinationRoutingAddress_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_DestinationRoutingAddress_item },
};

static int
dissect_inap_DestinationRoutingAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                          DestinationRoutingAddress_sequence_of, hf_index, ett_inap_DestinationRoutingAddress);

  return offset;
}
static int dissect_destinationRoutingAddress_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_DestinationRoutingAddress(TRUE, tvb, offset, actx, tree, hf_inap_destinationRoutingAddress);
}



static int
dissect_inap_AlertingPattern(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_alertingPattern_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_AlertingPattern(TRUE, tvb, offset, actx, tree, hf_inap_alertingPattern);
}


static const ber_old_sequence_t AnalyseInformationArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_destinationRoutingAddress_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_alertingPattern_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iSDNAccessRelatedInformation_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_originalCalledPartyID_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumber_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartysCategory_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_calledPartyNumber_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_chargeNumber_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_travellingClassMark_impl },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_carrier_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_AnalyseInformationArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       AnalyseInformationArg_sequence, hf_index, ett_inap_AnalyseInformationArg);

  return offset;
}



static int
dissect_inap_AChBillingChargingCharacteristics(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_aChBillingChargingCharacteristics_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_AChBillingChargingCharacteristics(TRUE, tvb, offset, actx, tree, hf_inap_aChBillingChargingCharacteristics);
}


static const ber_old_sequence_t ApplyChargingArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_aChBillingChargingCharacteristics_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_partyToCharge_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_ApplyChargingArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       ApplyChargingArg_sequence, hf_index, ett_inap_ApplyChargingArg);

  return offset;
}



static int
dissect_inap_CallResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_ApplyChargingReportArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_inap_CallResult(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_inap_CorrelationID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_inap_Digits(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_correlationID_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_CorrelationID(TRUE, tvb, offset, actx, tree, hf_inap_correlationID);
}
static int dissect_bcsmEventCorrelationID_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_CorrelationID(TRUE, tvb, offset, actx, tree, hf_inap_bcsmEventCorrelationID);
}


static const ber_old_sequence_t AssistRequestInstructionsArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_correlationID_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iPAvailable_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iPSSPCapabilities_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_AssistRequestInstructionsArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       AssistRequestInstructionsArg_sequence, hf_index, ett_inap_AssistRequestInstructionsArg);

  return offset;
}


static const value_string inap_EventTypeBCSM_vals[] = {
  {   1, "origAttemptAuthorized" },
  {   2, "collectedInfo" },
  {   3, "analysedInformation" },
  {   4, "routeSelectFailure" },
  {   5, "oCalledPartyBusy" },
  {   6, "oNoAnswer" },
  {   7, "oAnswer" },
  {   8, "oMidCall" },
  {   9, "oDisconnect" },
  {  10, "oAbandon" },
  {  12, "termAttemptAuthorized" },
  {  13, "tBusy" },
  {  14, "tNoAnswer" },
  {  15, "tAnswer" },
  {  16, "tMidCall" },
  {  17, "tDisconnect" },
  {  18, "tAbandon" },
  { 0, NULL }
};


static int
dissect_inap_EventTypeBCSM(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_eventTypeBCSM_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_EventTypeBCSM(TRUE, tvb, offset, actx, tree, hf_inap_eventTypeBCSM);
}
static int dissect_dpCriteria_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_EventTypeBCSM(TRUE, tvb, offset, actx, tree, hf_inap_dpCriteria);
}


static const ber_old_sequence_t GapOnService_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_serviceKey_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dpCriteria_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_GapOnService(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       GapOnService_sequence, hf_index, ett_inap_GapOnService);

  return offset;
}
static int dissect_gapOnService_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_GapOnService(TRUE, tvb, offset, actx, tree, hf_inap_gapOnService);
}


static const ber_old_sequence_t T_calledAddressAndService_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_calledAddressValue_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_serviceKey_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_calledAddressAndService(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       T_calledAddressAndService_sequence, hf_index, ett_inap_T_calledAddressAndService);

  return offset;
}
static int dissect_calledAddressAndService_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_T_calledAddressAndService(TRUE, tvb, offset, actx, tree, hf_inap_calledAddressAndService);
}


static const ber_old_sequence_t T_callingAddressAndService_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_callingAddressValue_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_serviceKey_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationNumber_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_callingAddressAndService(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       T_callingAddressAndService_sequence, hf_index, ett_inap_T_callingAddressAndService);

  return offset;
}
static int dissect_callingAddressAndService_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_T_callingAddressAndService(TRUE, tvb, offset, actx, tree, hf_inap_callingAddressAndService);
}


static const value_string inap_GapCriteria_vals[] = {
  {   0, "calledAddressValue" },
  {   2, "gapOnService" },
  {  29, "calledAddressAndService" },
  {  30, "callingAddressAndService" },
  { 0, NULL }
};

static const ber_old_choice_t GapCriteria_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_calledAddressValue_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_gapOnService_impl },
  {  29, BER_CLASS_CON, 29, BER_FLAGS_IMPLTAG, dissect_calledAddressAndService_impl },
  {  30, BER_CLASS_CON, 30, BER_FLAGS_IMPLTAG, dissect_callingAddressAndService_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_GapCriteria(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_choice(actx, tree, tvb, offset,
                                     GapCriteria_choice, hf_index, ett_inap_GapCriteria,
                                     NULL);

  return offset;
}
static int dissect_gapCriteria_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_GapCriteria(TRUE, tvb, offset, actx, tree, hf_inap_gapCriteria);
}



static int
dissect_inap_Interval(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_gapInterval_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_Interval(TRUE, tvb, offset, actx, tree, hf_inap_gapInterval);
}


static const ber_old_sequence_t GapIndicators_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_duration_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gapInterval_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_GapIndicators(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       GapIndicators_sequence, hf_index, ett_inap_GapIndicators);

  return offset;
}
static int dissect_gapIndicators_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_GapIndicators(TRUE, tvb, offset, actx, tree, hf_inap_gapIndicators);
}


static const value_string inap_ControlType_vals[] = {
  {   0, "sCPOverloaded" },
  {   1, "manuallyInitiated" },
  {   2, "destinationOverload" },
  { 0, NULL }
};


static int
dissect_inap_ControlType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_controlType_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_ControlType(TRUE, tvb, offset, actx, tree, hf_inap_controlType);
}


static const ber_old_sequence_t T_both_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_informationToSend_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_releaseCause_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_both(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       T_both_sequence, hf_index, ett_inap_T_both);

  return offset;
}
static int dissect_both_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_T_both(TRUE, tvb, offset, actx, tree, hf_inap_both);
}


static const value_string inap_GapTreatment_vals[] = {
  {   0, "informationToSend" },
  {   1, "releaseCause" },
  {   2, "both" },
  { 0, NULL }
};

static const ber_old_choice_t GapTreatment_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_informationToSend_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_releaseCause_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_both_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_GapTreatment(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_choice(actx, tree, tvb, offset,
                                     GapTreatment_choice, hf_index, ett_inap_GapTreatment,
                                     NULL);

  return offset;
}
static int dissect_gapTreatment_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_GapTreatment(TRUE, tvb, offset, actx, tree, hf_inap_gapTreatment);
}


static const ber_old_sequence_t CallGapArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gapCriteria_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gapIndicators_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_controlType_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gapTreatment_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_CallGapArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       CallGapArg_sequence, hf_index, ett_inap_CallGapArg);

  return offset;
}


static const value_string inap_RequestedInformationType_vals[] = {
  {   0, "callAttemptElapsedTime" },
  {   1, "callStopTime" },
  {   2, "callConnectedElapsedTime" },
  {   3, "calledAddress" },
  {  30, "releaseCause" },
  { 0, NULL }
};


static int
dissect_inap_RequestedInformationType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_RequestedInformationTypeList_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_RequestedInformationType(FALSE, tvb, offset, actx, tree, hf_inap_RequestedInformationTypeList_item);
}
static int dissect_requestedInformationType_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_RequestedInformationType(TRUE, tvb, offset, actx, tree, hf_inap_requestedInformationType);
}


static const ber_old_sequence_t RequestedInformationTypeList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_RequestedInformationTypeList_item },
};

static int
dissect_inap_RequestedInformationTypeList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                          RequestedInformationTypeList_sequence_of, hf_index, ett_inap_RequestedInformationTypeList);

  return offset;
}
static int dissect_requestedInformationTypeList_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_RequestedInformationTypeList(TRUE, tvb, offset, actx, tree, hf_inap_requestedInformationTypeList);
}


static const ber_old_sequence_t CallInformationReportArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_requestedInformationTypeList_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_correlationID_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_CallInformationReportArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       CallInformationReportArg_sequence, hf_index, ett_inap_CallInformationReportArg);

  return offset;
}


static const ber_old_sequence_t CallInformationRequestArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_requestedInformationTypeList_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_correlationID_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_legID_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_CallInformationRequestArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       CallInformationRequestArg_sequence, hf_index, ett_inap_CallInformationRequestArg);

  return offset;
}



static int
dissect_inap_InvokeID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_invokeID_01_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_InvokeID(TRUE, tvb, offset, actx, tree, hf_inap_invokeID_01);
}


static const value_string inap_CancelArg_vals[] = {
  {   0, "invokeID" },
  {   1, "allRequests" },
  { 0, NULL }
};

static const ber_old_choice_t CancelArg_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_invokeID_01_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_allRequests_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_CancelArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_choice(actx, tree, tvb, offset,
                                     CancelArg_choice, hf_index, ett_inap_CancelArg,
                                     NULL);

  return offset;
}


static const value_string inap_ResourceID_vals[] = {
  {   0, "lineID" },
  {   1, "facilityGroupID" },
  {   2, "facilityGroupMemberID" },
  {   3, "trunkGroupID" },
  { 0, NULL }
};

static const ber_old_choice_t ResourceID_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_lineID_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_facilityGroupID_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_facilityGroupMemberID_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_trunkGroupID_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_ResourceID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_choice(actx, tree, tvb, offset,
                                     ResourceID_choice, hf_index, ett_inap_ResourceID,
                                     NULL);

  return offset;
}
static int dissect_resourceID_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_ResourceID(TRUE, tvb, offset, actx, tree, hf_inap_resourceID);
}


static const ber_old_sequence_t CancelStatusReportRequestArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_resourceID_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_CancelStatusReportRequestArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       CancelStatusReportRequestArg_sequence, hf_index, ett_inap_CancelStatusReportRequestArg);

  return offset;
}


static const ber_old_sequence_t CollectedInformationArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_dpSpecificCommonParameters_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dialledDigits_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyBusinessGroupID_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartySubaddress_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_callingFacilityGroup_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingFacilityGroupMember_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_originalCalledPartyID_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_prefix_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingPartyID_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectionInformation_impl },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_travellingClassMark_impl },
  { BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_featureCode_impl },
  { BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_accessCode_impl },
  { BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_carrier_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_CollectedInformationArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       CollectedInformationArg_sequence, hf_index, ett_inap_CollectedInformationArg);

  return offset;
}



static int
dissect_inap_NumberingPlan(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_numberingPlan_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_NumberingPlan(TRUE, tvb, offset, actx, tree, hf_inap_numberingPlan);
}


static const ber_old_sequence_t CollectInformationArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_alertingPattern_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_numberingPlan_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_originalCalledPartyID_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_travellingClassMark_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumber_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dialledDigits_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_CollectInformationArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       CollectInformationArg_sequence, hf_index, ett_inap_CollectInformationArg);

  return offset;
}



static int
dissect_inap_CutAndPaste(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_cutAndPaste_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_CutAndPaste(TRUE, tvb, offset, actx, tree, hf_inap_cutAndPaste);
}


static const value_string inap_ForwardingCondition_vals[] = {
  {   0, "busy" },
  {   1, "noanswer" },
  {   2, "any" },
  { 0, NULL }
};


static int
dissect_inap_ForwardingCondition(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_forwardingCondition_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_ForwardingCondition(TRUE, tvb, offset, actx, tree, hf_inap_forwardingCondition);
}



static int
dissect_inap_ScfID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_scfID_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_ScfID(TRUE, tvb, offset, actx, tree, hf_inap_scfID);
}



static int
dissect_inap_ServiceInteractionIndicators(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_serviceInteractionIndicators_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_ServiceInteractionIndicators(TRUE, tvb, offset, actx, tree, hf_inap_serviceInteractionIndicators);
}


static const ber_old_sequence_t ConnectArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_destinationRoutingAddress_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_alertingPattern_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_correlationID_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cutAndPaste_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_forwardingCondition_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iSDNAccessRelatedInformation_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_originalCalledPartyID_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_routeList_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_scfID_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_travellingClassMark_impl },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_carrier_impl },
  { BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_serviceInteractionIndicators_impl },
  { BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumber_impl },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartysCategory_impl },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingPartyID_impl },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectionInformation_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_ConnectArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       ConnectArg_sequence, hf_index, ett_inap_ConnectArg);

  return offset;
}



static int
dissect_inap_IPRoutingAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_inap_CalledPartyNumber(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_ipRoutingAddress_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_IPRoutingAddress(TRUE, tvb, offset, actx, tree, hf_inap_ipRoutingAddress);
}


static const ber_old_sequence_t T_both2_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ipRoutingAddress_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_legID_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_both2(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       T_both2_sequence, hf_index, ett_inap_T_both2);

  return offset;
}
static int dissect_both2_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_T_both2(TRUE, tvb, offset, actx, tree, hf_inap_both2);
}


static const value_string inap_T_resourceAddress_vals[] = {
  {   0, "ipRoutingAddress" },
  {   1, "legID" },
  {   2, "both2" },
  {   3, "none" },
  { 0, NULL }
};

static const ber_old_choice_t T_resourceAddress_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ipRoutingAddress_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_legID_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_both2_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_none_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_T_resourceAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_choice(actx, tree, tvb, offset,
                                     T_resourceAddress_choice, hf_index, ett_inap_T_resourceAddress,
                                     NULL);

  return offset;
}
static int dissect_resourceAddress(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_T_resourceAddress(FALSE, tvb, offset, actx, tree, hf_inap_resourceAddress);
}


static const ber_old_sequence_t ConnectToResourceArg_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_resourceAddress },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_serviceInteractionIndicators_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_ConnectToResourceArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       ConnectToResourceArg_sequence, hf_index, ett_inap_ConnectToResourceArg);

  return offset;
}



static int
dissect_inap_AssistingSSPIPRoutingAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_inap_Digits(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_assistingSSPIPRoutingAddress_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_AssistingSSPIPRoutingAddress(TRUE, tvb, offset, actx, tree, hf_inap_assistingSSPIPRoutingAddress);
}


static const ber_old_sequence_t EstablishTemporaryConnectionArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_assistingSSPIPRoutingAddress_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_correlationID_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_legID_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_scfID_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_carrier_impl },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_serviceInteractionIndicators_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_EstablishTemporaryConnectionArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       EstablishTemporaryConnectionArg_sequence, hf_index, ett_inap_EstablishTemporaryConnectionArg);

  return offset;
}



static int
dissect_inap_EventTypeCharging(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_eventTypeCharging_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_EventTypeCharging(TRUE, tvb, offset, actx, tree, hf_inap_eventTypeCharging);
}



static int
dissect_inap_EventSpecificInformationCharging(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_eventSpecificInformationCharging_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_EventSpecificInformationCharging(TRUE, tvb, offset, actx, tree, hf_inap_eventSpecificInformationCharging);
}


static const value_string inap_MonitorMode_vals[] = {
  {   0, "interrupted" },
  {   1, "notifyAndContinue" },
  {   2, "transparent" },
  { 0, NULL }
};


static int
dissect_inap_MonitorMode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_monitorMode_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_MonitorMode(TRUE, tvb, offset, actx, tree, hf_inap_monitorMode);
}


static const ber_old_sequence_t EventNotificationChargingArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_eventTypeCharging_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_eventSpecificInformationCharging_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_legID_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_monitorMode_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_EventNotificationChargingArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       EventNotificationChargingArg_sequence, hf_index, ett_inap_EventNotificationChargingArg);

  return offset;
}


static const ber_old_sequence_t T_collectedInfoSpecificInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_calledPartynumber_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_collectedInfoSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       T_collectedInfoSpecificInfo_sequence, hf_index, ett_inap_T_collectedInfoSpecificInfo);

  return offset;
}
static int dissect_collectedInfoSpecificInfo_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_T_collectedInfoSpecificInfo(TRUE, tvb, offset, actx, tree, hf_inap_collectedInfoSpecificInfo);
}


static const ber_old_sequence_t T_analyzedInfoSpecificInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_calledPartynumber_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_analyzedInfoSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       T_analyzedInfoSpecificInfo_sequence, hf_index, ett_inap_T_analyzedInfoSpecificInfo);

  return offset;
}
static int dissect_analyzedInfoSpecificInfo_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_T_analyzedInfoSpecificInfo(TRUE, tvb, offset, actx, tree, hf_inap_analyzedInfoSpecificInfo);
}


static const ber_old_sequence_t T_routeSelectFailureSpecificInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_failureCause_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_routeSelectFailureSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       T_routeSelectFailureSpecificInfo_sequence, hf_index, ett_inap_T_routeSelectFailureSpecificInfo);

  return offset;
}
static int dissect_routeSelectFailureSpecificInfo_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_T_routeSelectFailureSpecificInfo(TRUE, tvb, offset, actx, tree, hf_inap_routeSelectFailureSpecificInfo);
}


static const ber_old_sequence_t T_oCalledPartyBusySpecificInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_busyCause_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_oCalledPartyBusySpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       T_oCalledPartyBusySpecificInfo_sequence, hf_index, ett_inap_T_oCalledPartyBusySpecificInfo);

  return offset;
}
static int dissect_oCalledPartyBusySpecificInfo_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_T_oCalledPartyBusySpecificInfo(TRUE, tvb, offset, actx, tree, hf_inap_oCalledPartyBusySpecificInfo);
}


static const ber_old_sequence_t T_oNoAnswerSpecificInfo_sequence[] = {
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_oNoAnswerSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       T_oNoAnswerSpecificInfo_sequence, hf_index, ett_inap_T_oNoAnswerSpecificInfo);

  return offset;
}
static int dissect_oNoAnswerSpecificInfo_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_T_oNoAnswerSpecificInfo(TRUE, tvb, offset, actx, tree, hf_inap_oNoAnswerSpecificInfo);
}


static const ber_old_sequence_t T_oAnswerSpecificInfo_sequence[] = {
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_oAnswerSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       T_oAnswerSpecificInfo_sequence, hf_index, ett_inap_T_oAnswerSpecificInfo);

  return offset;
}
static int dissect_oAnswerSpecificInfo_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_T_oAnswerSpecificInfo(TRUE, tvb, offset, actx, tree, hf_inap_oAnswerSpecificInfo);
}


static const ber_old_sequence_t T_oMidCallSpecificInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_connectTime_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_oMidCallSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       T_oMidCallSpecificInfo_sequence, hf_index, ett_inap_T_oMidCallSpecificInfo);

  return offset;
}
static int dissect_oMidCallSpecificInfo_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_T_oMidCallSpecificInfo(TRUE, tvb, offset, actx, tree, hf_inap_oMidCallSpecificInfo);
}


static const ber_old_sequence_t T_oDisconnectSpecificInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_releaseCause_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_connectTime_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_oDisconnectSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       T_oDisconnectSpecificInfo_sequence, hf_index, ett_inap_T_oDisconnectSpecificInfo);

  return offset;
}
static int dissect_oDisconnectSpecificInfo_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_T_oDisconnectSpecificInfo(TRUE, tvb, offset, actx, tree, hf_inap_oDisconnectSpecificInfo);
}


static const ber_old_sequence_t T_tBusySpecificInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_busyCause_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_tBusySpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       T_tBusySpecificInfo_sequence, hf_index, ett_inap_T_tBusySpecificInfo);

  return offset;
}
static int dissect_tBusySpecificInfo_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_T_tBusySpecificInfo(TRUE, tvb, offset, actx, tree, hf_inap_tBusySpecificInfo);
}


static const ber_old_sequence_t T_tNoAnswerSpecificInfo_sequence[] = {
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_tNoAnswerSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       T_tNoAnswerSpecificInfo_sequence, hf_index, ett_inap_T_tNoAnswerSpecificInfo);

  return offset;
}
static int dissect_tNoAnswerSpecificInfo_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_T_tNoAnswerSpecificInfo(TRUE, tvb, offset, actx, tree, hf_inap_tNoAnswerSpecificInfo);
}


static const ber_old_sequence_t T_tAnswerSpecificInfo_sequence[] = {
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_tAnswerSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       T_tAnswerSpecificInfo_sequence, hf_index, ett_inap_T_tAnswerSpecificInfo);

  return offset;
}
static int dissect_tAnswerSpecificInfo_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_T_tAnswerSpecificInfo(TRUE, tvb, offset, actx, tree, hf_inap_tAnswerSpecificInfo);
}


static const ber_old_sequence_t T_tMidCallSpecificInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_connectTime_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_tMidCallSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       T_tMidCallSpecificInfo_sequence, hf_index, ett_inap_T_tMidCallSpecificInfo);

  return offset;
}
static int dissect_tMidCallSpecificInfo_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_T_tMidCallSpecificInfo(TRUE, tvb, offset, actx, tree, hf_inap_tMidCallSpecificInfo);
}


static const ber_old_sequence_t T_tDisconnectSpecificInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_releaseCause_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_connectTime_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_tDisconnectSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       T_tDisconnectSpecificInfo_sequence, hf_index, ett_inap_T_tDisconnectSpecificInfo);

  return offset;
}
static int dissect_tDisconnectSpecificInfo_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_T_tDisconnectSpecificInfo(TRUE, tvb, offset, actx, tree, hf_inap_tDisconnectSpecificInfo);
}


static const value_string inap_EventSpecificInformationBCSM_vals[] = {
  {   0, "collectedInfoSpecificInfo" },
  {   1, "analyzedInfoSpecificInfo" },
  {   2, "routeSelectFailureSpecificInfo" },
  {   3, "oCalledPartyBusySpecificInfo" },
  {   4, "oNoAnswerSpecificInfo" },
  {   5, "oAnswerSpecificInfo" },
  {   6, "oMidCallSpecificInfo" },
  {   7, "oDisconnectSpecificInfo" },
  {   8, "tBusySpecificInfo" },
  {   9, "tNoAnswerSpecificInfo" },
  {  10, "tAnswerSpecificInfo" },
  {  11, "tMidCallSpecificInfo" },
  {  12, "tDisconnectSpecificInfo" },
  { 0, NULL }
};

static const ber_old_choice_t EventSpecificInformationBCSM_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_collectedInfoSpecificInfo_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_analyzedInfoSpecificInfo_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_routeSelectFailureSpecificInfo_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_oCalledPartyBusySpecificInfo_impl },
  {   4, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_oNoAnswerSpecificInfo_impl },
  {   5, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_oAnswerSpecificInfo_impl },
  {   6, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_oMidCallSpecificInfo_impl },
  {   7, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_oDisconnectSpecificInfo_impl },
  {   8, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_tBusySpecificInfo_impl },
  {   9, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_tNoAnswerSpecificInfo_impl },
  {  10, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_tAnswerSpecificInfo_impl },
  {  11, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_tMidCallSpecificInfo_impl },
  {  12, BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_tDisconnectSpecificInfo_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_EventSpecificInformationBCSM(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_choice(actx, tree, tvb, offset,
                                     EventSpecificInformationBCSM_choice, hf_index, ett_inap_EventSpecificInformationBCSM,
                                     NULL);

  return offset;
}
static int dissect_eventSpecificInformationBCSM_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_EventSpecificInformationBCSM(TRUE, tvb, offset, actx, tree, hf_inap_eventSpecificInformationBCSM);
}


static const ber_old_sequence_t EventReportBCSMArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_eventTypeBCSM_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_bcsmEventCorrelationID_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_eventSpecificInformationBCSM_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_legID_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_miscCallInfo_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_EventReportBCSMArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       EventReportBCSMArg_sequence, hf_index, ett_inap_EventReportBCSMArg);

  return offset;
}



static int
dissect_inap_FCIBillingChargingCharacteristics(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_inap_FurnishChargingInformationArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_inap_FCIBillingChargingCharacteristics(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_inap_HoldCause(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_holdcause_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_HoldCause(TRUE, tvb, offset, actx, tree, hf_inap_holdcause);
}


static const value_string inap_HoldCallInNetworkArg_vals[] = {
  {   0, "holdcause" },
  {   1, "empty" },
  { 0, NULL }
};

static const ber_old_choice_t HoldCallInNetworkArg_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_holdcause_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_empty_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_HoldCallInNetworkArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_choice(actx, tree, tvb, offset,
                                     HoldCallInNetworkArg_choice, hf_index, ett_inap_HoldCallInNetworkArg,
                                     NULL);

  return offset;
}



static int
dissect_inap_HighLayerCompatibility(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_highLayerCompatibility_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_HighLayerCompatibility(TRUE, tvb, offset, actx, tree, hf_inap_highLayerCompatibility);
}



static int
dissect_inap_AdditionalCallingPartyNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_inap_Digits(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_additionalCallingPartyNumber_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_AdditionalCallingPartyNumber(TRUE, tvb, offset, actx, tree, hf_inap_additionalCallingPartyNumber);
}



static int
dissect_inap_ForwardCallIndicators(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_forwardCallIndicators_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_ForwardCallIndicators(TRUE, tvb, offset, actx, tree, hf_inap_forwardCallIndicators);
}


static const ber_old_sequence_t InitialDP_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_serviceKey_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dialledDigits_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_calledPartyNumber_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumber_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyBusinessGroupID_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartysCategory_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartySubaddress_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cGEncountered_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iPSSPCapabilities_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iPAvailable_impl },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationNumber_impl },
  { BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_miscCallInfo_impl },
  { BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_originalCalledPartyID_impl },
  { BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_serviceProfileIdentifier_impl },
  { BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminalType_impl },
  { BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_triggerType_impl },
  { BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_highLayerCompatibility_impl },
  { BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_serviceInteractionIndicators_impl },
  { BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_additionalCallingPartyNumber_impl },
  { BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_forwardCallIndicators_impl },
  { BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_bearerCapability_impl },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_eventTypeBCSM_impl },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingPartyID_impl },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectionInformation_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_InitialDP(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       InitialDP_sequence, hf_index, ett_inap_InitialDP);

  return offset;
}


static const ber_old_sequence_t InitiateCallAttemptArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_destinationRoutingAddress_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_alertingPattern_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iSDNAccessRelatedInformation_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_travellingClassMark_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_serviceInteractionIndicators_impl },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyNumber_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_InitiateCallAttemptArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       InitiateCallAttemptArg_sequence, hf_index, ett_inap_InitiateCallAttemptArg);

  return offset;
}



static int
dissect_inap_CalledPartyBusinessGroupID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_calledPartyBusinessGroupID_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_CalledPartyBusinessGroupID(TRUE, tvb, offset, actx, tree, hf_inap_calledPartyBusinessGroupID);
}



static int
dissect_inap_CalledPartySubaddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_calledPartySubaddress_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_CalledPartySubaddress(TRUE, tvb, offset, actx, tree, hf_inap_calledPartySubaddress);
}


static const value_string inap_FeatureRequestIndicator_vals[] = {
  {   0, "hold" },
  {   1, "retrieve" },
  {   2, "featureActivation" },
  {   3, "spare1" },
  { 127, "sparen" },
  { 0, NULL }
};


static int
dissect_inap_FeatureRequestIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_featureRequestIndicator_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_FeatureRequestIndicator(TRUE, tvb, offset, actx, tree, hf_inap_featureRequestIndicator);
}


static const ber_old_sequence_t MidCallArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_dpSpecificCommonParameters_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_calledPartyBusinessGroupID_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_calledPartySubaddress_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyBusinessGroupID_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartySubaddress_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_featureRequestIndicator_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_carrier_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_MidCallArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       MidCallArg_sequence, hf_index, ett_inap_MidCallArg);

  return offset;
}


static const ber_old_sequence_t OAnswerArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_dpSpecificCommonParameters_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyBusinessGroupID_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartySubaddress_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_callingFacilityGroup_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingFacilityGroupMember_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_originalCalledPartyID_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingPartyID_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectionInformation_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_routeList_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_travellingClassMark_impl },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_OAnswerArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       OAnswerArg_sequence, hf_index, ett_inap_OAnswerArg);

  return offset;
}


static const ber_old_sequence_t OCalledPartyBusyArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_dpSpecificCommonParameters_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_busyCause_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyBusinessGroupID_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartySubaddress_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_callingFacilityGroup_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingFacilityGroupMember_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_originalCalledPartyID_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_prefix_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingPartyID_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectionInformation_impl },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_routeList_impl },
  { BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_travellingClassMark_impl },
  { BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_carrier_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_OCalledPartyBusyArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       OCalledPartyBusyArg_sequence, hf_index, ett_inap_OCalledPartyBusyArg);

  return offset;
}


static const ber_old_sequence_t ODisconnectArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_dpSpecificCommonParameters_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyBusinessGroupID_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartySubaddress_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_callingFacilityGroup_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingFacilityGroupMember_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_releaseCause_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_routeList_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_carrier_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_connectTime_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_ODisconnectArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       ODisconnectArg_sequence, hf_index, ett_inap_ODisconnectArg);

  return offset;
}


static const ber_old_sequence_t ONoAnswer_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_dpSpecificCommonParameters_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyBusinessGroupID_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartySubaddress_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_callingFacilityGroup_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingFacilityGroupMember_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_originalCalledPartyID_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_prefix_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingPartyID_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectionInformation_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_routeList_impl },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_travellingClassMark_impl },
  { BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_carrier_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_ONoAnswer(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       ONoAnswer_sequence, hf_index, ett_inap_ONoAnswer);

  return offset;
}


static const ber_old_sequence_t OriginationAttemptAuthorizedArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_dpSpecificCommonParameters_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dialledDigits_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyBusinessGroupID_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartySubaddress_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_callingFacilityGroup_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingFacilityGroupMember_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_travellingClassMark_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_carrier_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_OriginationAttemptAuthorizedArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       OriginationAttemptAuthorizedArg_sequence, hf_index, ett_inap_OriginationAttemptAuthorizedArg);

  return offset;
}



static int
dissect_inap_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_disconnectFromIPForbidden_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_BOOLEAN(TRUE, tvb, offset, actx, tree, hf_inap_disconnectFromIPForbidden);
}
static int dissect_requestAnnouncementComplete_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_BOOLEAN(TRUE, tvb, offset, actx, tree, hf_inap_requestAnnouncementComplete);
}
static int dissect_interruptableAnnInd_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_BOOLEAN(TRUE, tvb, offset, actx, tree, hf_inap_interruptableAnnInd);
}
static int dissect_voiceInformation_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_BOOLEAN(TRUE, tvb, offset, actx, tree, hf_inap_voiceInformation);
}
static int dissect_voiceBack_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_BOOLEAN(TRUE, tvb, offset, actx, tree, hf_inap_voiceBack);
}
static int dissect_iA5Information_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_BOOLEAN(TRUE, tvb, offset, actx, tree, hf_inap_iA5Information);
}


static const ber_old_sequence_t PlayAnnouncementArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_informationToSend_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_disconnectFromIPForbidden_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_requestAnnouncementComplete_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_PlayAnnouncementArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       PlayAnnouncementArg_sequence, hf_index, ett_inap_PlayAnnouncementArg);

  return offset;
}



static int
dissect_inap_OCTET_STRING_SIZE_1_2(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_endOfReplyDigit_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_OCTET_STRING_SIZE_1_2(TRUE, tvb, offset, actx, tree, hf_inap_endOfReplyDigit);
}
static int dissect_cancelDigit_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_OCTET_STRING_SIZE_1_2(TRUE, tvb, offset, actx, tree, hf_inap_cancelDigit);
}
static int dissect_startDigit_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_OCTET_STRING_SIZE_1_2(TRUE, tvb, offset, actx, tree, hf_inap_startDigit);
}


static const value_string inap_ErrorTreatment_vals[] = {
  {   0, "reportErrorToScf" },
  {   1, "help" },
  {   2, "repeatPrompt" },
  { 0, NULL }
};


static int
dissect_inap_ErrorTreatment(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_errorTreatment_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_ErrorTreatment(TRUE, tvb, offset, actx, tree, hf_inap_errorTreatment);
}


static const ber_old_sequence_t CollectedDigits_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_minimumNbOfDigits_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_maximumNbOfDigits_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_endOfReplyDigit_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cancelDigit_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_startDigit_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_firstDigitTimeOut_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_interDigitTimeOut_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_errorTreatment_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_interruptableAnnInd_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_voiceInformation_impl },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_voiceBack_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_CollectedDigits(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       CollectedDigits_sequence, hf_index, ett_inap_CollectedDigits);

  return offset;
}
static int dissect_collectedDigits_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_CollectedDigits(TRUE, tvb, offset, actx, tree, hf_inap_collectedDigits);
}


static const value_string inap_CollectedInfo_vals[] = {
  {   0, "collectedDigits" },
  {   1, "iA5Information" },
  { 0, NULL }
};

static const ber_old_choice_t CollectedInfo_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_collectedDigits_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iA5Information_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_CollectedInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_choice(actx, tree, tvb, offset,
                                     CollectedInfo_choice, hf_index, ett_inap_CollectedInfo,
                                     NULL);

  return offset;
}
static int dissect_collectedInfo_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_CollectedInfo(TRUE, tvb, offset, actx, tree, hf_inap_collectedInfo);
}


static const ber_old_sequence_t PromptAndCollectUserInformationArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_collectedInfo_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_disconnectFromIPForbidden_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_informationToSend_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_PromptAndCollectUserInformationArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       PromptAndCollectUserInformationArg_sequence, hf_index, ett_inap_PromptAndCollectUserInformationArg);

  return offset;
}



static int
dissect_inap_IA5String(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_iA5Response_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_IA5String(TRUE, tvb, offset, actx, tree, hf_inap_iA5Response);
}


static const value_string inap_ReceivedInformationArg_vals[] = {
  {   0, "digitsResponse" },
  {   1, "iA5Response" },
  { 0, NULL }
};

static const ber_old_choice_t ReceivedInformationArg_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_digitsResponse_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iA5Response_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_ReceivedInformationArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_choice(actx, tree, tvb, offset,
                                     ReceivedInformationArg_choice, hf_index, ett_inap_ReceivedInformationArg,
                                     NULL);

  return offset;
}


static const ber_old_sequence_t T_allCallSegments_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_releaseCause_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_allCallSegments(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       T_allCallSegments_sequence, hf_index, ett_inap_T_allCallSegments);

  return offset;
}
static int dissect_allCallSegments_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_T_allCallSegments(TRUE, tvb, offset, actx, tree, hf_inap_allCallSegments);
}


static const value_string inap_ReleaseCallArg_vals[] = {
  {   0, "initialCallSegment" },
  {   1, "allCallSegments" },
  { 0, NULL }
};

static const ber_old_choice_t ReleaseCallArg_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_initialCallSegment },
  {   1, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_allCallSegments_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_ReleaseCallArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_choice(actx, tree, tvb, offset,
                                     ReleaseCallArg_choice, hf_index, ett_inap_ReleaseCallArg,
                                     NULL);

  return offset;
}



static int
dissect_inap_RequestCurrentStatusReportArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_inap_ResourceID(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string inap_ResourceStatus_vals[] = {
  {   0, "busy" },
  {   1, "idle" },
  { 0, NULL }
};


static int
dissect_inap_ResourceStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_resourceStatus_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_ResourceStatus(TRUE, tvb, offset, actx, tree, hf_inap_resourceStatus);
}


static const ber_old_sequence_t RequestCurrentStatusReportResultArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_resourceStatus_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_resourceID_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_RequestCurrentStatusReportResultArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       RequestCurrentStatusReportResultArg_sequence, hf_index, ett_inap_RequestCurrentStatusReportResultArg);

  return offset;
}


static const ber_old_sequence_t RequestEveryStatusChangeReportArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_resourceID_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_correlationID_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_monitorDuration_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_RequestEveryStatusChangeReportArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       RequestEveryStatusChangeReportArg_sequence, hf_index, ett_inap_RequestEveryStatusChangeReportArg);

  return offset;
}


static const ber_old_sequence_t RequestFirstStatusMatchReportArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_resourceID_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_resourceStatus_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_correlationID_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_monitorDuration_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_bearerCapability_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_RequestFirstStatusMatchReportArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       RequestFirstStatusMatchReportArg_sequence, hf_index, ett_inap_RequestFirstStatusMatchReportArg);

  return offset;
}


static const ber_old_sequence_t RequestNotificationChargingEvent_item_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_eventTypeCharging2_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_monitorMode_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_legID_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_RequestNotificationChargingEvent_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       RequestNotificationChargingEvent_item_sequence, hf_index, ett_inap_RequestNotificationChargingEvent_item);

  return offset;
}
static int dissect_RequestNotificationChargingEvent_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_RequestNotificationChargingEvent_item(FALSE, tvb, offset, actx, tree, hf_inap_RequestNotificationChargingEvent_item);
}


static const ber_old_sequence_t RequestNotificationChargingEvent_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_RequestNotificationChargingEvent_item },
};

static int
dissect_inap_RequestNotificationChargingEvent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                          RequestNotificationChargingEvent_sequence_of, hf_index, ett_inap_RequestNotificationChargingEvent);

  return offset;
}



static int
dissect_inap_NumberOfDigits(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_numberOfDigits_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_NumberOfDigits(TRUE, tvb, offset, actx, tree, hf_inap_numberOfDigits);
}



static int
dissect_inap_ApplicationTimer(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_applicationTimer_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_ApplicationTimer(TRUE, tvb, offset, actx, tree, hf_inap_applicationTimer);
}


static const value_string inap_DpSpecificCriteria_vals[] = {
  {   0, "numberOfDigits" },
  {   1, "applicationTimer" },
  { 0, NULL }
};

static const ber_old_choice_t DpSpecificCriteria_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_numberOfDigits_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_applicationTimer_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_DpSpecificCriteria(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_choice(actx, tree, tvb, offset,
                                     DpSpecificCriteria_choice, hf_index, ett_inap_DpSpecificCriteria,
                                     NULL);

  return offset;
}
static int dissect_dpSpecificCriteria_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_DpSpecificCriteria(TRUE, tvb, offset, actx, tree, hf_inap_dpSpecificCriteria);
}


static const ber_old_sequence_t BCSMEvent_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_eventTypeBCSM_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_monitorMode_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_legID_impl },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_dpSpecificCriteria_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_BCSMEvent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       BCSMEvent_sequence, hf_index, ett_inap_BCSMEvent);

  return offset;
}
static int dissect_bcsmEvents_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_BCSMEvent(FALSE, tvb, offset, actx, tree, hf_inap_bcsmEvents_item);
}


static const ber_old_sequence_t SEQUENCE_SIZE_1_numOfBCSMEvents_OF_BCSMEvent_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_bcsmEvents_item },
};

static int
dissect_inap_SEQUENCE_SIZE_1_numOfBCSMEvents_OF_BCSMEvent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                          SEQUENCE_SIZE_1_numOfBCSMEvents_OF_BCSMEvent_sequence_of, hf_index, ett_inap_SEQUENCE_SIZE_1_numOfBCSMEvents_OF_BCSMEvent);

  return offset;
}
static int dissect_bcsmEvents_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_SEQUENCE_SIZE_1_numOfBCSMEvents_OF_BCSMEvent(TRUE, tvb, offset, actx, tree, hf_inap_bcsmEvents);
}


static const ber_old_sequence_t RequestReportBCSMEventArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_bcsmEvents_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_bcsmEventCorrelationID_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_RequestReportBCSMEventArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       RequestReportBCSMEventArg_sequence, hf_index, ett_inap_RequestReportBCSMEventArg);

  return offset;
}


static const value_string inap_TimerID_vals[] = {
  {   0, "tssf" },
  { 0, NULL }
};


static int
dissect_inap_TimerID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_timerID_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_TimerID(TRUE, tvb, offset, actx, tree, hf_inap_timerID);
}



static int
dissect_inap_TimerValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_inap_Integer4(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_timervalue_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_TimerValue(TRUE, tvb, offset, actx, tree, hf_inap_timervalue);
}


static const ber_old_sequence_t ResetTimerArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_timerID_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_timervalue_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_ResetTimerArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       ResetTimerArg_sequence, hf_index, ett_inap_ResetTimerArg);

  return offset;
}


static const ber_old_sequence_t RouteSelectFailureArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_dpSpecificCommonParameters_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dialledDigits_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyBusinessGroupID_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartySubaddress_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_callingFacilityGroup_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingFacilityGroupMember_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_failureCause_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_originalCalledPartyID_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_prefix_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingPartyID_impl },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectionInformation_impl },
  { BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_routeList_impl },
  { BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_travellingClassMark_impl },
  { BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_carrier_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_RouteSelectFailureArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       RouteSelectFailureArg_sequence, hf_index, ett_inap_RouteSelectFailureArg);

  return offset;
}


static const ber_old_sequence_t SelectFacilityArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_alertingPattern_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_destinationNumberRoutingAddress_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iSDNAccessRelatedInformation_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_calledFacilityGroup_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_calledFacilityGroupMember_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_originalCalledPartyID_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_SelectFacilityArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       SelectFacilityArg_sequence, hf_index, ett_inap_SelectFacilityArg);

  return offset;
}


static const ber_old_sequence_t SelectRouteArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_destinationRoutingAddress_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_alertingPattern_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_correlationID_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iSDNAccessRelatedInformation_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_originalCalledPartyID_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_routeList_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_scfID_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_travellingClassMark_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_carrier_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_SelectRouteArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       SelectRouteArg_sequence, hf_index, ett_inap_SelectRouteArg);

  return offset;
}



static int
dissect_inap_SCIBillingChargingCharacteristics(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_sCIBillingChargingCharacteristics_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_SCIBillingChargingCharacteristics(TRUE, tvb, offset, actx, tree, hf_inap_sCIBillingChargingCharacteristics);
}


static const ber_old_sequence_t SendChargingInformationArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sCIBillingChargingCharacteristics_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_partyToCharge_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_SendChargingInformationArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       SendChargingInformationArg_sequence, hf_index, ett_inap_SendChargingInformationArg);

  return offset;
}



static int
dissect_inap_CounterID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_counterID_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_CounterID(TRUE, tvb, offset, actx, tree, hf_inap_counterID);
}


static const ber_old_sequence_t CounterAndValue_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_counterID_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_counterValue_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_CounterAndValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       CounterAndValue_sequence, hf_index, ett_inap_CounterAndValue);

  return offset;
}
static int dissect_CountersValue_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_CounterAndValue(FALSE, tvb, offset, actx, tree, hf_inap_CountersValue_item);
}


static const ber_old_sequence_t CountersValue_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_CountersValue_item },
};

static int
dissect_inap_CountersValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                          CountersValue_sequence_of, hf_index, ett_inap_CountersValue);

  return offset;
}
static int dissect_countersValue_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_CountersValue(TRUE, tvb, offset, actx, tree, hf_inap_countersValue);
}


static const value_string inap_ResponseCondition_vals[] = {
  {   0, "intermediateResponse" },
  {   1, "lastResponse" },
  { 0, NULL }
};


static int
dissect_inap_ResponseCondition(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_responseCondition_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_ResponseCondition(TRUE, tvb, offset, actx, tree, hf_inap_responseCondition);
}


static const ber_old_sequence_t ServiceFilteringResponseArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_countersValue_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_filteringCriteria_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_responseCondition_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_ServiceFilteringResponseArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       ServiceFilteringResponseArg_sequence, hf_index, ett_inap_ServiceFilteringResponseArg);

  return offset;
}



static int
dissect_inap_SpecializedResourceReportArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string inap_ReportCondition_vals[] = {
  {   0, "statusReport" },
  {   1, "timerExpired" },
  {   2, "canceled" },
  { 0, NULL }
};


static int
dissect_inap_ReportCondition(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_reportCondition_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_ReportCondition(TRUE, tvb, offset, actx, tree, hf_inap_reportCondition);
}


static const ber_old_sequence_t StatusReportArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_resourceStatus_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_correlationID_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_resourceID_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_reportCondition_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_StatusReportArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       StatusReportArg_sequence, hf_index, ett_inap_StatusReportArg);

  return offset;
}


static const ber_old_sequence_t TAnswerArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_dpSpecificCommonParameters_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_calledPartyBusinessGroupID_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_calledPartySubaddress_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_calledFacilityGroup_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_calledFacilityGroupMember_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_TAnswerArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       TAnswerArg_sequence, hf_index, ett_inap_TAnswerArg);

  return offset;
}


static const ber_old_sequence_t TBusyArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_dpSpecificCommonParameters_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_busyCause_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_calledPartyBusinessGroupID_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_calledPartySubaddress_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_originalCalledPartyID_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingPartyID_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectionInformation_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_routeList_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_travellingClassMark_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_TBusyArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       TBusyArg_sequence, hf_index, ett_inap_TBusyArg);

  return offset;
}


static const ber_old_sequence_t TDisconnectArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_dpSpecificCommonParameters_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_calledPartyBusinessGroupID_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_calledPartySubaddress_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_calledFacilityGroup_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_calledFacilityGroupMember_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_releaseCause_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_connectTime_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_TDisconnectArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       TDisconnectArg_sequence, hf_index, ett_inap_TDisconnectArg);

  return offset;
}


static const ber_old_sequence_t TermAttemptAuthorizedArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_dpSpecificCommonParameters_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_calledPartyBusinessGroupID_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_calledPartySubaddress_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingPartyBusinessGroupID_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_originalCalledPartyID_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingPartyID_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectionInformation_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_routeList_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_travellingClassMark_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_TermAttemptAuthorizedArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       TermAttemptAuthorizedArg_sequence, hf_index, ett_inap_TermAttemptAuthorizedArg);

  return offset;
}


static const ber_old_sequence_t TNoAnswerArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_dpSpecificCommonParameters_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_calledPartyBusinessGroupID_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_calledPartySubaddress_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_calledFacilityGroup_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_calledFacilityGroupMember_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_originalCalledPartyID_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectingPartyID_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_redirectionInformation_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_travellingClassMark_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_TNoAnswerArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       TNoAnswerArg_sequence, hf_index, ett_inap_TNoAnswerArg);

  return offset;
}


static const ber_old_sequence_t ChargingEvent_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_eventTypeCharging_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_monitorMode_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_legID_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_ChargingEvent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       ChargingEvent_sequence, hf_index, ett_inap_ChargingEvent);

  return offset;
}



static int
dissect_inap_INTEGER_0_255(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_callAttemptElapsedTimeValue_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_INTEGER_0_255(TRUE, tvb, offset, actx, tree, hf_inap_callAttemptElapsedTimeValue);
}


static const value_string inap_RequestedInformationValue_vals[] = {
  {   0, "callAttemptElapsedTimeValue" },
  {   1, "callStopTimeValue" },
  {   2, "callConnectedElapsedTimeValue" },
  {   3, "calledAddressValue" },
  {  30, "releaseCauseValue" },
  { 0, NULL }
};

static const ber_old_choice_t RequestedInformationValue_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_callAttemptElapsedTimeValue_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_callStopTimeValue_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_callConnectedElapsedTimeValue_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_calledAddressValue_impl },
  {  30, BER_CLASS_CON, 30, BER_FLAGS_IMPLTAG, dissect_releaseCauseValue_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_RequestedInformationValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_choice(actx, tree, tvb, offset,
                                     RequestedInformationValue_choice, hf_index, ett_inap_RequestedInformationValue,
                                     NULL);

  return offset;
}
static int dissect_requestedInformationValue_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_RequestedInformationValue(TRUE, tvb, offset, actx, tree, hf_inap_requestedInformationValue);
}


static const ber_old_sequence_t RequestedInformation_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_requestedInformationType_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_requestedInformationValue_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_RequestedInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       RequestedInformation_sequence, hf_index, ett_inap_RequestedInformation);

  return offset;
}
static int dissect_RequestedInformationList_item(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_RequestedInformation(FALSE, tvb, offset, actx, tree, hf_inap_RequestedInformationList_item);
}


static const ber_old_sequence_t RequestedInformationList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_RequestedInformationList_item },
};

static int
dissect_inap_RequestedInformationList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                          RequestedInformationList_sequence_of, hf_index, ett_inap_RequestedInformationList);

  return offset;
}


static const value_string inap_UnavailableNetworkResource_vals[] = {
  {   0, "unavailableResources" },
  {   1, "componentFailure" },
  {   2, "basicCallProcessingException" },
  {   3, "resourceStatusFailure" },
  {   4, "endUserFailure" },
  { 0, NULL }
};


static int
dissect_inap_UnavailableNetworkResource(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string inap_T_problem_01_vals[] = {
  {   0, "unknownOperation" },
  {   1, "tooLate" },
  {   2, "operationNotCancellable" },
  { 0, NULL }
};


static int
dissect_inap_T_problem_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_problem_01_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_T_problem_01(TRUE, tvb, offset, actx, tree, hf_inap_problem_01);
}



static int
dissect_inap_INTEGER_M128_127(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_operation_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_inap_INTEGER_M128_127(TRUE, tvb, offset, actx, tree, hf_inap_operation);
}


static const ber_old_sequence_t CancelFailed_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_problem_01_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_operation_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_CancelFailed(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       CancelFailed_sequence, hf_index, ett_inap_CancelFailed);

  return offset;
}


static const value_string inap_RequestedInfoError_vals[] = {
  {   1, "unknownRequestedInfo" },
  {   2, "requestedInfoNotAvailable" },
  { 0, NULL }
};


static int
dissect_inap_RequestedInfoError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string inap_SystemFailure_vals[] = {
  {   0, "unavailableResources" },
  {   1, "componentFailure" },
  {   2, "basicCallProcessingException" },
  {   3, "resourceStatusFailure" },
  {   4, "endUserFailure" },
  { 0, NULL }
};


static int
dissect_inap_SystemFailure(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string inap_TaskRefused_vals[] = {
  {   0, "generic" },
  {   1, "unobtainable" },
  {   2, "congestion" },
  { 0, NULL }
};


static int
dissect_inap_TaskRefused(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}

/*--- PDUs ---*/

static void dissect_Component_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_Component(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_Component_PDU);
}
static void dissect_ActivateServiceFilteringArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_ActivateServiceFilteringArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_ActivateServiceFilteringArg_PDU);
}
static void dissect_AnalysedInformationArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_AnalysedInformationArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_AnalysedInformationArg_PDU);
}
static void dissect_AnalyseInformationArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_AnalyseInformationArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_AnalyseInformationArg_PDU);
}
static void dissect_ApplyChargingArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_ApplyChargingArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_ApplyChargingArg_PDU);
}
static void dissect_ApplyChargingReportArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_ApplyChargingReportArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_ApplyChargingReportArg_PDU);
}
static void dissect_AssistRequestInstructionsArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_AssistRequestInstructionsArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_AssistRequestInstructionsArg_PDU);
}
static void dissect_CallGapArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_CallGapArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_CallGapArg_PDU);
}
static void dissect_CallInformationReportArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_CallInformationReportArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_CallInformationReportArg_PDU);
}
static void dissect_CallInformationRequestArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_CallInformationRequestArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_CallInformationRequestArg_PDU);
}
static void dissect_CancelArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_CancelArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_CancelArg_PDU);
}
static void dissect_CollectedInformationArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_CollectedInformationArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_CollectedInformationArg_PDU);
}
static void dissect_CollectInformationArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_CollectInformationArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_CollectInformationArg_PDU);
}
static void dissect_ConnectArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_ConnectArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_ConnectArg_PDU);
}
static void dissect_ConnectToResourceArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_ConnectToResourceArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_ConnectToResourceArg_PDU);
}
static void dissect_EstablishTemporaryConnectionArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_EstablishTemporaryConnectionArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_EstablishTemporaryConnectionArg_PDU);
}
static void dissect_EventNotificationChargingArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_EventNotificationChargingArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_EventNotificationChargingArg_PDU);
}
static void dissect_EventReportBCSMArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_EventReportBCSMArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_EventReportBCSMArg_PDU);
}
static void dissect_FurnishChargingInformationArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_FurnishChargingInformationArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_FurnishChargingInformationArg_PDU);
}
static void dissect_HoldCallInNetworkArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_HoldCallInNetworkArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_HoldCallInNetworkArg_PDU);
}
static void dissect_InitialDP_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_InitialDP(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_InitialDP_PDU);
}
static void dissect_InitiateCallAttemptArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_InitiateCallAttemptArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_InitiateCallAttemptArg_PDU);
}
static void dissect_MidCallArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_MidCallArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_MidCallArg_PDU);
}
static void dissect_OAnswerArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_OAnswerArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_OAnswerArg_PDU);
}
static void dissect_OCalledPartyBusyArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_OCalledPartyBusyArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_OCalledPartyBusyArg_PDU);
}
static void dissect_ODisconnectArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_ODisconnectArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_ODisconnectArg_PDU);
}
static void dissect_ONoAnswer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_ONoAnswer(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_ONoAnswer_PDU);
}
static void dissect_OriginationAttemptAuthorizedArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_OriginationAttemptAuthorizedArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_OriginationAttemptAuthorizedArg_PDU);
}
static void dissect_PlayAnnouncementArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_PlayAnnouncementArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_PlayAnnouncementArg_PDU);
}
static void dissect_PromptAndCollectUserInformationArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_PromptAndCollectUserInformationArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_PromptAndCollectUserInformationArg_PDU);
}
static void dissect_ReceivedInformationArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_ReceivedInformationArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_ReceivedInformationArg_PDU);
}
static void dissect_ReleaseCallArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_ReleaseCallArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_ReleaseCallArg_PDU);
}
static void dissect_RequestCurrentStatusReportArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_RequestCurrentStatusReportArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_RequestCurrentStatusReportArg_PDU);
}
static void dissect_RequestCurrentStatusReportResultArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_RequestCurrentStatusReportResultArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_RequestCurrentStatusReportResultArg_PDU);
}
static void dissect_RequestEveryStatusChangeReportArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_RequestEveryStatusChangeReportArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_RequestEveryStatusChangeReportArg_PDU);
}
static void dissect_RequestFirstStatusMatchReportArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_RequestFirstStatusMatchReportArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_RequestFirstStatusMatchReportArg_PDU);
}
static void dissect_RequestNotificationChargingEvent_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_RequestNotificationChargingEvent(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_RequestNotificationChargingEvent_PDU);
}
static void dissect_RequestReportBCSMEventArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_RequestReportBCSMEventArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_RequestReportBCSMEventArg_PDU);
}
static void dissect_ResetTimerArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_ResetTimerArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_ResetTimerArg_PDU);
}
static void dissect_RouteSelectFailureArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_RouteSelectFailureArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_RouteSelectFailureArg_PDU);
}
static void dissect_SelectFacilityArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_SelectFacilityArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_SelectFacilityArg_PDU);
}
static void dissect_SelectRouteArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_SelectRouteArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_SelectRouteArg_PDU);
}
static void dissect_ServiceFilteringResponseArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_ServiceFilteringResponseArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_ServiceFilteringResponseArg_PDU);
}
static void dissect_SpecializedResourceReportArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_SpecializedResourceReportArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_SpecializedResourceReportArg_PDU);
}
static void dissect_StatusReportArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_StatusReportArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_StatusReportArg_PDU);
}
static void dissect_TAnswerArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_TAnswerArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_TAnswerArg_PDU);
}
static void dissect_TBusyArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_TBusyArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_TBusyArg_PDU);
}
static void dissect_TDisconnectArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_TDisconnectArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_TDisconnectArg_PDU);
}
static void dissect_TermAttemptAuthorizedArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_TermAttemptAuthorizedArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_TermAttemptAuthorizedArg_PDU);
}
static void dissect_TNoAnswerArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_inap_TNoAnswerArg(FALSE, tvb, 0, &asn1_ctx, tree, hf_inap_TNoAnswerArg_PDU);
}


/*--- End of included file: packet-inap-fn.c ---*/
#line 166 "packet-inap-template.c"
/*
TC-Invokable OPERATION ::=
  {activateServiceFiltering | activityTest | analysedInformation |
   analyseInformation | applyCharging | applyChargingReport |
   assistRequestInstructions | callGap | callInformationReport |
   callInformationRequest | cancel | cancelStatusReportRequest |
   collectedInformation | collectInformation | connect | connectToResource |
   continue | disconnectForwardConnection | establishTemporaryConnection |
   eventNotificationCharging | eventReportBCSM | furnishChargingInformation |
   holdCallInNetwork | initialDP | initiateCallAttempt | oAnswer |
   oCalledPartyBusy | oDisconnect | oMidCall | oNoAnswer |
   originationAttemptAuthorized | releaseCall | requestCurrentStatusReport |
   requestEveryStatusChangeReport | requestFirstStatusMatchReport |
   requestNotificationChargingEvent | requestReportBCSMEvent | resetTimer |
   routeSelectFailure | selectFacility | selectRoute | sendChargingInformation
   | serviceFilteringResponse | statusReport | tAnswer | tBusy | tDisconnect |
   termAttemptAuthorized | tMidCall | tNoAnswer | playAnnouncement |
   promptAndCollectUserInformation}
*/

static int dissect_invokeData(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_) {
  switch(opcode){
  case 0: /*InitialDP*/
    offset=dissect_inap_InitialDP(FALSE, tvb, offset, actx, tree, hf_inap_InitialDP_PDU);
    break;
  case 1: /*1 OriginationAttemptAuthorized */
    offset=dissect_inap_OriginationAttemptAuthorizedArg(FALSE, tvb, offset, actx, tree, hf_inap_OriginationAttemptAuthorizedArg_PDU);
    break;
  case 2: /*2 CollectedInformation */
    offset=dissect_inap_CollectedInformationArg(FALSE, tvb, offset, actx, tree, hf_inap_CollectedInformationArg_PDU);
    break;
  case 3: /*3 AnalysedInformation */
    offset=dissect_inap_AnalysedInformationArg(FALSE, tvb, offset, actx, tree, hf_inap_AnalysedInformationArg_PDU);
    break;
  case 4: /*4 RouteSelectFailure */
    offset=dissect_inap_RouteSelectFailureArg(FALSE, tvb, offset, actx, tree, hf_inap_RouteSelectFailureArg_PDU);
    break;
  case 5: /*5 oCalledPartyBusy */
    offset=dissect_inap_OCalledPartyBusyArg(FALSE, tvb, offset, actx, tree, hf_inap_OCalledPartyBusyArg_PDU);
    break;	 
  case 6: /*6 oNoAnswer */
    offset=dissect_inap_ONoAnswer(FALSE, tvb, offset, actx, tree, hf_inap_ONoAnswer_PDU);
    break;
  case 7: /*7 oAnswer */
    offset=dissect_inap_OAnswerArg(FALSE, tvb, offset, actx, tree, hf_inap_OAnswerArg_PDU);
    break;
  case 8: /*8 oDisconnect */
    offset=dissect_inap_ODisconnectArg(FALSE, tvb, offset, actx, tree, hf_inap_ODisconnectArg_PDU);
    break;
  case 9: /*9 TermAttemptAuthorized */
    offset=dissect_inap_TermAttemptAuthorizedArg(FALSE, tvb, offset, actx, tree, hf_inap_TermAttemptAuthorizedArg_PDU);
    break;
  case 10: /*10 tBusy */
    offset=dissect_inap_TBusyArg(FALSE, tvb, offset, actx, tree, hf_inap_TBusyArg_PDU);
    break;
  case 11: /*11 tNoAnswer */
    offset=dissect_inap_TNoAnswerArg(FALSE, tvb, offset, actx, tree, hf_inap_TNoAnswerArg_PDU);
    break;
  case 12: /*12 tAnswer */
    offset=dissect_inap_TAnswerArg(FALSE, tvb, offset, actx, tree, hf_inap_TAnswerArg_PDU);
    break;
  case 13: /*13 tDisconnect */
    offset=dissect_inap_TDisconnectArg(FALSE, tvb, offset, actx, tree, hf_inap_TDisconnectArg_PDU);
    break;
  case 14: /*14 oMidCall */
    offset=dissect_inap_MidCallArg(FALSE, tvb, offset, actx, tree, hf_inap_MidCallArg_PDU);
    break;
  case 15: /*15 tMidCall */
    offset=dissect_inap_MidCallArg(FALSE, tvb, offset, actx, tree, hf_inap_MidCallArg_PDU);
    break;
  case  16: /*AssistRequestInstructions*/
    offset=dissect_inap_AssistRequestInstructionsArg(FALSE, tvb, offset, actx, tree, hf_inap_AssistRequestInstructionsArg_PDU);
    break;
  case  17: /*EstablishTemporaryConnection*/
    offset=dissect_inap_EstablishTemporaryConnectionArg(FALSE, tvb, offset, actx, tree, hf_inap_EstablishTemporaryConnectionArg_PDU);
    break;
  case  18: /*DisconnectForwardConnections*/
    proto_tree_add_text(tree, tvb, offset, -1, "Disconnect Forward Connection");
    break;
  case  19: /*ConnectToResource*/
    offset=dissect_inap_ConnectToResourceArg(FALSE, tvb, offset, actx, tree, hf_inap_ConnectToResourceArg_PDU);
    break;
  case  20: /*Connect*/
    offset=dissect_inap_ConnectArg(FALSE, tvb, offset, actx, tree,hf_inap_ConnectArg_PDU);
    break;	
  case  21: /* 21 HoldCallInNetwork */
    offset=dissect_inap_HoldCallInNetworkArg(FALSE, tvb, offset, actx, tree,hf_inap_HoldCallInNetworkArg_PDU);
    break;

   case 22: /*ReleaseCall*/
    offset=dissect_inap_ReleaseCallArg(FALSE, tvb, offset, actx, tree,hf_inap_ReleaseCallArg_PDU);
    break;
    case 23: /*InitialDP*/
    offset=dissect_inap_RequestReportBCSMEventArg(FALSE, tvb, offset, actx, tree, hf_inap_RequestReportBCSMEventArg_PDU);
    break;
  case  24: /*EventReportBCSM*/
    offset=dissect_inap_EventReportBCSMArg(FALSE, tvb, offset, actx, tree, hf_inap_EventReportBCSMArg_PDU);
    break;
  case  25: /*25, "RequestNotificationChargingEvent */
    offset=dissect_inap_RequestNotificationChargingEvent(FALSE, tvb, offset, actx, tree, hf_inap_RequestNotificationChargingEvent_PDU);
    break;
  case  26: /*26, "EventNotificationCharging */
    offset=dissect_inap_EventNotificationChargingArg(FALSE, tvb, offset, actx, tree, hf_inap_EventNotificationChargingArg_PDU);
    break;
  case  27: /*27, "CollectInformation */
    offset=dissect_inap_CollectInformationArg(FALSE, tvb, offset, actx, tree, hf_inap_CollectInformationArg_PDU);
    break;
  case  28: /*28, "AnalyseInformation */
    offset=dissect_inap_AnalyseInformationArg(FALSE, tvb, offset, actx, tree, hf_inap_AnalyseInformationArg_PDU);
    break;
  case  29: /*29, "SelectRoute */
    offset=dissect_inap_SelectRouteArg(FALSE, tvb, offset, actx, tree, hf_inap_SelectRouteArg_PDU);
    break;
  case  30: /*30, "SelectFacility */
    offset=dissect_inap_SelectFacilityArg(FALSE, tvb, offset, actx, tree, hf_inap_SelectFacilityArg_PDU);
    break;
	/*31, "Continue */
  case  32: /*32, InitiateCallAttempt*/
    offset=dissect_inap_InitiateCallAttemptArg(FALSE, tvb, offset, actx, tree, hf_inap_InitiateCallAttemptArg_PDU);
    break;
  case 33: /*ResetTimer*/
    offset=dissect_inap_ResetTimerArg(FALSE, tvb, offset, actx, tree, hf_inap_ResetTimerArg_PDU);
    break;
  case 34: /*FurnishChargingInformation*/
    offset=dissect_inap_FurnishChargingInformationArg(FALSE, tvb, offset, actx, tree, hf_inap_FurnishChargingInformationArg_PDU);
    break;
  case 35: /*35, ApplyCharging */
    offset=dissect_inap_ApplyChargingArg(FALSE, tvb, offset, actx, tree, hf_inap_ApplyChargingArg_PDU);
    break;	
  case 36: /*36, "ApplyChargingReport */
    offset=dissect_inap_ApplyChargingReportArg(FALSE, tvb, offset, actx, tree, hf_inap_ApplyChargingReportArg_PDU);
    break;
  case 37: /*37, "RequestCurrentStatusReport */
    offset=dissect_inap_RequestCurrentStatusReportArg(FALSE, tvb, offset, actx, tree, hf_inap_RequestCurrentStatusReportArg_PDU);
    break;
  case 38:/*38, "RequestEveryStatusChangeReport */
    offset=dissect_inap_RequestEveryStatusChangeReportArg(FALSE, tvb, offset, actx, tree, hf_inap_RequestEveryStatusChangeReportArg_PDU);
    break;
  case 39:/*39, "RequestFirstStatusMatchReport */
    offset=dissect_inap_RequestFirstStatusMatchReportArg(FALSE, tvb, offset, actx, tree, hf_inap_RequestFirstStatusMatchReportArg_PDU);
    break;
  case 40:/*40, "StatusReport */
    offset=dissect_inap_StatusReportArg(FALSE, tvb, offset, actx, tree, hf_inap_StatusReportArg_PDU);
    break;
  case 41:/*41, "CallGap */
    offset=dissect_inap_CallGapArg(FALSE, tvb, offset, actx, tree, hf_inap_CallGapArg_PDU);
    break;
  case 42:/*42, "ActivateServiceFiltering */
    offset=dissect_inap_ActivateServiceFilteringArg(FALSE, tvb, offset, actx, tree, hf_inap_ActivateServiceFilteringArg_PDU);
    break;
  case 43:/*43, "ServiceFilteringResponse */
    offset=dissect_inap_ServiceFilteringResponseArg(FALSE, tvb, offset, actx, tree, hf_inap_ServiceFilteringResponseArg_PDU);
    break;    
  case  44: /*CallInformationReport*/
    offset=dissect_inap_CallInformationReportArg(FALSE, tvb, offset, actx, tree, hf_inap_CallInformationReportArg_PDU);
    break;
  case  45: /*CallInformationRequest*/
    offset=dissect_inap_CallInformationRequestArg(FALSE, tvb, offset, actx, tree, hf_inap_CallInformationRequestArg_PDU);
    break;
  case 47: /*PlayAnnouncement*/
    offset=dissect_inap_PlayAnnouncementArg(FALSE, tvb, offset, actx, tree, hf_inap_PlayAnnouncementArg_PDU);
    break;
  case 48: /*PromptAndCollectUserInformation*/
    offset=dissect_inap_PromptAndCollectUserInformationArg(FALSE, tvb, offset, actx, tree, hf_inap_PromptAndCollectUserInformationArg_PDU);
    break;
  case 49: /* 49 SpecializedResourceReport */
    offset=dissect_inap_SpecializedResourceReportArg(FALSE, tvb, offset, actx, tree, hf_inap_SpecializedResourceReportArg_PDU);
    break;
  case  53: /*Cancel*/
    offset=dissect_inap_CancelArg(FALSE, tvb, offset, actx, tree, hf_inap_CancelArg_PDU);
    break;
	/*55 ActivityTest*/
   default:
    proto_tree_add_text(tree, tvb, offset, -1, "Unknown invokeData blob");
    /* todo call the asn.1 dissector */
  }
  return offset;
}

/*
TC-Returnable OPERATION ::=
  {activateServiceFiltering | activityTest | requestCurrentStatusReport |
   requestEveryStatusChangeReport | requestFirstStatusMatchReport |
   promptAndCollectUserInformation}

   activateServiceFiltering			- No arg
   activityTest						- No Arg
   requestCurrentStatusReport		- RESULT         RequestCurrentStatusReportResultArg
   requestEveryStatusChangeReport	- No arg
   requestFirstStatusMatchReport	- No Arg 
   promptAndCollectUserInformation	- RESULT         ReceivedInformationArg
	
*/
static int dissect_returnResultData(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_) {
  switch(opcode){
   case 37: /*requestCurrentStatusReport*/
    offset=dissect_inap_RequestCurrentStatusReportResultArg(FALSE, tvb, offset, actx, tree, -1);
    break;
   case 48: /*PromptAndCollectUserInformation*/
    offset=dissect_inap_ReceivedInformationArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  default:
    proto_tree_add_text(tree, tvb, offset, -1, "Unknown returnResultData blob");
  }
  return offset;
}
/* From GSMMAP TODO find out if there is ERROR parameters */
static int dissect_returnErrorData(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx) {
  proto_item *cause;
	
  switch(errorCode){
  default:
    cause=proto_tree_add_text(tree, tvb, offset, -1, "Unknown returnErrorData blob");
    proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
    expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "Unknown invokeData %d",errorCode);
    break;
  }
  return offset;
}

static guint8 inap_pdu_type = 0;
static guint8 inap_pdu_size = 0;


static void
dissect_inap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
    proto_item		*item=NULL;
    proto_tree		*tree=NULL;
	int				offset = 0;

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "INAP");
    }

    /* create display subtree for the protocol */
    if(parent_tree){
       item = proto_tree_add_item(parent_tree, proto_inap, tvb, 0, -1, FALSE);
       tree = proto_item_add_subtree(item, ett_inap);
    }
	inap_pdu_type = tvb_get_guint8(tvb, offset)&0x0f;
	/* Get the length and add 2 */
	inap_pdu_size = tvb_get_guint8(tvb, offset+1)+2;
	opcode = 0;
    dissect_Component_PDU(tvb, pinfo, tree);


}

/*--- proto_reg_handoff_inap ---------------------------------------*/
static void range_delete_callback(guint32 ssn)
{
    if (ssn) {
	delete_itu_tcap_subdissector(ssn, inap_handle);
    }
}

static void range_add_callback(guint32 ssn)
{
    if (ssn) {
	add_itu_tcap_subdissector(ssn, inap_handle);
    }
}

void proto_reg_handoff_inap(void) {

    static int inap_prefs_initialized = FALSE;
    
    inap_handle = create_dissector_handle(dissect_inap, proto_inap);
	
    if (!inap_prefs_initialized) {
	    inap_prefs_initialized = TRUE;
    }
    else {
	    range_foreach(ssn_range, range_delete_callback);
    }

    g_free(ssn_range);
    ssn_range = range_copy(global_ssn_range);

    range_foreach(ssn_range, range_add_callback);
}


void proto_register_inap(void) {
	module_t *inap_module;
  /* List of fields */
  static hf_register_info hf[] = {

	  


/*--- Included file: packet-inap-hfarr.c ---*/
#line 1 "packet-inap-hfarr.c"
    { &hf_inap_Component_PDU,
      { "Component", "inap.Component",
        FT_UINT32, BASE_DEC, VALS(inap_Component_vals), 0,
        "inap.Component", HFILL }},
    { &hf_inap_ActivateServiceFilteringArg_PDU,
      { "ActivateServiceFilteringArg", "inap.ActivateServiceFilteringArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.ActivateServiceFilteringArg", HFILL }},
    { &hf_inap_AnalysedInformationArg_PDU,
      { "AnalysedInformationArg", "inap.AnalysedInformationArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.AnalysedInformationArg", HFILL }},
    { &hf_inap_AnalyseInformationArg_PDU,
      { "AnalyseInformationArg", "inap.AnalyseInformationArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.AnalyseInformationArg", HFILL }},
    { &hf_inap_ApplyChargingArg_PDU,
      { "ApplyChargingArg", "inap.ApplyChargingArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.ApplyChargingArg", HFILL }},
    { &hf_inap_ApplyChargingReportArg_PDU,
      { "ApplyChargingReportArg", "inap.ApplyChargingReportArg",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.ApplyChargingReportArg", HFILL }},
    { &hf_inap_AssistRequestInstructionsArg_PDU,
      { "AssistRequestInstructionsArg", "inap.AssistRequestInstructionsArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.AssistRequestInstructionsArg", HFILL }},
    { &hf_inap_CallGapArg_PDU,
      { "CallGapArg", "inap.CallGapArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.CallGapArg", HFILL }},
    { &hf_inap_CallInformationReportArg_PDU,
      { "CallInformationReportArg", "inap.CallInformationReportArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.CallInformationReportArg", HFILL }},
    { &hf_inap_CallInformationRequestArg_PDU,
      { "CallInformationRequestArg", "inap.CallInformationRequestArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.CallInformationRequestArg", HFILL }},
    { &hf_inap_CancelArg_PDU,
      { "CancelArg", "inap.CancelArg",
        FT_UINT32, BASE_DEC, VALS(inap_CancelArg_vals), 0,
        "inap.CancelArg", HFILL }},
    { &hf_inap_CollectedInformationArg_PDU,
      { "CollectedInformationArg", "inap.CollectedInformationArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.CollectedInformationArg", HFILL }},
    { &hf_inap_CollectInformationArg_PDU,
      { "CollectInformationArg", "inap.CollectInformationArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.CollectInformationArg", HFILL }},
    { &hf_inap_ConnectArg_PDU,
      { "ConnectArg", "inap.ConnectArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.ConnectArg", HFILL }},
    { &hf_inap_ConnectToResourceArg_PDU,
      { "ConnectToResourceArg", "inap.ConnectToResourceArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.ConnectToResourceArg", HFILL }},
    { &hf_inap_EstablishTemporaryConnectionArg_PDU,
      { "EstablishTemporaryConnectionArg", "inap.EstablishTemporaryConnectionArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.EstablishTemporaryConnectionArg", HFILL }},
    { &hf_inap_EventNotificationChargingArg_PDU,
      { "EventNotificationChargingArg", "inap.EventNotificationChargingArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.EventNotificationChargingArg", HFILL }},
    { &hf_inap_EventReportBCSMArg_PDU,
      { "EventReportBCSMArg", "inap.EventReportBCSMArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.EventReportBCSMArg", HFILL }},
    { &hf_inap_FurnishChargingInformationArg_PDU,
      { "FurnishChargingInformationArg", "inap.FurnishChargingInformationArg",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.FurnishChargingInformationArg", HFILL }},
    { &hf_inap_HoldCallInNetworkArg_PDU,
      { "HoldCallInNetworkArg", "inap.HoldCallInNetworkArg",
        FT_UINT32, BASE_DEC, VALS(inap_HoldCallInNetworkArg_vals), 0,
        "inap.HoldCallInNetworkArg", HFILL }},
    { &hf_inap_InitialDP_PDU,
      { "InitialDP", "inap.InitialDP",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.InitialDP", HFILL }},
    { &hf_inap_InitiateCallAttemptArg_PDU,
      { "InitiateCallAttemptArg", "inap.InitiateCallAttemptArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.InitiateCallAttemptArg", HFILL }},
    { &hf_inap_MidCallArg_PDU,
      { "MidCallArg", "inap.MidCallArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.MidCallArg", HFILL }},
    { &hf_inap_OAnswerArg_PDU,
      { "OAnswerArg", "inap.OAnswerArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.OAnswerArg", HFILL }},
    { &hf_inap_OCalledPartyBusyArg_PDU,
      { "OCalledPartyBusyArg", "inap.OCalledPartyBusyArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.OCalledPartyBusyArg", HFILL }},
    { &hf_inap_ODisconnectArg_PDU,
      { "ODisconnectArg", "inap.ODisconnectArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.ODisconnectArg", HFILL }},
    { &hf_inap_ONoAnswer_PDU,
      { "ONoAnswer", "inap.ONoAnswer",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.ONoAnswer", HFILL }},
    { &hf_inap_OriginationAttemptAuthorizedArg_PDU,
      { "OriginationAttemptAuthorizedArg", "inap.OriginationAttemptAuthorizedArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.OriginationAttemptAuthorizedArg", HFILL }},
    { &hf_inap_PlayAnnouncementArg_PDU,
      { "PlayAnnouncementArg", "inap.PlayAnnouncementArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.PlayAnnouncementArg", HFILL }},
    { &hf_inap_PromptAndCollectUserInformationArg_PDU,
      { "PromptAndCollectUserInformationArg", "inap.PromptAndCollectUserInformationArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.PromptAndCollectUserInformationArg", HFILL }},
    { &hf_inap_ReceivedInformationArg_PDU,
      { "ReceivedInformationArg", "inap.ReceivedInformationArg",
        FT_UINT32, BASE_DEC, VALS(inap_ReceivedInformationArg_vals), 0,
        "inap.ReceivedInformationArg", HFILL }},
    { &hf_inap_ReleaseCallArg_PDU,
      { "ReleaseCallArg", "inap.ReleaseCallArg",
        FT_UINT32, BASE_DEC, VALS(inap_ReleaseCallArg_vals), 0,
        "inap.ReleaseCallArg", HFILL }},
    { &hf_inap_RequestCurrentStatusReportArg_PDU,
      { "RequestCurrentStatusReportArg", "inap.RequestCurrentStatusReportArg",
        FT_UINT32, BASE_DEC, VALS(inap_ResourceID_vals), 0,
        "inap.RequestCurrentStatusReportArg", HFILL }},
    { &hf_inap_RequestCurrentStatusReportResultArg_PDU,
      { "RequestCurrentStatusReportResultArg", "inap.RequestCurrentStatusReportResultArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.RequestCurrentStatusReportResultArg", HFILL }},
    { &hf_inap_RequestEveryStatusChangeReportArg_PDU,
      { "RequestEveryStatusChangeReportArg", "inap.RequestEveryStatusChangeReportArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.RequestEveryStatusChangeReportArg", HFILL }},
    { &hf_inap_RequestFirstStatusMatchReportArg_PDU,
      { "RequestFirstStatusMatchReportArg", "inap.RequestFirstStatusMatchReportArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.RequestFirstStatusMatchReportArg", HFILL }},
    { &hf_inap_RequestNotificationChargingEvent_PDU,
      { "RequestNotificationChargingEvent", "inap.RequestNotificationChargingEvent",
        FT_UINT32, BASE_DEC, NULL, 0,
        "inap.RequestNotificationChargingEvent", HFILL }},
    { &hf_inap_RequestReportBCSMEventArg_PDU,
      { "RequestReportBCSMEventArg", "inap.RequestReportBCSMEventArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.RequestReportBCSMEventArg", HFILL }},
    { &hf_inap_ResetTimerArg_PDU,
      { "ResetTimerArg", "inap.ResetTimerArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.ResetTimerArg", HFILL }},
    { &hf_inap_RouteSelectFailureArg_PDU,
      { "RouteSelectFailureArg", "inap.RouteSelectFailureArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.RouteSelectFailureArg", HFILL }},
    { &hf_inap_SelectFacilityArg_PDU,
      { "SelectFacilityArg", "inap.SelectFacilityArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.SelectFacilityArg", HFILL }},
    { &hf_inap_SelectRouteArg_PDU,
      { "SelectRouteArg", "inap.SelectRouteArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.SelectRouteArg", HFILL }},
    { &hf_inap_ServiceFilteringResponseArg_PDU,
      { "ServiceFilteringResponseArg", "inap.ServiceFilteringResponseArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.ServiceFilteringResponseArg", HFILL }},
    { &hf_inap_SpecializedResourceReportArg_PDU,
      { "SpecializedResourceReportArg", "inap.SpecializedResourceReportArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.SpecializedResourceReportArg", HFILL }},
    { &hf_inap_StatusReportArg_PDU,
      { "StatusReportArg", "inap.StatusReportArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.StatusReportArg", HFILL }},
    { &hf_inap_TAnswerArg_PDU,
      { "TAnswerArg", "inap.TAnswerArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.TAnswerArg", HFILL }},
    { &hf_inap_TBusyArg_PDU,
      { "TBusyArg", "inap.TBusyArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.TBusyArg", HFILL }},
    { &hf_inap_TDisconnectArg_PDU,
      { "TDisconnectArg", "inap.TDisconnectArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.TDisconnectArg", HFILL }},
    { &hf_inap_TermAttemptAuthorizedArg_PDU,
      { "TermAttemptAuthorizedArg", "inap.TermAttemptAuthorizedArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.TermAttemptAuthorizedArg", HFILL }},
    { &hf_inap_TNoAnswerArg_PDU,
      { "TNoAnswerArg", "inap.TNoAnswerArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.TNoAnswerArg", HFILL }},
    { &hf_inap_invoke,
      { "invoke", "inap.invoke",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.Invoke", HFILL }},
    { &hf_inap_returnResultLast,
      { "returnResultLast", "inap.returnResultLast",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.ReturnResult", HFILL }},
    { &hf_inap_returnError,
      { "returnError", "inap.returnError",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.ReturnError", HFILL }},
    { &hf_inap_reject,
      { "reject", "inap.reject",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.Reject", HFILL }},
    { &hf_inap_returnResultNotLast,
      { "returnResultNotLast", "inap.returnResultNotLast",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.ReturnResult", HFILL }},
    { &hf_inap_invokeID,
      { "invokeID", "inap.invokeID",
        FT_INT32, BASE_DEC, NULL, 0,
        "inap.InvokeIdType", HFILL }},
    { &hf_inap_linkedID,
      { "linkedID", "inap.linkedID",
        FT_INT32, BASE_DEC, NULL, 0,
        "inap.InvokeIdType", HFILL }},
    { &hf_inap_opCode,
      { "opCode", "inap.opCode",
        FT_UINT32, BASE_DEC, VALS(inap_OPERATION_vals), 0,
        "inap.OPERATION", HFILL }},
    { &hf_inap_invokeparameter,
      { "invokeparameter", "inap.invokeparameter",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.InvokeParameter", HFILL }},
    { &hf_inap_resultretres,
      { "resultretres", "inap.resultretres",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.T_resultretres", HFILL }},
    { &hf_inap_returnparameter,
      { "returnparameter", "inap.returnparameter",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.ReturnResultParameter", HFILL }},
    { &hf_inap_errorCode,
      { "errorCode", "inap.errorCode",
        FT_UINT32, BASE_DEC, VALS(inap_ERROR_vals), 0,
        "inap.ERROR", HFILL }},
    { &hf_inap_parameter,
      { "parameter", "inap.parameter",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.ReturnErrorParameter", HFILL }},
    { &hf_inap_invokeIDRej,
      { "invokeIDRej", "inap.invokeIDRej",
        FT_UINT32, BASE_DEC, VALS(inap_T_invokeIDRej_vals), 0,
        "inap.T_invokeIDRej", HFILL }},
    { &hf_inap_derivable,
      { "derivable", "inap.derivable",
        FT_INT32, BASE_DEC, NULL, 0,
        "inap.InvokeIdType", HFILL }},
    { &hf_inap_not_derivable,
      { "not-derivable", "inap.not_derivable",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.NULL", HFILL }},
    { &hf_inap_problem,
      { "problem", "inap.problem",
        FT_UINT32, BASE_DEC, VALS(inap_T_problem_vals), 0,
        "inap.T_problem", HFILL }},
    { &hf_inap_generalProblem,
      { "generalProblem", "inap.generalProblem",
        FT_INT32, BASE_DEC, VALS(inap_GeneralProblem_vals), 0,
        "inap.GeneralProblem", HFILL }},
    { &hf_inap_invokeProblem,
      { "invokeProblem", "inap.invokeProblem",
        FT_INT32, BASE_DEC, VALS(inap_InvokeProblem_vals), 0,
        "inap.InvokeProblem", HFILL }},
    { &hf_inap_returnResultProblem,
      { "returnResultProblem", "inap.returnResultProblem",
        FT_INT32, BASE_DEC, VALS(inap_ReturnResultProblem_vals), 0,
        "inap.ReturnResultProblem", HFILL }},
    { &hf_inap_returnErrorProblem,
      { "returnErrorProblem", "inap.returnErrorProblem",
        FT_INT32, BASE_DEC, VALS(inap_ReturnErrorProblem_vals), 0,
        "inap.ReturnErrorProblem", HFILL }},
    { &hf_inap_localValue,
      { "localValue", "inap.localValue",
        FT_INT32, BASE_DEC, NULL, 0,
        "inap.OperationLocalvalue", HFILL }},
    { &hf_inap_globalValue,
      { "globalValue", "inap.globalValue",
        FT_OID, BASE_NONE, NULL, 0,
        "inap.OBJECT_IDENTIFIER", HFILL }},
    { &hf_inap_localValue_01,
      { "localValue", "inap.localValue",
        FT_INT32, BASE_DEC, NULL, 0,
        "inap.LocalErrorcode", HFILL }},
    { &hf_inap_originalCallID,
      { "originalCallID", "inap.originalCallID",
        FT_INT32, BASE_DEC, NULL, 0,
        "inap.CallID", HFILL }},
    { &hf_inap_destinationCallID,
      { "destinationCallID", "inap.destinationCallID",
        FT_INT32, BASE_DEC, NULL, 0,
        "inap.CallID", HFILL }},
    { &hf_inap_newLegID,
      { "newLegID", "inap.newLegID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.OCTET_STRING", HFILL }},
    { &hf_inap_correlationidentifier,
      { "correlationidentifier", "inap.correlationidentifier",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.OCTET_STRING", HFILL }},
    { &hf_inap_CallPartyHandlingResultsArg_item,
      { "Item", "inap.CallPartyHandlingResultsArg_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.LegInformation", HFILL }},
    { &hf_inap_callID,
      { "callID", "inap.callID",
        FT_INT32, BASE_DEC, NULL, 0,
        "inap.CallID", HFILL }},
    { &hf_inap_targetCallID,
      { "targetCallID", "inap.targetCallID",
        FT_INT32, BASE_DEC, NULL, 0,
        "inap.CallID", HFILL }},
    { &hf_inap_legToBeConnectedID,
      { "legToBeConnectedID", "inap.legToBeConnectedID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.OCTET_STRING", HFILL }},
    { &hf_inap_legToBeDetached,
      { "legToBeDetached", "inap.legToBeDetached",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.OCTET_STRING", HFILL }},
    { &hf_inap_legID,
      { "legID", "inap.legID",
        FT_UINT32, BASE_DEC, VALS(inap_LegID_vals), 0,
        "inap.LegID", HFILL }},
    { &hf_inap_heldLegID,
      { "heldLegID", "inap.heldLegID",
        FT_UINT32, BASE_DEC, VALS(inap_LegID_vals), 0,
        "inap.LegID", HFILL }},
    { &hf_inap_legToBeReleased,
      { "legToBeReleased", "inap.legToBeReleased",
        FT_UINT32, BASE_DEC, VALS(inap_LegID_vals), 0,
        "inap.LegID", HFILL }},
    { &hf_inap_releaseCause,
      { "releaseCause", "inap.releaseCause",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.Cause", HFILL }},
    { &hf_inap_legStatus,
      { "legStatus", "inap.legStatus",
        FT_UINT32, BASE_DEC, VALS(inap_LegStatus_vals), 0,
        "inap.LegStatus", HFILL }},
    { &hf_inap_Extensions_item,
      { "Item", "inap.Extensions_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.Extensions_item", HFILL }},
    { &hf_inap_type,
      { "type", "inap.type",
        FT_INT32, BASE_DEC, NULL, 0,
        "inap.INTEGER", HFILL }},
    { &hf_inap_criticality,
      { "criticality", "inap.criticality",
        FT_UINT32, BASE_DEC, VALS(inap_T_criticality_vals), 0,
        "inap.T_criticality", HFILL }},
    { &hf_inap_value,
      { "value", "inap.value",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.OCTET_STRING", HFILL }},
    { &hf_inap_filteredCallTreatment,
      { "filteredCallTreatment", "inap.filteredCallTreatment",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.FilteredCallTreatment", HFILL }},
    { &hf_inap_filteringCharacteristics,
      { "filteringCharacteristics", "inap.filteringCharacteristics",
        FT_UINT32, BASE_DEC, VALS(inap_FilteringCharacteristics_vals), 0,
        "inap.FilteringCharacteristics", HFILL }},
    { &hf_inap_filteringTimeOut,
      { "filteringTimeOut", "inap.filteringTimeOut",
        FT_UINT32, BASE_DEC, VALS(inap_FilteringTimeOut_vals), 0,
        "inap.FilteringTimeOut", HFILL }},
    { &hf_inap_filteringCriteria,
      { "filteringCriteria", "inap.filteringCriteria",
        FT_UINT32, BASE_DEC, VALS(inap_FilteringCriteria_vals), 0,
        "inap.FilteringCriteria", HFILL }},
    { &hf_inap_startTime,
      { "startTime", "inap.startTime",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.DateAndTime", HFILL }},
    { &hf_inap_extensions,
      { "extensions", "inap.extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "inap.Extensions", HFILL }},
    { &hf_inap_dpSpecificCommonParameters,
      { "dpSpecificCommonParameters", "inap.dpSpecificCommonParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.DpSpecificCommonParameters", HFILL }},
    { &hf_inap_dialledDigits,
      { "dialledDigits", "inap.dialledDigits",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.CalledPartyNumber", HFILL }},
    { &hf_inap_callingPartyBusinessGroupID,
      { "callingPartyBusinessGroupID", "inap.callingPartyBusinessGroupID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.CallingPartyBusinessGroupID", HFILL }},
    { &hf_inap_callingPartySubaddress,
      { "callingPartySubaddress", "inap.callingPartySubaddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.CallingPartySubaddress", HFILL }},
    { &hf_inap_callingFacilityGroup,
      { "callingFacilityGroup", "inap.callingFacilityGroup",
        FT_UINT32, BASE_DEC, VALS(inap_FacilityGroup_vals), 0,
        "inap.FacilityGroup", HFILL }},
    { &hf_inap_callingFacilityGroupMember,
      { "callingFacilityGroupMember", "inap.callingFacilityGroupMember",
        FT_INT32, BASE_DEC, NULL, 0,
        "inap.FacilityGroupMember", HFILL }},
    { &hf_inap_originalCalledPartyID,
      { "originalCalledPartyID", "inap.originalCalledPartyID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.OriginalCalledPartyID", HFILL }},
    { &hf_inap_prefix,
      { "prefix", "inap.prefix",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.Digits", HFILL }},
    { &hf_inap_redirectingPartyID,
      { "redirectingPartyID", "inap.redirectingPartyID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.RedirectingPartyID", HFILL }},
    { &hf_inap_redirectionInformation,
      { "redirectionInformation", "inap.redirectionInformation",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.RedirectionInformation", HFILL }},
    { &hf_inap_routeList,
      { "routeList", "inap.routeList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "inap.RouteList", HFILL }},
    { &hf_inap_travellingClassMark,
      { "travellingClassMark", "inap.travellingClassMark",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.TravellingClassMark", HFILL }},
    { &hf_inap_featureCode,
      { "featureCode", "inap.featureCode",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.FeatureCode", HFILL }},
    { &hf_inap_accessCode,
      { "accessCode", "inap.accessCode",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.AccessCode", HFILL }},
    { &hf_inap_carrier,
      { "carrier", "inap.carrier",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.Carrier", HFILL }},
    { &hf_inap_destinationRoutingAddress,
      { "destinationRoutingAddress", "inap.destinationRoutingAddress",
        FT_UINT32, BASE_DEC, NULL, 0,
        "inap.DestinationRoutingAddress", HFILL }},
    { &hf_inap_alertingPattern,
      { "alertingPattern", "inap.alertingPattern",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.AlertingPattern", HFILL }},
    { &hf_inap_iSDNAccessRelatedInformation,
      { "iSDNAccessRelatedInformation", "inap.iSDNAccessRelatedInformation",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.ISDNAccessRelatedInformation", HFILL }},
    { &hf_inap_callingPartyNumber,
      { "callingPartyNumber", "inap.callingPartyNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.CallingPartyNumber", HFILL }},
    { &hf_inap_callingPartysCategory,
      { "callingPartysCategory", "inap.callingPartysCategory",
        FT_UINT16, BASE_DEC, VALS(isup_calling_partys_category_value), 0,
        "inap.CallingPartysCategory", HFILL }},
    { &hf_inap_calledPartyNumber,
      { "calledPartyNumber", "inap.calledPartyNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.CalledPartyNumber", HFILL }},
    { &hf_inap_chargeNumber,
      { "chargeNumber", "inap.chargeNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.ChargeNumber", HFILL }},
    { &hf_inap_aChBillingChargingCharacteristics,
      { "aChBillingChargingCharacteristics", "inap.aChBillingChargingCharacteristics",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.AChBillingChargingCharacteristics", HFILL }},
    { &hf_inap_partyToCharge,
      { "partyToCharge", "inap.partyToCharge",
        FT_UINT32, BASE_DEC, VALS(inap_LegID_vals), 0,
        "inap.LegID", HFILL }},
    { &hf_inap_correlationID,
      { "correlationID", "inap.correlationID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.CorrelationID", HFILL }},
    { &hf_inap_iPAvailable,
      { "iPAvailable", "inap.iPAvailable",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.IPAvailable", HFILL }},
    { &hf_inap_iPSSPCapabilities,
      { "iPSSPCapabilities", "inap.iPSSPCapabilities",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.IPSSPCapabilities", HFILL }},
    { &hf_inap_gapCriteria,
      { "gapCriteria", "inap.gapCriteria",
        FT_UINT32, BASE_DEC, VALS(inap_GapCriteria_vals), 0,
        "inap.GapCriteria", HFILL }},
    { &hf_inap_gapIndicators,
      { "gapIndicators", "inap.gapIndicators",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.GapIndicators", HFILL }},
    { &hf_inap_controlType,
      { "controlType", "inap.controlType",
        FT_UINT32, BASE_DEC, VALS(inap_ControlType_vals), 0,
        "inap.ControlType", HFILL }},
    { &hf_inap_gapTreatment,
      { "gapTreatment", "inap.gapTreatment",
        FT_UINT32, BASE_DEC, VALS(inap_GapTreatment_vals), 0,
        "inap.GapTreatment", HFILL }},
    { &hf_inap_requestedInformationTypeList,
      { "requestedInformationTypeList", "inap.requestedInformationTypeList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "inap.RequestedInformationTypeList", HFILL }},
    { &hf_inap_invokeID_01,
      { "invokeID", "inap.invokeID",
        FT_INT32, BASE_DEC, NULL, 0,
        "inap.InvokeID", HFILL }},
    { &hf_inap_allRequests,
      { "allRequests", "inap.allRequests",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.NULL", HFILL }},
    { &hf_inap_resourceID,
      { "resourceID", "inap.resourceID",
        FT_UINT32, BASE_DEC, VALS(inap_ResourceID_vals), 0,
        "inap.ResourceID", HFILL }},
    { &hf_inap_numberingPlan,
      { "numberingPlan", "inap.numberingPlan",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.NumberingPlan", HFILL }},
    { &hf_inap_cutAndPaste,
      { "cutAndPaste", "inap.cutAndPaste",
        FT_UINT32, BASE_DEC, NULL, 0,
        "inap.CutAndPaste", HFILL }},
    { &hf_inap_forwardingCondition,
      { "forwardingCondition", "inap.forwardingCondition",
        FT_UINT32, BASE_DEC, VALS(inap_ForwardingCondition_vals), 0,
        "inap.ForwardingCondition", HFILL }},
    { &hf_inap_scfID,
      { "scfID", "inap.scfID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.ScfID", HFILL }},
    { &hf_inap_serviceInteractionIndicators,
      { "serviceInteractionIndicators", "inap.serviceInteractionIndicators",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.ServiceInteractionIndicators", HFILL }},
    { &hf_inap_resourceAddress,
      { "resourceAddress", "inap.resourceAddress",
        FT_UINT32, BASE_DEC, VALS(inap_T_resourceAddress_vals), 0,
        "inap.T_resourceAddress", HFILL }},
    { &hf_inap_ipRoutingAddress,
      { "ipRoutingAddress", "inap.ipRoutingAddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.IPRoutingAddress", HFILL }},
    { &hf_inap_both2,
      { "both2", "inap.both2",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.T_both2", HFILL }},
    { &hf_inap_none,
      { "none", "inap.none",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.NULL", HFILL }},
    { &hf_inap_serviceAddressInformation,
      { "serviceAddressInformation", "inap.serviceAddressInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.ServiceAddressInformation", HFILL }},
    { &hf_inap_bearerCapability,
      { "bearerCapability", "inap.bearerCapability",
        FT_UINT32, BASE_DEC, VALS(inap_BearerCapability_vals), 0,
        "inap.BearerCapability", HFILL }},
    { &hf_inap_cGEncountered,
      { "cGEncountered", "inap.cGEncountered",
        FT_UINT32, BASE_DEC, VALS(inap_CGEncountered_vals), 0,
        "inap.CGEncountered", HFILL }},
    { &hf_inap_locationNumber,
      { "locationNumber", "inap.locationNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.LocationNumber", HFILL }},
    { &hf_inap_serviceProfileIdentifier,
      { "serviceProfileIdentifier", "inap.serviceProfileIdentifier",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.ServiceProfileIdentifier", HFILL }},
    { &hf_inap_terminalType,
      { "terminalType", "inap.terminalType",
        FT_UINT32, BASE_DEC, VALS(inap_TerminalType_vals), 0,
        "inap.TerminalType", HFILL }},
    { &hf_inap_servingAreaID,
      { "servingAreaID", "inap.servingAreaID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.ServingAreaID", HFILL }},
    { &hf_inap_assistingSSPIPRoutingAddress,
      { "assistingSSPIPRoutingAddress", "inap.assistingSSPIPRoutingAddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.AssistingSSPIPRoutingAddress", HFILL }},
    { &hf_inap_eventTypeCharging,
      { "eventTypeCharging", "inap.eventTypeCharging",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.EventTypeCharging", HFILL }},
    { &hf_inap_eventSpecificInformationCharging,
      { "eventSpecificInformationCharging", "inap.eventSpecificInformationCharging",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.EventSpecificInformationCharging", HFILL }},
    { &hf_inap_monitorMode,
      { "monitorMode", "inap.monitorMode",
        FT_UINT32, BASE_DEC, VALS(inap_MonitorMode_vals), 0,
        "inap.MonitorMode", HFILL }},
    { &hf_inap_eventTypeBCSM,
      { "eventTypeBCSM", "inap.eventTypeBCSM",
        FT_UINT32, BASE_DEC, VALS(inap_EventTypeBCSM_vals), 0,
        "inap.EventTypeBCSM", HFILL }},
    { &hf_inap_bcsmEventCorrelationID,
      { "bcsmEventCorrelationID", "inap.bcsmEventCorrelationID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.CorrelationID", HFILL }},
    { &hf_inap_eventSpecificInformationBCSM,
      { "eventSpecificInformationBCSM", "inap.eventSpecificInformationBCSM",
        FT_UINT32, BASE_DEC, VALS(inap_EventSpecificInformationBCSM_vals), 0,
        "inap.EventSpecificInformationBCSM", HFILL }},
    { &hf_inap_miscCallInfo,
      { "miscCallInfo", "inap.miscCallInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.MiscCallInfo", HFILL }},
    { &hf_inap_holdcause,
      { "holdcause", "inap.holdcause",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.HoldCause", HFILL }},
    { &hf_inap_empty,
      { "empty", "inap.empty",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.NULL", HFILL }},
    { &hf_inap_serviceKey,
      { "serviceKey", "inap.serviceKey",
        FT_UINT32, BASE_DEC, NULL, 0,
        "inap.ServiceKey", HFILL }},
    { &hf_inap_triggerType,
      { "triggerType", "inap.triggerType",
        FT_UINT32, BASE_DEC, VALS(inap_TriggerType_vals), 0,
        "inap.TriggerType", HFILL }},
    { &hf_inap_highLayerCompatibility,
      { "highLayerCompatibility", "inap.highLayerCompatibility",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.HighLayerCompatibility", HFILL }},
    { &hf_inap_additionalCallingPartyNumber,
      { "additionalCallingPartyNumber", "inap.additionalCallingPartyNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.AdditionalCallingPartyNumber", HFILL }},
    { &hf_inap_forwardCallIndicators,
      { "forwardCallIndicators", "inap.forwardCallIndicators",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.ForwardCallIndicators", HFILL }},
    { &hf_inap_calledPartyBusinessGroupID,
      { "calledPartyBusinessGroupID", "inap.calledPartyBusinessGroupID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.CalledPartyBusinessGroupID", HFILL }},
    { &hf_inap_calledPartySubaddress,
      { "calledPartySubaddress", "inap.calledPartySubaddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.CalledPartySubaddress", HFILL }},
    { &hf_inap_featureRequestIndicator,
      { "featureRequestIndicator", "inap.featureRequestIndicator",
        FT_UINT32, BASE_DEC, VALS(inap_FeatureRequestIndicator_vals), 0,
        "inap.FeatureRequestIndicator", HFILL }},
    { &hf_inap_busyCause,
      { "busyCause", "inap.busyCause",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.Cause", HFILL }},
    { &hf_inap_connectTime,
      { "connectTime", "inap.connectTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "inap.Integer4", HFILL }},
    { &hf_inap_informationToSend,
      { "informationToSend", "inap.informationToSend",
        FT_UINT32, BASE_DEC, VALS(inap_InformationToSend_vals), 0,
        "inap.InformationToSend", HFILL }},
    { &hf_inap_disconnectFromIPForbidden,
      { "disconnectFromIPForbidden", "inap.disconnectFromIPForbidden",
        FT_BOOLEAN, 8, NULL, 0,
        "inap.BOOLEAN", HFILL }},
    { &hf_inap_requestAnnouncementComplete,
      { "requestAnnouncementComplete", "inap.requestAnnouncementComplete",
        FT_BOOLEAN, 8, NULL, 0,
        "inap.BOOLEAN", HFILL }},
    { &hf_inap_collectedInfo,
      { "collectedInfo", "inap.collectedInfo",
        FT_UINT32, BASE_DEC, VALS(inap_CollectedInfo_vals), 0,
        "inap.CollectedInfo", HFILL }},
    { &hf_inap_digitsResponse,
      { "digitsResponse", "inap.digitsResponse",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.Digits", HFILL }},
    { &hf_inap_iA5Response,
      { "iA5Response", "inap.iA5Response",
        FT_STRING, BASE_NONE, NULL, 0,
        "inap.IA5String", HFILL }},
    { &hf_inap_initialCallSegment,
      { "initialCallSegment", "inap.initialCallSegment",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.Cause", HFILL }},
    { &hf_inap_allCallSegments,
      { "allCallSegments", "inap.allCallSegments",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.T_allCallSegments", HFILL }},
    { &hf_inap_resourceStatus,
      { "resourceStatus", "inap.resourceStatus",
        FT_UINT32, BASE_DEC, VALS(inap_ResourceStatus_vals), 0,
        "inap.ResourceStatus", HFILL }},
    { &hf_inap_monitorDuration,
      { "monitorDuration", "inap.monitorDuration",
        FT_INT32, BASE_DEC, NULL, 0,
        "inap.Duration", HFILL }},
    { &hf_inap_RequestNotificationChargingEvent_item,
      { "Item", "inap.RequestNotificationChargingEvent_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.RequestNotificationChargingEvent_item", HFILL }},
    { &hf_inap_eventTypeCharging2,
      { "eventTypeCharging2", "inap.eventTypeCharging2",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.OCTET_STRING", HFILL }},
    { &hf_inap_bcsmEvents,
      { "bcsmEvents", "inap.bcsmEvents",
        FT_UINT32, BASE_DEC, NULL, 0,
        "inap.SEQUENCE_SIZE_1_numOfBCSMEvents_OF_BCSMEvent", HFILL }},
    { &hf_inap_bcsmEvents_item,
      { "Item", "inap.bcsmEvents_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.BCSMEvent", HFILL }},
    { &hf_inap_timerID,
      { "timerID", "inap.timerID",
        FT_UINT32, BASE_DEC, VALS(inap_TimerID_vals), 0,
        "inap.TimerID", HFILL }},
    { &hf_inap_timervalue,
      { "timervalue", "inap.timervalue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "inap.TimerValue", HFILL }},
    { &hf_inap_failureCause,
      { "failureCause", "inap.failureCause",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.Cause", HFILL }},
    { &hf_inap_destinationNumberRoutingAddress,
      { "destinationNumberRoutingAddress", "inap.destinationNumberRoutingAddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.CalledPartyNumber", HFILL }},
    { &hf_inap_calledFacilityGroup,
      { "calledFacilityGroup", "inap.calledFacilityGroup",
        FT_UINT32, BASE_DEC, VALS(inap_FacilityGroup_vals), 0,
        "inap.FacilityGroup", HFILL }},
    { &hf_inap_calledFacilityGroupMember,
      { "calledFacilityGroupMember", "inap.calledFacilityGroupMember",
        FT_INT32, BASE_DEC, NULL, 0,
        "inap.FacilityGroupMember", HFILL }},
    { &hf_inap_sCIBillingChargingCharacteristics,
      { "sCIBillingChargingCharacteristics", "inap.sCIBillingChargingCharacteristics",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.SCIBillingChargingCharacteristics", HFILL }},
    { &hf_inap_countersValue,
      { "countersValue", "inap.countersValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "inap.CountersValue", HFILL }},
    { &hf_inap_responseCondition,
      { "responseCondition", "inap.responseCondition",
        FT_UINT32, BASE_DEC, VALS(inap_ResponseCondition_vals), 0,
        "inap.ResponseCondition", HFILL }},
    { &hf_inap_reportCondition,
      { "reportCondition", "inap.reportCondition",
        FT_UINT32, BASE_DEC, VALS(inap_ReportCondition_vals), 0,
        "inap.ReportCondition", HFILL }},
    { &hf_inap_dpSpecificCriteria,
      { "dpSpecificCriteria", "inap.dpSpecificCriteria",
        FT_UINT32, BASE_DEC, VALS(inap_DpSpecificCriteria_vals), 0,
        "inap.DpSpecificCriteria", HFILL }},
    { &hf_inap_bearerCap,
      { "bearerCap", "inap.bearerCap",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.BearerCap", HFILL }},
    { &hf_inap_tmr,
      { "tmr", "inap.tmr",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.OCTET_STRING_SIZE_1", HFILL }},
    { &hf_inap_minimumNbOfDigits,
      { "minimumNbOfDigits", "inap.minimumNbOfDigits",
        FT_UINT32, BASE_DEC, NULL, 0,
        "inap.INTEGER_1_127", HFILL }},
    { &hf_inap_maximumNbOfDigits,
      { "maximumNbOfDigits", "inap.maximumNbOfDigits",
        FT_UINT32, BASE_DEC, NULL, 0,
        "inap.INTEGER_1_127", HFILL }},
    { &hf_inap_endOfReplyDigit,
      { "endOfReplyDigit", "inap.endOfReplyDigit",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.OCTET_STRING_SIZE_1_2", HFILL }},
    { &hf_inap_cancelDigit,
      { "cancelDigit", "inap.cancelDigit",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.OCTET_STRING_SIZE_1_2", HFILL }},
    { &hf_inap_startDigit,
      { "startDigit", "inap.startDigit",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.OCTET_STRING_SIZE_1_2", HFILL }},
    { &hf_inap_firstDigitTimeOut,
      { "firstDigitTimeOut", "inap.firstDigitTimeOut",
        FT_UINT32, BASE_DEC, NULL, 0,
        "inap.INTEGER_1_127", HFILL }},
    { &hf_inap_interDigitTimeOut,
      { "interDigitTimeOut", "inap.interDigitTimeOut",
        FT_UINT32, BASE_DEC, NULL, 0,
        "inap.INTEGER_1_127", HFILL }},
    { &hf_inap_errorTreatment,
      { "errorTreatment", "inap.errorTreatment",
        FT_UINT32, BASE_DEC, VALS(inap_ErrorTreatment_vals), 0,
        "inap.ErrorTreatment", HFILL }},
    { &hf_inap_interruptableAnnInd,
      { "interruptableAnnInd", "inap.interruptableAnnInd",
        FT_BOOLEAN, 8, NULL, 0,
        "inap.BOOLEAN", HFILL }},
    { &hf_inap_voiceInformation,
      { "voiceInformation", "inap.voiceInformation",
        FT_BOOLEAN, 8, NULL, 0,
        "inap.BOOLEAN", HFILL }},
    { &hf_inap_voiceBack,
      { "voiceBack", "inap.voiceBack",
        FT_BOOLEAN, 8, NULL, 0,
        "inap.BOOLEAN", HFILL }},
    { &hf_inap_collectedDigits,
      { "collectedDigits", "inap.collectedDigits",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.CollectedDigits", HFILL }},
    { &hf_inap_iA5Information,
      { "iA5Information", "inap.iA5Information",
        FT_BOOLEAN, 8, NULL, 0,
        "inap.BOOLEAN", HFILL }},
    { &hf_inap_counterID,
      { "counterID", "inap.counterID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "inap.CounterID", HFILL }},
    { &hf_inap_counterValue,
      { "counterValue", "inap.counterValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "inap.Integer4", HFILL }},
    { &hf_inap_CountersValue_item,
      { "Item", "inap.CountersValue_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.CounterAndValue", HFILL }},
    { &hf_inap_DestinationRoutingAddress_item,
      { "Item", "inap.DestinationRoutingAddress_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.CalledPartyNumber", HFILL }},
    { &hf_inap_numberOfDigits,
      { "numberOfDigits", "inap.numberOfDigits",
        FT_UINT32, BASE_DEC, NULL, 0,
        "inap.NumberOfDigits", HFILL }},
    { &hf_inap_applicationTimer,
      { "applicationTimer", "inap.applicationTimer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "inap.ApplicationTimer", HFILL }},
    { &hf_inap_collectedInfoSpecificInfo,
      { "collectedInfoSpecificInfo", "inap.collectedInfoSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.T_collectedInfoSpecificInfo", HFILL }},
    { &hf_inap_calledPartynumber,
      { "calledPartynumber", "inap.calledPartynumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.CalledPartyNumber", HFILL }},
    { &hf_inap_analyzedInfoSpecificInfo,
      { "analyzedInfoSpecificInfo", "inap.analyzedInfoSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.T_analyzedInfoSpecificInfo", HFILL }},
    { &hf_inap_routeSelectFailureSpecificInfo,
      { "routeSelectFailureSpecificInfo", "inap.routeSelectFailureSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.T_routeSelectFailureSpecificInfo", HFILL }},
    { &hf_inap_oCalledPartyBusySpecificInfo,
      { "oCalledPartyBusySpecificInfo", "inap.oCalledPartyBusySpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.T_oCalledPartyBusySpecificInfo", HFILL }},
    { &hf_inap_oNoAnswerSpecificInfo,
      { "oNoAnswerSpecificInfo", "inap.oNoAnswerSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.T_oNoAnswerSpecificInfo", HFILL }},
    { &hf_inap_oAnswerSpecificInfo,
      { "oAnswerSpecificInfo", "inap.oAnswerSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.T_oAnswerSpecificInfo", HFILL }},
    { &hf_inap_oMidCallSpecificInfo,
      { "oMidCallSpecificInfo", "inap.oMidCallSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.T_oMidCallSpecificInfo", HFILL }},
    { &hf_inap_oDisconnectSpecificInfo,
      { "oDisconnectSpecificInfo", "inap.oDisconnectSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.T_oDisconnectSpecificInfo", HFILL }},
    { &hf_inap_tBusySpecificInfo,
      { "tBusySpecificInfo", "inap.tBusySpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.T_tBusySpecificInfo", HFILL }},
    { &hf_inap_tNoAnswerSpecificInfo,
      { "tNoAnswerSpecificInfo", "inap.tNoAnswerSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.T_tNoAnswerSpecificInfo", HFILL }},
    { &hf_inap_tAnswerSpecificInfo,
      { "tAnswerSpecificInfo", "inap.tAnswerSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.T_tAnswerSpecificInfo", HFILL }},
    { &hf_inap_tMidCallSpecificInfo,
      { "tMidCallSpecificInfo", "inap.tMidCallSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.T_tMidCallSpecificInfo", HFILL }},
    { &hf_inap_tDisconnectSpecificInfo,
      { "tDisconnectSpecificInfo", "inap.tDisconnectSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.T_tDisconnectSpecificInfo", HFILL }},
    { &hf_inap_trunkGroupID,
      { "trunkGroupID", "inap.trunkGroupID",
        FT_INT32, BASE_DEC, NULL, 0,
        "inap.INTEGER", HFILL }},
    { &hf_inap_privateFacilityID,
      { "privateFacilityID", "inap.privateFacilityID",
        FT_INT32, BASE_DEC, NULL, 0,
        "inap.INTEGER", HFILL }},
    { &hf_inap_huntGroup,
      { "huntGroup", "inap.huntGroup",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.OCTET_STRING", HFILL }},
    { &hf_inap_routeIndex,
      { "routeIndex", "inap.routeIndex",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.OCTET_STRING", HFILL }},
    { &hf_inap_sFBillingChargingCharacteristics,
      { "sFBillingChargingCharacteristics", "inap.sFBillingChargingCharacteristics",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.SFBillingChargingCharacteristics", HFILL }},
    { &hf_inap_maximumNumberOfCounters,
      { "maximumNumberOfCounters", "inap.maximumNumberOfCounters",
        FT_UINT32, BASE_DEC, NULL, 0,
        "inap.MaximumNumberOfCounters", HFILL }},
    { &hf_inap_interval1,
      { "interval1", "inap.interval1",
        FT_INT32, BASE_DEC, NULL, 0,
        "inap.INTEGER_M1_32000", HFILL }},
    { &hf_inap_numberOfCalls,
      { "numberOfCalls", "inap.numberOfCalls",
        FT_UINT32, BASE_DEC, NULL, 0,
        "inap.Integer4", HFILL }},
    { &hf_inap_dialledNumber,
      { "dialledNumber", "inap.dialledNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.Digits", HFILL }},
    { &hf_inap_callingLineID,
      { "callingLineID", "inap.callingLineID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.Digits", HFILL }},
    { &hf_inap_addressAndService,
      { "addressAndService", "inap.addressAndService",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.T_addressAndService", HFILL }},
    { &hf_inap_calledAddressValue,
      { "calledAddressValue", "inap.calledAddressValue",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.Digits", HFILL }},
    { &hf_inap_callingAddressValue,
      { "callingAddressValue", "inap.callingAddressValue",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.Digits", HFILL }},
    { &hf_inap_duration,
      { "duration", "inap.duration",
        FT_INT32, BASE_DEC, NULL, 0,
        "inap.Duration", HFILL }},
    { &hf_inap_stopTime,
      { "stopTime", "inap.stopTime",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.DateAndTime", HFILL }},
    { &hf_inap_gapOnService,
      { "gapOnService", "inap.gapOnService",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.GapOnService", HFILL }},
    { &hf_inap_calledAddressAndService,
      { "calledAddressAndService", "inap.calledAddressAndService",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.T_calledAddressAndService", HFILL }},
    { &hf_inap_callingAddressAndService,
      { "callingAddressAndService", "inap.callingAddressAndService",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.T_callingAddressAndService", HFILL }},
    { &hf_inap_dpCriteria,
      { "dpCriteria", "inap.dpCriteria",
        FT_UINT32, BASE_DEC, VALS(inap_EventTypeBCSM_vals), 0,
        "inap.EventTypeBCSM", HFILL }},
    { &hf_inap_gapInterval,
      { "gapInterval", "inap.gapInterval",
        FT_INT32, BASE_DEC, NULL, 0,
        "inap.Interval", HFILL }},
    { &hf_inap_both,
      { "both", "inap.both",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.T_both", HFILL }},
    { &hf_inap_messageID,
      { "messageID", "inap.messageID",
        FT_UINT32, BASE_DEC, VALS(inap_MessageID_vals), 0,
        "inap.MessageID", HFILL }},
    { &hf_inap_numberOfRepetitions,
      { "numberOfRepetitions", "inap.numberOfRepetitions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "inap.INTEGER_1_127", HFILL }},
    { &hf_inap_duration3,
      { "duration3", "inap.duration3",
        FT_UINT32, BASE_DEC, NULL, 0,
        "inap.INTEGER_0_32767", HFILL }},
    { &hf_inap_interval,
      { "interval", "inap.interval",
        FT_UINT32, BASE_DEC, NULL, 0,
        "inap.INTEGER_0_32767", HFILL }},
    { &hf_inap_inbandInfo,
      { "inbandInfo", "inap.inbandInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.InbandInfo", HFILL }},
    { &hf_inap_tone,
      { "tone", "inap.tone",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.Tone", HFILL }},
    { &hf_inap_displayInformation,
      { "displayInformation", "inap.displayInformation",
        FT_STRING, BASE_NONE, NULL, 0,
        "inap.DisplayInformation", HFILL }},
    { &hf_inap_sendingSideID,
      { "sendingSideID", "inap.sendingSideID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.LegType", HFILL }},
    { &hf_inap_receivingSideID,
      { "receivingSideID", "inap.receivingSideID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.LegType", HFILL }},
    { &hf_inap_elementaryMessageID,
      { "elementaryMessageID", "inap.elementaryMessageID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "inap.Integer4", HFILL }},
    { &hf_inap_text,
      { "text", "inap.text",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.T_text", HFILL }},
    { &hf_inap_messageContent,
      { "messageContent", "inap.messageContent",
        FT_STRING, BASE_NONE, NULL, 0,
        "inap.IA5String_SIZE_minMessageContentLength_maxMessageContentLength", HFILL }},
    { &hf_inap_attributes,
      { "attributes", "inap.attributes",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.OCTET_STRING_SIZE_minAttributesLength_maxAttributesLength", HFILL }},
    { &hf_inap_elementaryMessageIDs,
      { "elementaryMessageIDs", "inap.elementaryMessageIDs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "inap.SEQUENCE_SIZE_1_numOfMessageIDs_OF_Integer4", HFILL }},
    { &hf_inap_elementaryMessageIDs_item,
      { "Item", "inap.elementaryMessageIDs_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "inap.Integer4", HFILL }},
    { &hf_inap_variableMessage,
      { "variableMessage", "inap.variableMessage",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.T_variableMessage", HFILL }},
    { &hf_inap_variableParts,
      { "variableParts", "inap.variableParts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "inap.SEQUENCE_SIZE_1_5_OF_VariablePart", HFILL }},
    { &hf_inap_variableParts_item,
      { "Item", "inap.variableParts_item",
        FT_UINT32, BASE_DEC, VALS(inap_VariablePart_vals), 0,
        "inap.VariablePart", HFILL }},
    { &hf_inap_messageType,
      { "messageType", "inap.messageType",
        FT_UINT32, BASE_DEC, VALS(inap_T_messageType_vals), 0,
        "inap.T_messageType", HFILL }},
    { &hf_inap_dpAssignment,
      { "dpAssignment", "inap.dpAssignment",
        FT_UINT32, BASE_DEC, VALS(inap_T_dpAssignment_vals), 0,
        "inap.T_dpAssignment", HFILL }},
    { &hf_inap_RequestedInformationList_item,
      { "Item", "inap.RequestedInformationList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "inap.RequestedInformation", HFILL }},
    { &hf_inap_RequestedInformationTypeList_item,
      { "Item", "inap.RequestedInformationTypeList_item",
        FT_UINT32, BASE_DEC, VALS(inap_RequestedInformationType_vals), 0,
        "inap.RequestedInformationType", HFILL }},
    { &hf_inap_requestedInformationType,
      { "requestedInformationType", "inap.requestedInformationType",
        FT_UINT32, BASE_DEC, VALS(inap_RequestedInformationType_vals), 0,
        "inap.RequestedInformationType", HFILL }},
    { &hf_inap_requestedInformationValue,
      { "requestedInformationValue", "inap.requestedInformationValue",
        FT_UINT32, BASE_DEC, VALS(inap_RequestedInformationValue_vals), 0,
        "inap.RequestedInformationValue", HFILL }},
    { &hf_inap_callAttemptElapsedTimeValue,
      { "callAttemptElapsedTimeValue", "inap.callAttemptElapsedTimeValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "inap.INTEGER_0_255", HFILL }},
    { &hf_inap_callStopTimeValue,
      { "callStopTimeValue", "inap.callStopTimeValue",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.DateAndTime", HFILL }},
    { &hf_inap_callConnectedElapsedTimeValue,
      { "callConnectedElapsedTimeValue", "inap.callConnectedElapsedTimeValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "inap.Integer4", HFILL }},
    { &hf_inap_releaseCauseValue,
      { "releaseCauseValue", "inap.releaseCauseValue",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.Cause", HFILL }},
    { &hf_inap_lineID,
      { "lineID", "inap.lineID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.Digits", HFILL }},
    { &hf_inap_facilityGroupID,
      { "facilityGroupID", "inap.facilityGroupID",
        FT_UINT32, BASE_DEC, VALS(inap_FacilityGroup_vals), 0,
        "inap.FacilityGroup", HFILL }},
    { &hf_inap_facilityGroupMemberID,
      { "facilityGroupMemberID", "inap.facilityGroupMemberID",
        FT_INT32, BASE_DEC, NULL, 0,
        "inap.INTEGER", HFILL }},
    { &hf_inap_RouteList_item,
      { "Item", "inap.RouteList_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.OCTET_STRING", HFILL }},
    { &hf_inap_toneID,
      { "toneID", "inap.toneID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "inap.Integer4", HFILL }},
    { &hf_inap_tone_duration,
      { "tone-duration", "inap.tone_duration",
        FT_UINT32, BASE_DEC, NULL, 0,
        "inap.Integer4", HFILL }},
    { &hf_inap_integer,
      { "integer", "inap.integer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "inap.Integer4", HFILL }},
    { &hf_inap_number,
      { "number", "inap.number",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.Digits", HFILL }},
    { &hf_inap_time,
      { "time", "inap.time",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.OCTET_STRING_SIZE_2", HFILL }},
    { &hf_inap_date2,
      { "date2", "inap.date2",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.OCTET_STRING_SIZE_3", HFILL }},
    { &hf_inap_price,
      { "price", "inap.price",
        FT_BYTES, BASE_HEX, NULL, 0,
        "inap.OCTET_STRING_SIZE_4", HFILL }},
    { &hf_inap_problem_01,
      { "problem", "inap.problem",
        FT_UINT32, BASE_DEC, VALS(inap_T_problem_01_vals), 0,
        "inap.T_problem_01", HFILL }},
    { &hf_inap_operation,
      { "operation", "inap.operation",
        FT_INT32, BASE_DEC, NULL, 0,
        "inap.INTEGER_M128_127", HFILL }},

/*--- End of included file: packet-inap-hfarr.c ---*/
#line 459 "packet-inap-template.c"
  };






  /* List of subtrees */
  static gint *ett[] = {
    &ett_inap,
	&ett_inapisup_parameter,

/*--- Included file: packet-inap-ettarr.c ---*/
#line 1 "packet-inap-ettarr.c"
    &ett_inap_Component,
    &ett_inap_Invoke,
    &ett_inap_ReturnResult,
    &ett_inap_T_resultretres,
    &ett_inap_ReturnError,
    &ett_inap_Reject,
    &ett_inap_T_invokeIDRej,
    &ett_inap_T_problem,
    &ett_inap_OPERATION,
    &ett_inap_ERROR,
    &ett_inap_AddPartyArg,
    &ett_inap_AttachArg,
    &ett_inap_CallPartyHandlingResultsArg,
    &ett_inap_ChangePartiesArg,
    &ett_inap_DetachArg,
    &ett_inap_HoldCallPartyConnectionArg,
    &ett_inap_ReconnectArg,
    &ett_inap_ReleaseCallPartyConnectionArg,
    &ett_inap_LegInformation,
    &ett_inap_Extensions,
    &ett_inap_Extensions_item,
    &ett_inap_ActivateServiceFilteringArg,
    &ett_inap_AnalysedInformationArg,
    &ett_inap_AnalyseInformationArg,
    &ett_inap_ApplyChargingArg,
    &ett_inap_AssistRequestInstructionsArg,
    &ett_inap_CallGapArg,
    &ett_inap_CallInformationReportArg,
    &ett_inap_CallInformationRequestArg,
    &ett_inap_CancelArg,
    &ett_inap_CancelStatusReportRequestArg,
    &ett_inap_CollectedInformationArg,
    &ett_inap_CollectInformationArg,
    &ett_inap_ConnectArg,
    &ett_inap_ConnectToResourceArg,
    &ett_inap_T_resourceAddress,
    &ett_inap_T_both2,
    &ett_inap_DpSpecificCommonParameters,
    &ett_inap_EstablishTemporaryConnectionArg,
    &ett_inap_EventNotificationChargingArg,
    &ett_inap_EventReportBCSMArg,
    &ett_inap_HoldCallInNetworkArg,
    &ett_inap_InitialDP,
    &ett_inap_InitiateCallAttemptArg,
    &ett_inap_MidCallArg,
    &ett_inap_OAnswerArg,
    &ett_inap_OCalledPartyBusyArg,
    &ett_inap_ODisconnectArg,
    &ett_inap_ONoAnswer,
    &ett_inap_OriginationAttemptAuthorizedArg,
    &ett_inap_PlayAnnouncementArg,
    &ett_inap_PromptAndCollectUserInformationArg,
    &ett_inap_ReceivedInformationArg,
    &ett_inap_ReleaseCallArg,
    &ett_inap_T_allCallSegments,
    &ett_inap_RequestCurrentStatusReportResultArg,
    &ett_inap_RequestEveryStatusChangeReportArg,
    &ett_inap_RequestFirstStatusMatchReportArg,
    &ett_inap_RequestNotificationChargingEvent,
    &ett_inap_RequestNotificationChargingEvent_item,
    &ett_inap_RequestReportBCSMEventArg,
    &ett_inap_SEQUENCE_SIZE_1_numOfBCSMEvents_OF_BCSMEvent,
    &ett_inap_ResetTimerArg,
    &ett_inap_RouteSelectFailureArg,
    &ett_inap_SelectFacilityArg,
    &ett_inap_SelectRouteArg,
    &ett_inap_SendChargingInformationArg,
    &ett_inap_ServiceFilteringResponseArg,
    &ett_inap_StatusReportArg,
    &ett_inap_TAnswerArg,
    &ett_inap_TBusyArg,
    &ett_inap_TDisconnectArg,
    &ett_inap_TermAttemptAuthorizedArg,
    &ett_inap_TNoAnswerArg,
    &ett_inap_BCSMEvent,
    &ett_inap_BearerCapability,
    &ett_inap_ChargingEvent,
    &ett_inap_CollectedDigits,
    &ett_inap_CollectedInfo,
    &ett_inap_CounterAndValue,
    &ett_inap_CountersValue,
    &ett_inap_DestinationRoutingAddress,
    &ett_inap_DpSpecificCriteria,
    &ett_inap_EventSpecificInformationBCSM,
    &ett_inap_T_collectedInfoSpecificInfo,
    &ett_inap_T_analyzedInfoSpecificInfo,
    &ett_inap_T_routeSelectFailureSpecificInfo,
    &ett_inap_T_oCalledPartyBusySpecificInfo,
    &ett_inap_T_oNoAnswerSpecificInfo,
    &ett_inap_T_oAnswerSpecificInfo,
    &ett_inap_T_oMidCallSpecificInfo,
    &ett_inap_T_oDisconnectSpecificInfo,
    &ett_inap_T_tBusySpecificInfo,
    &ett_inap_T_tNoAnswerSpecificInfo,
    &ett_inap_T_tAnswerSpecificInfo,
    &ett_inap_T_tMidCallSpecificInfo,
    &ett_inap_T_tDisconnectSpecificInfo,
    &ett_inap_FacilityGroup,
    &ett_inap_FilteredCallTreatment,
    &ett_inap_FilteringCharacteristics,
    &ett_inap_FilteringCriteria,
    &ett_inap_T_addressAndService,
    &ett_inap_FilteringTimeOut,
    &ett_inap_GapCriteria,
    &ett_inap_T_calledAddressAndService,
    &ett_inap_T_callingAddressAndService,
    &ett_inap_GapOnService,
    &ett_inap_GapIndicators,
    &ett_inap_GapTreatment,
    &ett_inap_T_both,
    &ett_inap_InbandInfo,
    &ett_inap_InformationToSend,
    &ett_inap_LegID,
    &ett_inap_MessageID,
    &ett_inap_T_text,
    &ett_inap_SEQUENCE_SIZE_1_numOfMessageIDs_OF_Integer4,
    &ett_inap_T_variableMessage,
    &ett_inap_SEQUENCE_SIZE_1_5_OF_VariablePart,
    &ett_inap_MiscCallInfo,
    &ett_inap_RequestedInformationList,
    &ett_inap_RequestedInformationTypeList,
    &ett_inap_RequestedInformation,
    &ett_inap_RequestedInformationValue,
    &ett_inap_ResourceID,
    &ett_inap_RouteList,
    &ett_inap_ServiceAddressInformation,
    &ett_inap_Tone,
    &ett_inap_VariablePart,
    &ett_inap_CancelFailed,

/*--- End of included file: packet-inap-ettarr.c ---*/
#line 471 "packet-inap-template.c"
  };

  /* Register protocol */
  proto_inap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("inap", dissect_inap, proto_inap);
  /* Register fields and subtrees */
  proto_register_field_array(proto_inap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  
  /* Set default SSNs */
  range_convert_str(&global_ssn_range, "106,241", MAX_SSN);
  ssn_range = range_empty();
  
  inap_module = prefs_register_protocol(proto_inap, proto_reg_handoff_inap);

  prefs_register_obsolete_preference(inap_module, "tcap.itu_ssn");
 
  prefs_register_obsolete_preference(inap_module, "tcap.itu_ssn1");

  prefs_register_range_preference(inap_module, "ssn", "TCAP SSNs",
				  "TCAP Subsystem numbers used for INAP",
				  &global_ssn_range, MAX_SSN);
}



