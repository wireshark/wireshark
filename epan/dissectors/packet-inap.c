/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* ./packet-inap.c                                                            */
/* ../../tools/asn2eth.py -X -b -e -p inap -c inap.cnf -s packet-inap-template inap.asn */

/* Input file: packet-inap-template.c */

/* packet-inap-template.c
 * Routines for INAP
 * Copyright 2004, Tim Endean <endeant@hotmail.com>
 * Built from the gsm-map dissector Copyright 2004, Anders Broman <anders.broman@ericsson.com>
 *
 * $Id$
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-inap.h"
#include "packet-q931.h"
#include "packet-e164.h"

#define PNAME  "INAP"
#define PSNAME "INAP"
#define PFNAME "inap"

/* Initialize the protocol and registered fields */
int proto_inap = -1;
static int hf_inap_invokeCmd = -1;             /* Opcode */
static int hf_inap_invokeid = -1;              /* INTEGER */
static int hf_inap_absent = -1;                /* NULL */
static int hf_inap_invokeId = -1;              /* InvokeId */
static int hf_inap_invoke = -1;                /* InvokePDU */
static int hf_inap_ReturnError = -1;                /* InvokePDU */
static int hf_inap_returnResult = -1;                /* InvokePDU */
static int hf_inap_returnResult_result = -1;
static int hf_inap_getPassword = -1;  
static int hf_inap_currentPassword = -1;  
static int hf_inap_genproblem = -1;

/*--- Included file: packet-inap-hf.c ---*/

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
static int hf_inap_sendingSideID = -1;            /* OCTET_STRING_SIZE_1 */
static int hf_inap_receivingSideID = -1;          /* OCTET_STRING_SIZE_1 */
static int hf_inap_heldLegID = -1;                /* LegID */
static int hf_inap_legToBeReleased = -1;          /* LegID */
static int hf_inap_releaseCause = -1;             /* Cause */
static int hf_inap_legStatus = -1;                /* LegStatus */
static int hf_inap_VariableParts_item = -1;       /* VariableParts_item */
static int hf_inap_integer = -1;                  /* INTEGER_0_2147483647 */
static int hf_inap_number = -1;                   /* OCTET_STRING */
static int hf_inap_time = -1;                     /* OCTET_STRING */
static int hf_inap_date = -1;                     /* OCTET_STRING */
static int hf_inap_price = -1;                    /* OCTET_STRING */
static int hf_inap_elementaryMessageID = -1;      /* INTEGER_0_2147483647 */
static int hf_inap_variableParts = -1;            /* VariableParts */
static int hf_inap_toneID = -1;                   /* INTEGER_0_2147483647 */
static int hf_inap_tduration = -1;                /* INTEGER_0_2147483647 */
static int hf_inap_messageContent = -1;           /* IA5String */
static int hf_inap_attributes = -1;               /* OCTET_STRING */
static int hf_inap_text = -1;                     /* Text */
static int hf_inap_elementaryMessageIDs = -1;     /* T_elementaryMessageIDs */
static int hf_inap_elementaryMessageIDs_item = -1;  /* INTEGER_0_2147483647 */
static int hf_inap_variableMessage = -1;          /* VariableMessage */
static int hf_inap_inbandInfo = -1;               /* T_inbandInfo */
static int hf_inap_messageID = -1;                /* MessageID */
static int hf_inap_numberOfRepetitions = -1;      /* INTEGER_1_127 */
static int hf_inap_mduration = -1;                /* INTEGER_0_32767 */
static int hf_inap_interval = -1;                 /* INTEGER_0_32767 */
static int hf_inap_tone = -1;                     /* Tone */
static int hf_inap_displayInformation = -1;       /* IA5String */
static int hf_inap_dialledNumber = -1;            /* OCTET_STRING */
static int hf_inap_callingLineID = -1;            /* OCTET_STRING */
static int hf_inap_serviceKey = -1;               /* INTEGER_0_2147483647 */
static int hf_inap_addressAndService = -1;        /* T_addressAndService */
static int hf_inap_calledAddressValue = -1;       /* OCTET_STRING */
static int hf_inap_callingAddressValue = -1;      /* OCTET_STRING */
static int hf_inap_locationNumber = -1;           /* OCTET_STRING */
static int hf_inap_Extensions_item = -1;          /* Extensions_item */
static int hf_inap_type = -1;                     /* INTEGER */
static int hf_inap_criticality = -1;              /* T_criticality */
static int hf_inap_value = -1;                    /* OCTET_STRING */
static int hf_inap_filteredCallTreatment = -1;    /* T_filteredCallTreatment */
static int hf_inap_sFBillingChargingCharacteristics = -1;  /* OCTET_STRING */
static int hf_inap_informationToSend = -1;        /* InformationToSend */
static int hf_inap_maximumNumberOfCounters = -1;  /* INTEGER */
static int hf_inap_filteringCharacteristics = -1;  /* T_filteringCharacteristics */
static int hf_inap_numberOfCalls = -1;            /* INTEGER_0_2147483647 */
static int hf_inap_filteringTimeOut = -1;         /* T_filteringTimeOut */
static int hf_inap_aduration = -1;                /* INTEGER_M2_86400 */
static int hf_inap_stopTime = -1;                 /* OCTET_STRING_SIZE_6 */
static int hf_inap_filteringCriteria = -1;        /* FilteringCriteria */
static int hf_inap_startTime = -1;                /* OCTET_STRING_SIZE_6 */
static int hf_inap_extensions = -1;               /* Extensions */
static int hf_inap_messageType = -1;              /* T_messageType */
static int hf_inap_dpAssignment = -1;             /* T_dpAssignment */
static int hf_inap_miscCallInfo = -1;             /* MiscCallInfo */
static int hf_inap_triggerType = -1;              /* TriggerType */
static int hf_inap_RouteList_item = -1;           /* OCTET_STRING */
static int hf_inap_bearerCap = -1;                /* OCTET_STRING */
static int hf_inap_tmr = -1;                      /* OCTET_STRING_SIZE_1 */
static int hf_inap_serviceAddressInformation = -1;  /* ServiceAddressInformation */
static int hf_inap_bearerCapability = -1;         /* BearerCapability */
static int hf_inap_calledPartyNumber = -1;        /* OCTET_STRING */
static int hf_inap_callingPartyNumber = -1;       /* OCTET_STRING */
static int hf_inap_callingPartysCategory = -1;    /* OCTET_STRING_SIZE_1 */
static int hf_inap_iPSSPCapabilities = -1;        /* OCTET_STRING */
static int hf_inap_iPAvailable = -1;              /* OCTET_STRING */
static int hf_inap_iSDNAccessRelatedInformation = -1;  /* OCTET_STRING */
static int hf_inap_cGEncountered = -1;            /* CGEncountered */
static int hf_inap_serviceProfileIdentifier = -1;  /* OCTET_STRING */
static int hf_inap_terminalType = -1;             /* TerminalType */
static int hf_inap_chargeNumber = -1;             /* OCTET_STRING */
static int hf_inap_servingAreaID = -1;            /* OCTET_STRING */
static int hf_inap_trunkGroupID = -1;             /* INTEGER */
static int hf_inap_privateFacilityID = -1;        /* INTEGER */
static int hf_inap_huntGroup = -1;                /* OCTET_STRING */
static int hf_inap_routeIndex = -1;               /* OCTET_STRING */
static int hf_inap_dpSpecificCommonParameters = -1;  /* DpSpecificCommonParameters */
static int hf_inap_dialledDigits = -1;            /* OCTET_STRING */
static int hf_inap_callingPartyBusinessGroupID = -1;  /* OCTET_STRING */
static int hf_inap_callingPartySubaddress = -1;   /* OCTET_STRING */
static int hf_inap_callingFacilityGroup = -1;     /* CallingFacilityGroup */
static int hf_inap_callingFacilityGroupMember = -1;  /* INTEGER */
static int hf_inap_originalCalledPartyID = -1;    /* OCTET_STRING */
static int hf_inap_prefix = -1;                   /* OCTET_STRING */
static int hf_inap_redirectingPartyID = -1;       /* OCTET_STRING */
static int hf_inap_redirectionInformation = -1;   /* OCTET_STRING_SIZE_2 */
static int hf_inap_routeList = -1;                /* RouteList */
static int hf_inap_travellingClassMark = -1;      /* OCTET_STRING */
static int hf_inap_featureCode = -1;              /* OCTET_STRING */
static int hf_inap_accessCode = -1;               /* OCTET_STRING */
static int hf_inap_carrier = -1;                  /* OCTET_STRING */
static int hf_inap_destinationRoutingAddress = -1;  /* SEQUENCE_SIZE_1_3_OF_DestinationAddress */
static int hf_inap_destinationRoutingAddress_item = -1;  /* DestinationAddress */
static int hf_inap_alertingPattern = -1;          /* OCTET_STRING_SIZE_3 */
static int hf_inap_aChBillingChargingCharacteristics = -1;  /* OCTET_STRING */
static int hf_inap_partyToCharge = -1;            /* PartyToCharge */
static int hf_inap_correlationID = -1;            /* OCTET_STRING */
static int hf_inap_gapCriteria = -1;              /* T_gapCriteria */
static int hf_inap_gapOnService = -1;             /* T_gapOnService */
static int hf_inap_dpCriteria = -1;               /* T_dpCriteria */
static int hf_inap_calledAddressAndService = -1;  /* T_calledAddressAndService */
static int hf_inap_callingAddressAndService = -1;  /* T_callingAddressAndService */
static int hf_inap_gapIndicators = -1;            /* T_gapIndicators */
static int hf_inap_cgduration = -1;               /* INTEGER_M2_86400 */
static int hf_inap_gapInterval = -1;              /* INTEGER_M1_60000 */
static int hf_inap_controlType = -1;              /* T_controlType */
static int hf_inap_gapTreatment = -1;             /* T_gapTreatment */
static int hf_inap_both = -1;                     /* Both */
static int hf_inap_requestedInformationList = -1;  /* T_requestedInformationList */
static int hf_inap_requestedInformationList_item = -1;  /* T_requestedInformationList_item */
static int hf_inap_requestedInformationType = -1;  /* T_requestedInformationType */
static int hf_inap_requestedInformationValue = -1;  /* T_requestedInformationValue */
static int hf_inap_callAttemptElapsedTimeValue = -1;  /* INTEGER_0_255 */
static int hf_inap_callStopTimeValue = -1;        /* OCTET_STRING_SIZE_6 */
static int hf_inap_callConnectedElapsedTimeValue = -1;  /* INTEGER_0_2147483647 */
static int hf_inap_releaseCauseValue = -1;        /* Cause */
static int hf_inap_requestedInformationTypeList = -1;  /* T_requestedInformationTypeList */
static int hf_inap_requestedInformationTypeList_item = -1;  /* T_requestedInformationTypeList_item */
static int hf_inap_invokeID = -1;                 /* INTEGER_M128_127 */
static int hf_inap_allRequests = -1;              /* NULL */
static int hf_inap_lineID = -1;                   /* OCTET_STRING */
static int hf_inap_facilityGroupID = -1;          /* FacilityGroupID */
static int hf_inap_facilityGroupMemberID = -1;    /* INTEGER */
static int hf_inap_resourceID = -1;               /* ResourceID */
static int hf_inap_numberingPlan = -1;            /* OCTET_STRING_SIZE_1 */
static int hf_inap_cutAndPaste = -1;              /* INTEGER_0_22 */
static int hf_inap_forwardingCondition = -1;      /* T_forwardingCondition */
static int hf_inap_scfID = -1;                    /* OCTET_STRING */
static int hf_inap_serviceInteractionIndicators = -1;  /* OCTET_STRING */
static int hf_inap_resourceAddress = -1;          /* T_resourceAddress */
static int hf_inap_ipRoutingAddress = -1;         /* OCTET_STRING */
static int hf_inap_none = -1;                     /* NULL */
static int hf_inap_assistingSSPIPRoutingAddress = -1;  /* OCTET_STRING */
static int hf_inap_eventTypeCharging = -1;        /* OCTET_STRING */
static int hf_inap_eventSpecificInformationCharging = -1;  /* OCTET_STRING */
static int hf_inap_monitorMode = -1;              /* MonitorMode */
static int hf_inap_eventTypeBCSM = -1;            /* EventTypeBCSM */
static int hf_inap_bcsmEventCorrelationID = -1;   /* OCTET_STRING */
static int hf_inap_eventSpecificInformationBCSM = -1;  /* T_eventSpecificInformationBCSM */
static int hf_inap_collectedInfoSpecificInfo = -1;  /* T_collectedInfoSpecificInfo */
static int hf_inap_calledPartynumber = -1;        /* OCTET_STRING */
static int hf_inap_analyzedInfoSpecificInfo = -1;  /* T_analyzedInfoSpecificInfo */
static int hf_inap_routeSelectFailureSpecificInfo = -1;  /* T_routeSelectFailureSpecificInfo */
static int hf_inap_failureCause = -1;             /* OCTET_STRING_SIZE_2_10 */
static int hf_inap_oCalledPartyBusySpecificInfo = -1;  /* T_oCalledPartyBusySpecificInfo */
static int hf_inap_busyCause = -1;                /* OCTET_STRING_SIZE_2_10 */
static int hf_inap_oNoAnswerSpecificInfo = -1;    /* T_oNoAnswerSpecificInfo */
static int hf_inap_oAnswerSpecificInfo = -1;      /* T_oAnswerSpecificInfo */
static int hf_inap_oMidCallSpecificInfo = -1;     /* T_oMidCallSpecificInfo */
static int hf_inap_connectTime = -1;              /* INTEGER_0_2147483647 */
static int hf_inap_oDisconnectSpecificInfo = -1;  /* T_oDisconnectSpecificInfo */
static int hf_inap_tBusySpecificInfo = -1;        /* T_tBusySpecificInfo */
static int hf_inap_tNoAnswerSpecificInfo = -1;    /* T_tNoAnswerSpecificInfo */
static int hf_inap_tAnswerSpecificInfo = -1;      /* T_tAnswerSpecificInfo */
static int hf_inap_tMidCallSpecificInfo = -1;     /* T_tMidCallSpecificInfo */
static int hf_inap_tDisconnectSpecificInfo = -1;  /* T_tDisconnectSpecificInfo */
static int hf_inap_holdcause = -1;                /* OCTET_STRING */
static int hf_inap_empty = -1;                    /* NULL */
static int hf_inap_highLayerCompatibility = -1;   /* OCTET_STRING_SIZE_2 */
static int hf_inap_additionalCallingPartyNumber = -1;  /* OCTET_STRING */
static int hf_inap_forwardCallIndicators = -1;    /* OCTET_STRING_SIZE_2 */
static int hf_inap_calledPartyBusinessGroupID = -1;  /* OCTET_STRING */
static int hf_inap_calledPartySubaddress = -1;    /* OCTET_STRING */
static int hf_inap_featureRequestIndicator = -1;  /* FeatureRequestIndicator */
static int hf_inap_disconnectFromIPForbidden = -1;  /* BOOLEAN */
static int hf_inap_requestAnnouncementComplete = -1;  /* BOOLEAN */
static int hf_inap_collectedInfo = -1;            /* T_collectedInfo */
static int hf_inap_collectedDigits = -1;          /* T_collectedDigits */
static int hf_inap_minimumNbOfDigits = -1;        /* INTEGER_1_127 */
static int hf_inap_maximumNbOfDigits = -1;        /* INTEGER_1_127 */
static int hf_inap_endOfReplyDigit = -1;          /* OCTET_STRING_SIZE_1_2 */
static int hf_inap_cancelDigit = -1;              /* OCTET_STRING_SIZE_1_2 */
static int hf_inap_startDigit = -1;               /* OCTET_STRING_SIZE_1_2 */
static int hf_inap_firstDigitTimeOut = -1;        /* INTEGER_1_127 */
static int hf_inap_interDigitTimeOut = -1;        /* INTEGER_1_127 */
static int hf_inap_errorTreatment = -1;           /* T_errorTreatment */
static int hf_inap_interruptableAnnInd = -1;      /* BOOLEAN */
static int hf_inap_voiceInformation = -1;         /* BOOLEAN */
static int hf_inap_voiceBack = -1;                /* BOOLEAN */
static int hf_inap_iA5Information = -1;           /* BOOLEAN */
static int hf_inap_digitsResponse = -1;           /* OCTET_STRING */
static int hf_inap_iA5Response = -1;              /* IA5String */
static int hf_inap_initialCallSegment = -1;       /* Cause */
static int hf_inap_allCallSegments = -1;          /* T_allCallSegments */
static int hf_inap_resourceStatus = -1;           /* ResourceStatus */
static int hf_inap_monitorDuration = -1;          /* INTEGER_M2_86400 */
static int hf_inap_RequestNotificationChargingEvent_item = -1;  /* RequestNotificationChargingEvent_item */
static int hf_inap_bcsmEvents = -1;               /* T_bcsmEvents */
static int hf_inap_bcsmEvents_item = -1;          /* T_bcsmEvents_item */
static int hf_inap_dpSpecificCriteria = -1;       /* T_dpSpecificCriteria */
static int hf_inap_numberOfDigits = -1;           /* INTEGER_1_255 */
static int hf_inap_applicationTimer = -1;         /* INTEGER_0_2047 */
static int hf_inap_timerID = -1;                  /* T_timerID */
static int hf_inap_timervalue = -1;               /* INTEGER_0_2147483647 */
static int hf_inap_destinationNumberRoutingAddress = -1;  /* OCTET_STRING */
static int hf_inap_calledFacilityGroup = -1;      /* CalledFacilityGroup */
static int hf_inap_calledFacilityGroupMember = -1;  /* INTEGER */
static int hf_inap_sCIBillingChargingCharacteristics = -1;  /* OCTET_STRING */
static int hf_inap_countersValue = -1;            /* T_countersValue */
static int hf_inap_countersValue_item = -1;       /* T_countersValue_item */
static int hf_inap_counterID = -1;                /* INTEGER_0_99 */
static int hf_inap_counterValue = -1;             /* INTEGER_0_2147483647 */
static int hf_inap_responseCondition = -1;        /* T_responseCondition */
static int hf_inap_reportCondition = -1;          /* T_reportCondition */
static int hf_inap_problem = -1;                  /* T_problem */
static int hf_inap_operation = -1;                /* INTEGER_M128_127 */
static int hf_inap_rinvokeID = -1;                /* T_rinvokeID */
static int hf_inap_invidtype = -1;                /* InvokeIDType */
static int hf_inap_null = -1;                     /* NULL */
static int hf_inap_rproblem = -1;                 /* T_rproblem */
static int hf_inap_gp = -1;                       /* GeneralProblem */
static int hf_inap_ip = -1;                       /* InvokeProblem */
static int hf_inap_rrp = -1;                      /* ReturnResultProblem */
static int hf_inap_rep = -1;                      /* ReturnErrorProblem */

/*--- End of included file: packet-inap-hf.c ---*/


static guint tcap_itu_ssn = 106;
static guint tcap_itu_ssn1 = 241;


static guint global_tcap_itu_ssn = 1;
static guint global_tcap_itu_ssn1 = 1;

/* Initialize the subtree pointers */
static gint ett_inap = -1;
static gint ett_inap_InvokeId = -1;
static gint ett_inap_InvokePDU = -1;
static gint ett_inap_ReturnErrorPDU = -1;
static gint ett_inap_ReturnResultPDU = -1;
static gint ett_inap_ReturnResult_result = -1;
static gint ett_inap_INAPPDU = -1;
static gint ett_inapisup_parameter = -1;

/*--- Included file: packet-inap-ett.c ---*/

static gint ett_inap_AddPartyArg = -1;
static gint ett_inap_AttachArg = -1;
static gint ett_inap_CallPartyHandlingResultsArg = -1;
static gint ett_inap_ChangePartiesArg = -1;
static gint ett_inap_DetachArg = -1;
static gint ett_inap_HoldCallPartyConnectionArg = -1;
static gint ett_inap_LegID = -1;
static gint ett_inap_ReconnectArg = -1;
static gint ett_inap_ReleaseCallPartyConnectionArg = -1;
static gint ett_inap_LegInformation = -1;
static gint ett_inap_VariableParts = -1;
static gint ett_inap_VariableParts_item = -1;
static gint ett_inap_VariableMessage = -1;
static gint ett_inap_Tone = -1;
static gint ett_inap_Text = -1;
static gint ett_inap_MessageID = -1;
static gint ett_inap_T_elementaryMessageIDs = -1;
static gint ett_inap_InformationToSend = -1;
static gint ett_inap_T_inbandInfo = -1;
static gint ett_inap_FilteringCriteria = -1;
static gint ett_inap_T_addressAndService = -1;
static gint ett_inap_Extensions = -1;
static gint ett_inap_Extensions_item = -1;
static gint ett_inap_ActivateServiceFilteringarg = -1;
static gint ett_inap_T_filteredCallTreatment = -1;
static gint ett_inap_T_filteringCharacteristics = -1;
static gint ett_inap_T_filteringTimeOut = -1;
static gint ett_inap_MiscCallInfo = -1;
static gint ett_inap_ServiceAddressInformation = -1;
static gint ett_inap_RouteList = -1;
static gint ett_inap_BearerCapability = -1;
static gint ett_inap_DpSpecificCommonParameters = -1;
static gint ett_inap_CallingFacilityGroup = -1;
static gint ett_inap_AnalysedInformationarg = -1;
static gint ett_inap_AnalyseInformationarg = -1;
static gint ett_inap_SEQUENCE_SIZE_1_3_OF_DestinationAddress = -1;
static gint ett_inap_PartyToCharge = -1;
static gint ett_inap_ApplyChargingarg = -1;
static gint ett_inap_AssistRequestInstructionsarg = -1;
static gint ett_inap_CallGaparg = -1;
static gint ett_inap_T_gapCriteria = -1;
static gint ett_inap_T_gapOnService = -1;
static gint ett_inap_T_calledAddressAndService = -1;
static gint ett_inap_T_callingAddressAndService = -1;
static gint ett_inap_T_gapIndicators = -1;
static gint ett_inap_T_gapTreatment = -1;
static gint ett_inap_Both = -1;
static gint ett_inap_CallInformationReportarg = -1;
static gint ett_inap_T_requestedInformationList = -1;
static gint ett_inap_T_requestedInformationList_item = -1;
static gint ett_inap_T_requestedInformationValue = -1;
static gint ett_inap_CallInformationRequestarg = -1;
static gint ett_inap_T_requestedInformationTypeList = -1;
static gint ett_inap_Cancelarg = -1;
static gint ett_inap_FacilityGroupID = -1;
static gint ett_inap_ResourceID = -1;
static gint ett_inap_CancelStatusReportRequestarg = -1;
static gint ett_inap_CollectedInformationarg = -1;
static gint ett_inap_CollectInformationarg = -1;
static gint ett_inap_Connectarg = -1;
static gint ett_inap_ConnectToResource = -1;
static gint ett_inap_T_resourceAddress = -1;
static gint ett_inap_EstablishTemporaryConnection = -1;
static gint ett_inap_EventNotificationChargingarg = -1;
static gint ett_inap_EventReportBCSM = -1;
static gint ett_inap_T_eventSpecificInformationBCSM = -1;
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
static gint ett_inap_HoldCallInNetworkarg = -1;
static gint ett_inap_InitialDP = -1;
static gint ett_inap_InitiateCallAttempt = -1;
static gint ett_inap_OAnswer = -1;
static gint ett_inap_OCalledPartyBusy = -1;
static gint ett_inap_ODisconnect = -1;
static gint ett_inap_OMidCall = -1;
static gint ett_inap_ONoAnswer = -1;
static gint ett_inap_OriginationAttemptAuthorized = -1;
static gint ett_inap_PlayAnnouncement = -1;
static gint ett_inap_PromptAndCollectUserInformationarg = -1;
static gint ett_inap_T_collectedInfo = -1;
static gint ett_inap_T_collectedDigits = -1;
static gint ett_inap_PromptAndCollectUserInformationres = -1;
static gint ett_inap_ReleaseCallArg = -1;
static gint ett_inap_T_allCallSegments = -1;
static gint ett_inap_RequestCurrentStatusReportarg = -1;
static gint ett_inap_RequestCurrentStatusReportres = -1;
static gint ett_inap_RequestEveryStatusChangeReport = -1;
static gint ett_inap_RequestFirstStatusMatchReport = -1;
static gint ett_inap_RequestNotificationChargingEvent = -1;
static gint ett_inap_RequestNotificationChargingEvent_item = -1;
static gint ett_inap_RequestReportBCSMEvent = -1;
static gint ett_inap_T_bcsmEvents = -1;
static gint ett_inap_T_bcsmEvents_item = -1;
static gint ett_inap_T_dpSpecificCriteria = -1;
static gint ett_inap_ResetTimer = -1;
static gint ett_inap_RouteSelectFailure = -1;
static gint ett_inap_CalledFacilityGroup = -1;
static gint ett_inap_SelectFacility = -1;
static gint ett_inap_SelectRoute = -1;
static gint ett_inap_SendChargingInformation = -1;
static gint ett_inap_ServiceFilteringResponse = -1;
static gint ett_inap_T_countersValue = -1;
static gint ett_inap_T_countersValue_item = -1;
static gint ett_inap_StatusReport = -1;
static gint ett_inap_TAnswer = -1;
static gint ett_inap_TBusy = -1;
static gint ett_inap_TDisconnect = -1;
static gint ett_inap_TermAttemptAuthorized = -1;
static gint ett_inap_TMidCall = -1;
static gint ett_inap_TNoAnswer = -1;
static gint ett_inap_CancelFailed = -1;
static gint ett_inap_RejectPDU = -1;
static gint ett_inap_T_rinvokeID = -1;
static gint ett_inap_T_rproblem = -1;

/*--- End of included file: packet-inap-ett.c ---*/


static int  dissect_invokeCmd(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);


/*--- Included file: packet-inap-fn.c ---*/

/*--- Fields for imported types ---*/




static int
dissect_inap_CallID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_originalCallID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_CallID(TRUE, tvb, offset, pinfo, tree, hf_inap_originalCallID);
}
static int dissect_destinationCallID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_CallID(TRUE, tvb, offset, pinfo, tree, hf_inap_destinationCallID);
}
static int dissect_callID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_CallID(TRUE, tvb, offset, pinfo, tree, hf_inap_callID);
}
static int dissect_targetCallID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_CallID(TRUE, tvb, offset, pinfo, tree, hf_inap_targetCallID);
}


static const ber_sequence_t AddPartyArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_originalCallID_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_destinationCallID_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_AddPartyArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AddPartyArg_sequence, hf_index, ett_inap_AddPartyArg);

  return offset;
}



static int
dissect_inap_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_newLegID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_newLegID);
}
static int dissect_correlationidentifier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_correlationidentifier);
}
static int dissect_legToBeConnectedID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_legToBeConnectedID);
}
static int dissect_legToBeDetached_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_legToBeDetached);
}
static int dissect_number_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_number);
}
static int dissect_time_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_time);
}
static int dissect_date_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_date);
}
static int dissect_price_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_price);
}
static int dissect_attributes_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_attributes);
}
static int dissect_dialledNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_dialledNumber);
}
static int dissect_callingLineID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_callingLineID);
}
static int dissect_calledAddressValue_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_calledAddressValue);
}
static int dissect_callingAddressValue_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_callingAddressValue);
}
static int dissect_locationNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_locationNumber);
}
static int dissect_value_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_value);
}
static int dissect_sFBillingChargingCharacteristics_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_sFBillingChargingCharacteristics);
}
static int dissect_RouteList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_inap_RouteList_item);
}
static int dissect_bearerCap_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_bearerCap);
}
static int dissect_calledPartyNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_calledPartyNumber);
}
static int dissect_callingPartyNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_callingPartyNumber);
}
static int dissect_iPSSPCapabilities_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_iPSSPCapabilities);
}
static int dissect_iPAvailable_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_iPAvailable);
}
static int dissect_iSDNAccessRelatedInformation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_iSDNAccessRelatedInformation);
}
static int dissect_serviceProfileIdentifier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_serviceProfileIdentifier);
}
static int dissect_chargeNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_chargeNumber);
}
static int dissect_servingAreaID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_servingAreaID);
}
static int dissect_huntGroup_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_huntGroup);
}
static int dissect_routeIndex_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_routeIndex);
}
static int dissect_dialledDigits_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_dialledDigits);
}
static int dissect_callingPartyBusinessGroupID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_callingPartyBusinessGroupID);
}
static int dissect_callingPartySubaddress_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_callingPartySubaddress);
}
static int dissect_originalCalledPartyID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_originalCalledPartyID);
}
static int dissect_prefix_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_prefix);
}
static int dissect_redirectingPartyID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_redirectingPartyID);
}
static int dissect_travellingClassMark_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_travellingClassMark);
}
static int dissect_featureCode_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_featureCode);
}
static int dissect_accessCode_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_accessCode);
}
static int dissect_carrier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_carrier);
}
static int dissect_aChBillingChargingCharacteristics_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_aChBillingChargingCharacteristics);
}
static int dissect_correlationID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_correlationID);
}
static int dissect_lineID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_lineID);
}
static int dissect_scfID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_scfID);
}
static int dissect_serviceInteractionIndicators_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_serviceInteractionIndicators);
}
static int dissect_ipRoutingAddress_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_ipRoutingAddress);
}
static int dissect_assistingSSPIPRoutingAddress_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_assistingSSPIPRoutingAddress);
}
static int dissect_eventTypeCharging_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_eventTypeCharging);
}
static int dissect_eventSpecificInformationCharging_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_eventSpecificInformationCharging);
}
static int dissect_bcsmEventCorrelationID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_bcsmEventCorrelationID);
}
static int dissect_calledPartynumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_calledPartynumber);
}
static int dissect_holdcause_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_holdcause);
}
static int dissect_additionalCallingPartyNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_additionalCallingPartyNumber);
}
static int dissect_calledPartyBusinessGroupID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_calledPartyBusinessGroupID);
}
static int dissect_calledPartySubaddress_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_calledPartySubaddress);
}
static int dissect_digitsResponse_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_digitsResponse);
}
static int dissect_destinationNumberRoutingAddress_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_destinationNumberRoutingAddress);
}
static int dissect_sCIBillingChargingCharacteristics_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_inap_sCIBillingChargingCharacteristics);
}


static const ber_sequence_t AttachArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_newLegID_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_correlationidentifier_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_AttachArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AttachArg_sequence, hf_index, ett_inap_AttachArg);

  return offset;
}



static int
dissect_inap_OCTET_STRING_SIZE_1(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_sendingSideID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING_SIZE_1(TRUE, tvb, offset, pinfo, tree, hf_inap_sendingSideID);
}
static int dissect_receivingSideID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING_SIZE_1(TRUE, tvb, offset, pinfo, tree, hf_inap_receivingSideID);
}
static int dissect_tmr_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING_SIZE_1(TRUE, tvb, offset, pinfo, tree, hf_inap_tmr);
}
static int dissect_callingPartysCategory_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING_SIZE_1(TRUE, tvb, offset, pinfo, tree, hf_inap_callingPartysCategory);
}
static int dissect_numberingPlan_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING_SIZE_1(TRUE, tvb, offset, pinfo, tree, hf_inap_numberingPlan);
}


static const value_string inap_LegID_vals[] = {
  {   0, "sendingSideID" },
  {   1, "receivingSideID" },
  { 0, NULL }
};

static const ber_choice_t LegID_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sendingSideID_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_receivingSideID_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_LegID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 LegID_choice, hf_index, ett_inap_LegID,
                                 NULL);

  return offset;
}
static int dissect_legID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_LegID(TRUE, tvb, offset, pinfo, tree, hf_inap_legID);
}
static int dissect_heldLegID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_LegID(TRUE, tvb, offset, pinfo, tree, hf_inap_heldLegID);
}
static int dissect_legToBeReleased_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_LegID(TRUE, tvb, offset, pinfo, tree, hf_inap_legToBeReleased);
}


static const value_string inap_LegStatus_vals[] = {
  {   0, "connected" },
  {   1, "unconnected" },
  {   2, "pending" },
  {   3, "interacting" },
  { 0, NULL }
};


static int
dissect_inap_LegStatus(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_legStatus_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_LegStatus(TRUE, tvb, offset, pinfo, tree, hf_inap_legStatus);
}


static const ber_sequence_t LegInformation_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_legID_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_legStatus_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_LegInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   LegInformation_sequence, hf_index, ett_inap_LegInformation);

  return offset;
}
static int dissect_CallPartyHandlingResultsArg_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_LegInformation(FALSE, tvb, offset, pinfo, tree, hf_inap_CallPartyHandlingResultsArg_item);
}


static const ber_sequence_t CallPartyHandlingResultsArg_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_CallPartyHandlingResultsArg_item },
};

static int
dissect_inap_CallPartyHandlingResultsArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      CallPartyHandlingResultsArg_sequence_of, hf_index, ett_inap_CallPartyHandlingResultsArg);

  return offset;
}


static const ber_sequence_t ChangePartiesArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callID_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_targetCallID_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_legToBeConnectedID_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_ChangePartiesArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ChangePartiesArg_sequence, hf_index, ett_inap_ChangePartiesArg);

  return offset;
}


static const ber_sequence_t DetachArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_legToBeDetached_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_correlationidentifier_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_DetachArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DetachArg_sequence, hf_index, ett_inap_DetachArg);

  return offset;
}


static const ber_sequence_t HoldCallPartyConnectionArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callID_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_legID_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_HoldCallPartyConnectionArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   HoldCallPartyConnectionArg_sequence, hf_index, ett_inap_HoldCallPartyConnectionArg);

  return offset;
}


static const ber_sequence_t ReconnectArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callID_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_heldLegID_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_ReconnectArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ReconnectArg_sequence, hf_index, ett_inap_ReconnectArg);

  return offset;
}



static int
dissect_inap_Cause(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_releaseCause_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_Cause(TRUE, tvb, offset, pinfo, tree, hf_inap_releaseCause);
}
static int dissect_releaseCauseValue_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_Cause(TRUE, tvb, offset, pinfo, tree, hf_inap_releaseCauseValue);
}
static int dissect_initialCallSegment(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_Cause(FALSE, tvb, offset, pinfo, tree, hf_inap_initialCallSegment);
}


static const ber_sequence_t ReleaseCallPartyConnectionArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_legToBeReleased_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callID_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_releaseCause_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_ReleaseCallPartyConnectionArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ReleaseCallPartyConnectionArg_sequence, hf_index, ett_inap_ReleaseCallPartyConnectionArg);

  return offset;
}



static int
dissect_inap_INTEGER_0_2147483647(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_integer_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_INTEGER_0_2147483647(TRUE, tvb, offset, pinfo, tree, hf_inap_integer);
}
static int dissect_elementaryMessageID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_INTEGER_0_2147483647(TRUE, tvb, offset, pinfo, tree, hf_inap_elementaryMessageID);
}
static int dissect_toneID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_INTEGER_0_2147483647(TRUE, tvb, offset, pinfo, tree, hf_inap_toneID);
}
static int dissect_tduration_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_INTEGER_0_2147483647(TRUE, tvb, offset, pinfo, tree, hf_inap_tduration);
}
static int dissect_elementaryMessageIDs_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_INTEGER_0_2147483647(FALSE, tvb, offset, pinfo, tree, hf_inap_elementaryMessageIDs_item);
}
static int dissect_serviceKey_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_INTEGER_0_2147483647(TRUE, tvb, offset, pinfo, tree, hf_inap_serviceKey);
}
static int dissect_numberOfCalls_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_INTEGER_0_2147483647(TRUE, tvb, offset, pinfo, tree, hf_inap_numberOfCalls);
}
static int dissect_callConnectedElapsedTimeValue_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_INTEGER_0_2147483647(TRUE, tvb, offset, pinfo, tree, hf_inap_callConnectedElapsedTimeValue);
}
static int dissect_connectTime_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_INTEGER_0_2147483647(TRUE, tvb, offset, pinfo, tree, hf_inap_connectTime);
}
static int dissect_timervalue_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_INTEGER_0_2147483647(TRUE, tvb, offset, pinfo, tree, hf_inap_timervalue);
}
static int dissect_counterValue_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_INTEGER_0_2147483647(TRUE, tvb, offset, pinfo, tree, hf_inap_counterValue);
}


static const value_string inap_VariableParts_item_vals[] = {
  {   0, "integer" },
  {   1, "number" },
  {   2, "time" },
  {   3, "date" },
  {   4, "price" },
  { 0, NULL }
};

static const ber_choice_t VariableParts_item_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_integer_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_number_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_time_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_date_impl },
  {   4, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_price_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_VariableParts_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 VariableParts_item_choice, hf_index, ett_inap_VariableParts_item,
                                 NULL);

  return offset;
}
static int dissect_VariableParts_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_VariableParts_item(FALSE, tvb, offset, pinfo, tree, hf_inap_VariableParts_item);
}


static const ber_sequence_t VariableParts_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_VariableParts_item },
};

static int
dissect_inap_VariableParts(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      VariableParts_sequence_of, hf_index, ett_inap_VariableParts);

  return offset;
}
static int dissect_variableParts_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_VariableParts(TRUE, tvb, offset, pinfo, tree, hf_inap_variableParts);
}


static const ber_sequence_t VariableMessage_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_elementaryMessageID_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_variableParts_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_VariableMessage(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   VariableMessage_sequence, hf_index, ett_inap_VariableMessage);

  return offset;
}
static int dissect_variableMessage_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_VariableMessage(TRUE, tvb, offset, pinfo, tree, hf_inap_variableMessage);
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
dissect_inap_TriggerType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_triggerType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_TriggerType(TRUE, tvb, offset, pinfo, tree, hf_inap_triggerType);
}


static const ber_sequence_t Tone_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_toneID_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tduration_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_Tone(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Tone_sequence, hf_index, ett_inap_Tone);

  return offset;
}
static int dissect_tone_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_Tone(TRUE, tvb, offset, pinfo, tree, hf_inap_tone);
}



static int
dissect_inap_IA5String(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_messageContent_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_IA5String(TRUE, tvb, offset, pinfo, tree, hf_inap_messageContent);
}
static int dissect_displayInformation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_IA5String(TRUE, tvb, offset, pinfo, tree, hf_inap_displayInformation);
}
static int dissect_iA5Response_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_IA5String(TRUE, tvb, offset, pinfo, tree, hf_inap_iA5Response);
}


static const ber_sequence_t Text_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_messageContent_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_attributes_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_Text(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Text_sequence, hf_index, ett_inap_Text);

  return offset;
}
static int dissect_text_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_Text(TRUE, tvb, offset, pinfo, tree, hf_inap_text);
}


static const ber_sequence_t T_elementaryMessageIDs_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_elementaryMessageIDs_item },
};

static int
dissect_inap_T_elementaryMessageIDs(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      T_elementaryMessageIDs_sequence_of, hf_index, ett_inap_T_elementaryMessageIDs);

  return offset;
}
static int dissect_elementaryMessageIDs_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_elementaryMessageIDs(TRUE, tvb, offset, pinfo, tree, hf_inap_elementaryMessageIDs);
}


static const value_string inap_MessageID_vals[] = {
  {   0, "elementaryMessageID" },
  {   1, "text" },
  {  29, "elementaryMessageIDs" },
  {  30, "variableMessage" },
  { 0, NULL }
};

static const ber_choice_t MessageID_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_elementaryMessageID_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_text_impl },
  {  29, BER_CLASS_CON, 29, BER_FLAGS_IMPLTAG, dissect_elementaryMessageIDs_impl },
  {  30, BER_CLASS_CON, 30, BER_FLAGS_IMPLTAG, dissect_variableMessage_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_MessageID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 MessageID_choice, hf_index, ett_inap_MessageID,
                                 NULL);

  return offset;
}
static int dissect_messageID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_MessageID(TRUE, tvb, offset, pinfo, tree, hf_inap_messageID);
}



static int
dissect_inap_INTEGER_1_127(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_numberOfRepetitions_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_INTEGER_1_127(TRUE, tvb, offset, pinfo, tree, hf_inap_numberOfRepetitions);
}
static int dissect_minimumNbOfDigits_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_INTEGER_1_127(TRUE, tvb, offset, pinfo, tree, hf_inap_minimumNbOfDigits);
}
static int dissect_maximumNbOfDigits_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_INTEGER_1_127(TRUE, tvb, offset, pinfo, tree, hf_inap_maximumNbOfDigits);
}
static int dissect_firstDigitTimeOut_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_INTEGER_1_127(TRUE, tvb, offset, pinfo, tree, hf_inap_firstDigitTimeOut);
}
static int dissect_interDigitTimeOut_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_INTEGER_1_127(TRUE, tvb, offset, pinfo, tree, hf_inap_interDigitTimeOut);
}



static int
dissect_inap_INTEGER_0_32767(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_mduration_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_INTEGER_0_32767(TRUE, tvb, offset, pinfo, tree, hf_inap_mduration);
}
static int dissect_interval_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_INTEGER_0_32767(TRUE, tvb, offset, pinfo, tree, hf_inap_interval);
}


static const ber_sequence_t T_inbandInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_messageID_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_numberOfRepetitions_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mduration_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_interval_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_inbandInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_inbandInfo_sequence, hf_index, ett_inap_T_inbandInfo);

  return offset;
}
static int dissect_inbandInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_inbandInfo(TRUE, tvb, offset, pinfo, tree, hf_inap_inbandInfo);
}


static const value_string inap_InformationToSend_vals[] = {
  {   0, "inbandInfo" },
  {   1, "tone" },
  {   2, "displayInformation" },
  { 0, NULL }
};

static const ber_choice_t InformationToSend_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_inbandInfo_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_tone_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_displayInformation_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_InformationToSend(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 InformationToSend_choice, hf_index, ett_inap_InformationToSend,
                                 NULL);

  return offset;
}
static int dissect_informationToSend_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_InformationToSend(TRUE, tvb, offset, pinfo, tree, hf_inap_informationToSend);
}


static const ber_sequence_t T_addressAndService_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_calledAddressValue_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_serviceKey_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callingAddressValue_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationNumber_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_addressAndService(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_addressAndService_sequence, hf_index, ett_inap_T_addressAndService);

  return offset;
}
static int dissect_addressAndService_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_addressAndService(TRUE, tvb, offset, pinfo, tree, hf_inap_addressAndService);
}


static const value_string inap_FilteringCriteria_vals[] = {
  {   0, "dialledNumber" },
  {   1, "callingLineID" },
  {   2, "serviceKey" },
  {  30, "addressAndService" },
  { 0, NULL }
};

static const ber_choice_t FilteringCriteria_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_dialledNumber_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_callingLineID_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_serviceKey_impl },
  {  30, BER_CLASS_CON, 30, BER_FLAGS_IMPLTAG, dissect_addressAndService_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_FilteringCriteria(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 FilteringCriteria_choice, hf_index, ett_inap_FilteringCriteria,
                                 NULL);

  return offset;
}
static int dissect_filteringCriteria_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_FilteringCriteria(TRUE, tvb, offset, pinfo, tree, hf_inap_filteringCriteria);
}



static int
dissect_inap_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_type(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_inap_type);
}
static int dissect_maximumNumberOfCounters_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_INTEGER(TRUE, tvb, offset, pinfo, tree, hf_inap_maximumNumberOfCounters);
}
static int dissect_trunkGroupID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_INTEGER(TRUE, tvb, offset, pinfo, tree, hf_inap_trunkGroupID);
}
static int dissect_privateFacilityID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_INTEGER(TRUE, tvb, offset, pinfo, tree, hf_inap_privateFacilityID);
}
static int dissect_callingFacilityGroupMember_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_INTEGER(TRUE, tvb, offset, pinfo, tree, hf_inap_callingFacilityGroupMember);
}
static int dissect_facilityGroupMemberID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_INTEGER(TRUE, tvb, offset, pinfo, tree, hf_inap_facilityGroupMemberID);
}
static int dissect_calledFacilityGroupMember_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_INTEGER(TRUE, tvb, offset, pinfo, tree, hf_inap_calledFacilityGroupMember);
}


static const value_string inap_T_criticality_vals[] = {
  {   0, "ignore" },
  {   1, "abort" },
  { 0, NULL }
};


static int
dissect_inap_T_criticality(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_criticality(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_criticality(FALSE, tvb, offset, pinfo, tree, hf_inap_criticality);
}


static const ber_sequence_t Extensions_item_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_type },
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_criticality },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_value_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_Extensions_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Extensions_item_sequence, hf_index, ett_inap_Extensions_item);

  return offset;
}
static int dissect_Extensions_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_Extensions_item(FALSE, tvb, offset, pinfo, tree, hf_inap_Extensions_item);
}


static const ber_sequence_t Extensions_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_Extensions_item },
};

static int
dissect_inap_Extensions(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      Extensions_sequence_of, hf_index, ett_inap_Extensions);

  return offset;
}
static int dissect_extensions_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_Extensions(TRUE, tvb, offset, pinfo, tree, hf_inap_extensions);
}


static const ber_sequence_t T_filteredCallTreatment_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sFBillingChargingCharacteristics_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_informationToSend_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_maximumNumberOfCounters_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_releaseCause_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_filteredCallTreatment(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_filteredCallTreatment_sequence, hf_index, ett_inap_T_filteredCallTreatment);

  return offset;
}
static int dissect_filteredCallTreatment_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_filteredCallTreatment(TRUE, tvb, offset, pinfo, tree, hf_inap_filteredCallTreatment);
}


static const value_string inap_T_filteringCharacteristics_vals[] = {
  {   0, "interval" },
  {   1, "numberOfCalls" },
  { 0, NULL }
};

static const ber_choice_t T_filteringCharacteristics_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_interval_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_numberOfCalls_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_T_filteringCharacteristics(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_filteringCharacteristics_choice, hf_index, ett_inap_T_filteringCharacteristics,
                                 NULL);

  return offset;
}
static int dissect_filteringCharacteristics_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_filteringCharacteristics(TRUE, tvb, offset, pinfo, tree, hf_inap_filteringCharacteristics);
}



static int
dissect_inap_INTEGER_M2_86400(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_aduration_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_INTEGER_M2_86400(TRUE, tvb, offset, pinfo, tree, hf_inap_aduration);
}
static int dissect_cgduration_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_INTEGER_M2_86400(TRUE, tvb, offset, pinfo, tree, hf_inap_cgduration);
}
static int dissect_monitorDuration_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_INTEGER_M2_86400(TRUE, tvb, offset, pinfo, tree, hf_inap_monitorDuration);
}



static int
dissect_inap_OCTET_STRING_SIZE_6(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_stopTime_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING_SIZE_6(TRUE, tvb, offset, pinfo, tree, hf_inap_stopTime);
}
static int dissect_startTime_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING_SIZE_6(TRUE, tvb, offset, pinfo, tree, hf_inap_startTime);
}
static int dissect_callStopTimeValue_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING_SIZE_6(TRUE, tvb, offset, pinfo, tree, hf_inap_callStopTimeValue);
}


static const value_string inap_T_filteringTimeOut_vals[] = {
  {   0, "aduration" },
  {   1, "stopTime" },
  { 0, NULL }
};

static const ber_choice_t T_filteringTimeOut_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_aduration_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_stopTime_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_T_filteringTimeOut(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_filteringTimeOut_choice, hf_index, ett_inap_T_filteringTimeOut,
                                 NULL);

  return offset;
}
static int dissect_filteringTimeOut_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_filteringTimeOut(TRUE, tvb, offset, pinfo, tree, hf_inap_filteringTimeOut);
}


static const ber_sequence_t ActivateServiceFilteringarg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_filteredCallTreatment_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_filteringCharacteristics_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_filteringTimeOut_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_filteringCriteria_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_startTime_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_ActivateServiceFilteringarg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ActivateServiceFilteringarg_sequence, hf_index, ett_inap_ActivateServiceFilteringarg);

  return offset;
}


static const value_string inap_T_messageType_vals[] = {
  {   0, "request" },
  {   1, "notification" },
  { 0, NULL }
};


static int
dissect_inap_T_messageType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_messageType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_messageType(TRUE, tvb, offset, pinfo, tree, hf_inap_messageType);
}


static const value_string inap_T_dpAssignment_vals[] = {
  {   0, "individualLine" },
  {   1, "groupBased" },
  {   2, "officeBased" },
  { 0, NULL }
};


static int
dissect_inap_T_dpAssignment(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_dpAssignment_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_dpAssignment(TRUE, tvb, offset, pinfo, tree, hf_inap_dpAssignment);
}


static const ber_sequence_t MiscCallInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_messageType_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dpAssignment_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_MiscCallInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   MiscCallInfo_sequence, hf_index, ett_inap_MiscCallInfo);

  return offset;
}
static int dissect_miscCallInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_MiscCallInfo(TRUE, tvb, offset, pinfo, tree, hf_inap_miscCallInfo);
}


static const ber_sequence_t ServiceAddressInformation_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_serviceKey_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_miscCallInfo_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_triggerType_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_ServiceAddressInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ServiceAddressInformation_sequence, hf_index, ett_inap_ServiceAddressInformation);

  return offset;
}
static int dissect_serviceAddressInformation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_ServiceAddressInformation(TRUE, tvb, offset, pinfo, tree, hf_inap_serviceAddressInformation);
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
dissect_inap_TerminalType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_terminalType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_TerminalType(TRUE, tvb, offset, pinfo, tree, hf_inap_terminalType);
}


static const ber_sequence_t RouteList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_RouteList_item },
};

static int
dissect_inap_RouteList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      RouteList_sequence_of, hf_index, ett_inap_RouteList);

  return offset;
}
static int dissect_routeList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_RouteList(TRUE, tvb, offset, pinfo, tree, hf_inap_routeList);
}


static const value_string inap_CGEncountered_vals[] = {
  {   0, "noCGencountered" },
  {   1, "manualCGencountered" },
  {   2, "scpOverload" },
  { 0, NULL }
};


static int
dissect_inap_CGEncountered(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_cGEncountered_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_CGEncountered(TRUE, tvb, offset, pinfo, tree, hf_inap_cGEncountered);
}


static const value_string inap_BearerCapability_vals[] = {
  {   0, "bearerCap" },
  {   1, "tmr" },
  { 0, NULL }
};

static const ber_choice_t BearerCapability_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_bearerCap_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_tmr_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_BearerCapability(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 BearerCapability_choice, hf_index, ett_inap_BearerCapability,
                                 NULL);

  return offset;
}
static int dissect_bearerCapability_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_BearerCapability(TRUE, tvb, offset, pinfo, tree, hf_inap_bearerCapability);
}


static const ber_sequence_t DpSpecificCommonParameters_sequence[] = {
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
dissect_inap_DpSpecificCommonParameters(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DpSpecificCommonParameters_sequence, hf_index, ett_inap_DpSpecificCommonParameters);

  return offset;
}
static int dissect_dpSpecificCommonParameters_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_DpSpecificCommonParameters(TRUE, tvb, offset, pinfo, tree, hf_inap_dpSpecificCommonParameters);
}


static const value_string inap_CallingFacilityGroup_vals[] = {
  {   0, "trunkGroupID" },
  {   1, "privateFacilityID" },
  {   2, "huntGroup" },
  {   3, "routeIndex" },
  { 0, NULL }
};

static const ber_choice_t CallingFacilityGroup_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_trunkGroupID_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_privateFacilityID_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_huntGroup_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_routeIndex_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_CallingFacilityGroup(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 CallingFacilityGroup_choice, hf_index, ett_inap_CallingFacilityGroup,
                                 NULL);

  return offset;
}
static int dissect_callingFacilityGroup_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_CallingFacilityGroup(TRUE, tvb, offset, pinfo, tree, hf_inap_callingFacilityGroup);
}



static int
dissect_inap_OCTET_STRING_SIZE_2(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_redirectionInformation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING_SIZE_2(TRUE, tvb, offset, pinfo, tree, hf_inap_redirectionInformation);
}
static int dissect_highLayerCompatibility_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING_SIZE_2(TRUE, tvb, offset, pinfo, tree, hf_inap_highLayerCompatibility);
}
static int dissect_forwardCallIndicators_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING_SIZE_2(TRUE, tvb, offset, pinfo, tree, hf_inap_forwardCallIndicators);
}


static const ber_sequence_t AnalysedInformationarg_sequence[] = {
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
dissect_inap_AnalysedInformationarg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AnalysedInformationarg_sequence, hf_index, ett_inap_AnalysedInformationarg);

  return offset;
}



static int
dissect_inap_DestinationAddress(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_destinationRoutingAddress_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_DestinationAddress(FALSE, tvb, offset, pinfo, tree, hf_inap_destinationRoutingAddress_item);
}


static const ber_sequence_t SEQUENCE_SIZE_1_3_OF_DestinationAddress_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_destinationRoutingAddress_item },
};

static int
dissect_inap_SEQUENCE_SIZE_1_3_OF_DestinationAddress(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_3_OF_DestinationAddress_sequence_of, hf_index, ett_inap_SEQUENCE_SIZE_1_3_OF_DestinationAddress);

  return offset;
}
static int dissect_destinationRoutingAddress_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_SEQUENCE_SIZE_1_3_OF_DestinationAddress(TRUE, tvb, offset, pinfo, tree, hf_inap_destinationRoutingAddress);
}



static int
dissect_inap_OCTET_STRING_SIZE_3(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_alertingPattern_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING_SIZE_3(TRUE, tvb, offset, pinfo, tree, hf_inap_alertingPattern);
}


static const ber_sequence_t AnalyseInformationarg_sequence[] = {
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
dissect_inap_AnalyseInformationarg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AnalyseInformationarg_sequence, hf_index, ett_inap_AnalyseInformationarg);

  return offset;
}


static const value_string inap_PartyToCharge_vals[] = {
  {   0, "sendingSideID" },
  {   1, "receivingSideID" },
  { 0, NULL }
};

static const ber_choice_t PartyToCharge_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sendingSideID_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_receivingSideID_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_PartyToCharge(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 PartyToCharge_choice, hf_index, ett_inap_PartyToCharge,
                                 NULL);

  return offset;
}
static int dissect_partyToCharge_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_PartyToCharge(TRUE, tvb, offset, pinfo, tree, hf_inap_partyToCharge);
}


static const ber_sequence_t ApplyChargingarg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_aChBillingChargingCharacteristics_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_partyToCharge_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_ApplyChargingarg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ApplyChargingarg_sequence, hf_index, ett_inap_ApplyChargingarg);

  return offset;
}



static int
dissect_inap_ApplyChargingReportarg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t AssistRequestInstructionsarg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_correlationID_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iPAvailable_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iPSSPCapabilities_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_AssistRequestInstructionsarg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AssistRequestInstructionsarg_sequence, hf_index, ett_inap_AssistRequestInstructionsarg);

  return offset;
}


static const value_string inap_T_dpCriteria_vals[] = {
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
dissect_inap_T_dpCriteria(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_dpCriteria_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_dpCriteria(TRUE, tvb, offset, pinfo, tree, hf_inap_dpCriteria);
}


static const ber_sequence_t T_gapOnService_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_serviceKey_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dpCriteria_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_gapOnService(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_gapOnService_sequence, hf_index, ett_inap_T_gapOnService);

  return offset;
}
static int dissect_gapOnService_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_gapOnService(TRUE, tvb, offset, pinfo, tree, hf_inap_gapOnService);
}


static const ber_sequence_t T_calledAddressAndService_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_calledAddressValue_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_serviceKey_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_calledAddressAndService(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_calledAddressAndService_sequence, hf_index, ett_inap_T_calledAddressAndService);

  return offset;
}
static int dissect_calledAddressAndService_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_calledAddressAndService(TRUE, tvb, offset, pinfo, tree, hf_inap_calledAddressAndService);
}


static const ber_sequence_t T_callingAddressAndService_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_callingAddressValue_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_serviceKey_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationNumber_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_callingAddressAndService(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_callingAddressAndService_sequence, hf_index, ett_inap_T_callingAddressAndService);

  return offset;
}
static int dissect_callingAddressAndService_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_callingAddressAndService(TRUE, tvb, offset, pinfo, tree, hf_inap_callingAddressAndService);
}


static const value_string inap_T_gapCriteria_vals[] = {
  {   0, "calledAddressValue" },
  {   2, "gapOnService" },
  {  29, "calledAddressAndService" },
  {  30, "callingAddressAndService" },
  { 0, NULL }
};

static const ber_choice_t T_gapCriteria_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_calledAddressValue_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_gapOnService_impl },
  {  29, BER_CLASS_CON, 29, BER_FLAGS_IMPLTAG, dissect_calledAddressAndService_impl },
  {  30, BER_CLASS_CON, 30, BER_FLAGS_IMPLTAG, dissect_callingAddressAndService_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_T_gapCriteria(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_gapCriteria_choice, hf_index, ett_inap_T_gapCriteria,
                                 NULL);

  return offset;
}
static int dissect_gapCriteria_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_gapCriteria(TRUE, tvb, offset, pinfo, tree, hf_inap_gapCriteria);
}



static int
dissect_inap_INTEGER_M1_60000(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_gapInterval_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_INTEGER_M1_60000(TRUE, tvb, offset, pinfo, tree, hf_inap_gapInterval);
}


static const ber_sequence_t T_gapIndicators_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_cgduration_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gapInterval_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_gapIndicators(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_gapIndicators_sequence, hf_index, ett_inap_T_gapIndicators);

  return offset;
}
static int dissect_gapIndicators_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_gapIndicators(TRUE, tvb, offset, pinfo, tree, hf_inap_gapIndicators);
}


static const value_string inap_T_controlType_vals[] = {
  {   0, "sCPOverloaded" },
  {   1, "manuallyInitiated" },
  {   2, "destinationOverload" },
  { 0, NULL }
};


static int
dissect_inap_T_controlType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_controlType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_controlType(TRUE, tvb, offset, pinfo, tree, hf_inap_controlType);
}


static const ber_sequence_t Both_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_informationToSend_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_releaseCause_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_Both(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Both_sequence, hf_index, ett_inap_Both);

  return offset;
}
static int dissect_both_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_Both(TRUE, tvb, offset, pinfo, tree, hf_inap_both);
}


static const value_string inap_T_gapTreatment_vals[] = {
  {   0, "informationToSend" },
  {   1, "releaseCause" },
  {   2, "both" },
  { 0, NULL }
};

static const ber_choice_t T_gapTreatment_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_informationToSend_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_releaseCause_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_both_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_T_gapTreatment(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_gapTreatment_choice, hf_index, ett_inap_T_gapTreatment,
                                 NULL);

  return offset;
}
static int dissect_gapTreatment_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_gapTreatment(TRUE, tvb, offset, pinfo, tree, hf_inap_gapTreatment);
}


static const ber_sequence_t CallGaparg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gapCriteria_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gapIndicators_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_controlType_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gapTreatment_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_CallGaparg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CallGaparg_sequence, hf_index, ett_inap_CallGaparg);

  return offset;
}


static const value_string inap_T_requestedInformationType_vals[] = {
  {   0, "callAttemptElapsedTime" },
  {   1, "callStopTime" },
  {   2, "callConnectedElapsedTime" },
  {   3, "calledAddress" },
  {  30, "releaseCause" },
  { 0, NULL }
};


static int
dissect_inap_T_requestedInformationType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_requestedInformationType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_requestedInformationType(TRUE, tvb, offset, pinfo, tree, hf_inap_requestedInformationType);
}



static int
dissect_inap_INTEGER_0_255(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_callAttemptElapsedTimeValue_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_INTEGER_0_255(TRUE, tvb, offset, pinfo, tree, hf_inap_callAttemptElapsedTimeValue);
}


static const value_string inap_T_requestedInformationValue_vals[] = {
  {   0, "callAttemptElapsedTimeValue" },
  {   1, "callStopTimeValue" },
  {   2, "callConnectedElapsedTimeValue" },
  {   3, "calledAddressValue" },
  {  30, "releaseCauseValue" },
  { 0, NULL }
};

static const ber_choice_t T_requestedInformationValue_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_callAttemptElapsedTimeValue_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_callStopTimeValue_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_callConnectedElapsedTimeValue_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_calledAddressValue_impl },
  {  30, BER_CLASS_CON, 30, BER_FLAGS_IMPLTAG, dissect_releaseCauseValue_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_T_requestedInformationValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_requestedInformationValue_choice, hf_index, ett_inap_T_requestedInformationValue,
                                 NULL);

  return offset;
}
static int dissect_requestedInformationValue_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_requestedInformationValue(TRUE, tvb, offset, pinfo, tree, hf_inap_requestedInformationValue);
}


static const ber_sequence_t T_requestedInformationList_item_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_requestedInformationType_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_requestedInformationValue_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_requestedInformationList_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_requestedInformationList_item_sequence, hf_index, ett_inap_T_requestedInformationList_item);

  return offset;
}
static int dissect_requestedInformationList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_requestedInformationList_item(FALSE, tvb, offset, pinfo, tree, hf_inap_requestedInformationList_item);
}


static const ber_sequence_t T_requestedInformationList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_requestedInformationList_item },
};

static int
dissect_inap_T_requestedInformationList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      T_requestedInformationList_sequence_of, hf_index, ett_inap_T_requestedInformationList);

  return offset;
}
static int dissect_requestedInformationList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_requestedInformationList(TRUE, tvb, offset, pinfo, tree, hf_inap_requestedInformationList);
}


static const ber_sequence_t CallInformationReportarg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_requestedInformationList_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_correlationID_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_CallInformationReportarg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CallInformationReportarg_sequence, hf_index, ett_inap_CallInformationReportarg);

  return offset;
}


static const value_string inap_T_requestedInformationTypeList_item_vals[] = {
  {   0, "callAttemptElapsedTime" },
  {   1, "callStopTime" },
  {   2, "callConnectedElapsedTime" },
  {   3, "calledAddress" },
  {  30, "releaseCause" },
  { 0, NULL }
};


static int
dissect_inap_T_requestedInformationTypeList_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_requestedInformationTypeList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_requestedInformationTypeList_item(FALSE, tvb, offset, pinfo, tree, hf_inap_requestedInformationTypeList_item);
}


static const ber_sequence_t T_requestedInformationTypeList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_requestedInformationTypeList_item },
};

static int
dissect_inap_T_requestedInformationTypeList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      T_requestedInformationTypeList_sequence_of, hf_index, ett_inap_T_requestedInformationTypeList);

  return offset;
}
static int dissect_requestedInformationTypeList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_requestedInformationTypeList(TRUE, tvb, offset, pinfo, tree, hf_inap_requestedInformationTypeList);
}


static const ber_sequence_t CallInformationRequestarg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_requestedInformationTypeList_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_correlationID_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_legID_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_CallInformationRequestarg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CallInformationRequestarg_sequence, hf_index, ett_inap_CallInformationRequestarg);

  return offset;
}



static int
dissect_inap_INTEGER_M128_127(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_invokeID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_INTEGER_M128_127(TRUE, tvb, offset, pinfo, tree, hf_inap_invokeID);
}
static int dissect_operation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_INTEGER_M128_127(TRUE, tvb, offset, pinfo, tree, hf_inap_operation);
}



static int
dissect_inap_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_allRequests_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_NULL(TRUE, tvb, offset, pinfo, tree, hf_inap_allRequests);
}
static int dissect_none_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_NULL(TRUE, tvb, offset, pinfo, tree, hf_inap_none);
}
static int dissect_empty_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_NULL(TRUE, tvb, offset, pinfo, tree, hf_inap_empty);
}
static int dissect_null(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_NULL(FALSE, tvb, offset, pinfo, tree, hf_inap_null);
}


static const value_string inap_Cancelarg_vals[] = {
  {   0, "invokeID" },
  {   1, "allRequests" },
  { 0, NULL }
};

static const ber_choice_t Cancelarg_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_invokeID_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_allRequests_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_Cancelarg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Cancelarg_choice, hf_index, ett_inap_Cancelarg,
                                 NULL);

  return offset;
}


static const value_string inap_FacilityGroupID_vals[] = {
  {   0, "trunkGroupID" },
  {   1, "privateFacilityID" },
  {   2, "huntGroup" },
  {   3, "routeIndex" },
  { 0, NULL }
};

static const ber_choice_t FacilityGroupID_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_trunkGroupID_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_privateFacilityID_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_huntGroup_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_routeIndex_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_FacilityGroupID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 FacilityGroupID_choice, hf_index, ett_inap_FacilityGroupID,
                                 NULL);

  return offset;
}
static int dissect_facilityGroupID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_FacilityGroupID(TRUE, tvb, offset, pinfo, tree, hf_inap_facilityGroupID);
}


static const value_string inap_ResourceID_vals[] = {
  {   0, "lineID" },
  {   1, "facilityGroupID" },
  {   2, "facilityGroupMemberID" },
  {   3, "trunkGroupID" },
  { 0, NULL }
};

static const ber_choice_t ResourceID_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_lineID_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_facilityGroupID_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_facilityGroupMemberID_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_trunkGroupID_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_ResourceID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ResourceID_choice, hf_index, ett_inap_ResourceID,
                                 NULL);

  return offset;
}
static int dissect_resourceID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_ResourceID(TRUE, tvb, offset, pinfo, tree, hf_inap_resourceID);
}


static const ber_sequence_t CancelStatusReportRequestarg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_resourceID_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_CancelStatusReportRequestarg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CancelStatusReportRequestarg_sequence, hf_index, ett_inap_CancelStatusReportRequestarg);

  return offset;
}


static const ber_sequence_t CollectedInformationarg_sequence[] = {
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
dissect_inap_CollectedInformationarg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CollectedInformationarg_sequence, hf_index, ett_inap_CollectedInformationarg);

  return offset;
}


static const ber_sequence_t CollectInformationarg_sequence[] = {
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
dissect_inap_CollectInformationarg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CollectInformationarg_sequence, hf_index, ett_inap_CollectInformationarg);

  return offset;
}



static int
dissect_inap_INTEGER_0_22(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_cutAndPaste_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_INTEGER_0_22(TRUE, tvb, offset, pinfo, tree, hf_inap_cutAndPaste);
}


static const value_string inap_T_forwardingCondition_vals[] = {
  {   0, "busy" },
  {   1, "noanswer" },
  { 0, NULL }
};


static int
dissect_inap_T_forwardingCondition(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_forwardingCondition_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_forwardingCondition(TRUE, tvb, offset, pinfo, tree, hf_inap_forwardingCondition);
}


static const ber_sequence_t Connectarg_sequence[] = {
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
dissect_inap_Connectarg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Connectarg_sequence, hf_index, ett_inap_Connectarg);

  return offset;
}


static const value_string inap_T_resourceAddress_vals[] = {
  {   0, "ipRoutingAddress" },
  {   1, "legID" },
  {   2, "both" },
  {   3, "none" },
  { 0, NULL }
};

static const ber_choice_t T_resourceAddress_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ipRoutingAddress_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_legID_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_both_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_none_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_T_resourceAddress(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_resourceAddress_choice, hf_index, ett_inap_T_resourceAddress,
                                 NULL);

  return offset;
}
static int dissect_resourceAddress(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_resourceAddress(FALSE, tvb, offset, pinfo, tree, hf_inap_resourceAddress);
}


static const ber_sequence_t ConnectToResource_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_resourceAddress },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_serviceInteractionIndicators_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_ConnectToResource(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ConnectToResource_sequence, hf_index, ett_inap_ConnectToResource);

  return offset;
}


static const ber_sequence_t EstablishTemporaryConnection_sequence[] = {
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
dissect_inap_EstablishTemporaryConnection(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   EstablishTemporaryConnection_sequence, hf_index, ett_inap_EstablishTemporaryConnection);

  return offset;
}


static const value_string inap_MonitorMode_vals[] = {
  {   0, "interrupted" },
  {   1, "notifyAndContinue" },
  {   2, "transparent" },
  { 0, NULL }
};


static int
dissect_inap_MonitorMode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_monitorMode_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_MonitorMode(TRUE, tvb, offset, pinfo, tree, hf_inap_monitorMode);
}


static const ber_sequence_t EventNotificationChargingarg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_eventTypeCharging_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_eventSpecificInformationCharging_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_legID_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { BER_CLASS_CON, 30, BER_FLAGS_IMPLTAG, dissect_monitorMode_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_EventNotificationChargingarg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   EventNotificationChargingarg_sequence, hf_index, ett_inap_EventNotificationChargingarg);

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
dissect_inap_EventTypeBCSM(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_eventTypeBCSM_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_EventTypeBCSM(TRUE, tvb, offset, pinfo, tree, hf_inap_eventTypeBCSM);
}


static const ber_sequence_t T_collectedInfoSpecificInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_calledPartynumber_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_collectedInfoSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_collectedInfoSpecificInfo_sequence, hf_index, ett_inap_T_collectedInfoSpecificInfo);

  return offset;
}
static int dissect_collectedInfoSpecificInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_collectedInfoSpecificInfo(TRUE, tvb, offset, pinfo, tree, hf_inap_collectedInfoSpecificInfo);
}


static const ber_sequence_t T_analyzedInfoSpecificInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_calledPartynumber_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_analyzedInfoSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_analyzedInfoSpecificInfo_sequence, hf_index, ett_inap_T_analyzedInfoSpecificInfo);

  return offset;
}
static int dissect_analyzedInfoSpecificInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_analyzedInfoSpecificInfo(TRUE, tvb, offset, pinfo, tree, hf_inap_analyzedInfoSpecificInfo);
}



static int
dissect_inap_OCTET_STRING_SIZE_2_10(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_failureCause_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING_SIZE_2_10(TRUE, tvb, offset, pinfo, tree, hf_inap_failureCause);
}
static int dissect_busyCause_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING_SIZE_2_10(TRUE, tvb, offset, pinfo, tree, hf_inap_busyCause);
}


static const ber_sequence_t T_routeSelectFailureSpecificInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_failureCause_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_routeSelectFailureSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_routeSelectFailureSpecificInfo_sequence, hf_index, ett_inap_T_routeSelectFailureSpecificInfo);

  return offset;
}
static int dissect_routeSelectFailureSpecificInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_routeSelectFailureSpecificInfo(TRUE, tvb, offset, pinfo, tree, hf_inap_routeSelectFailureSpecificInfo);
}


static const ber_sequence_t T_oCalledPartyBusySpecificInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_busyCause_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_oCalledPartyBusySpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_oCalledPartyBusySpecificInfo_sequence, hf_index, ett_inap_T_oCalledPartyBusySpecificInfo);

  return offset;
}
static int dissect_oCalledPartyBusySpecificInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_oCalledPartyBusySpecificInfo(TRUE, tvb, offset, pinfo, tree, hf_inap_oCalledPartyBusySpecificInfo);
}


static const ber_sequence_t T_oNoAnswerSpecificInfo_sequence[] = {
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_oNoAnswerSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_oNoAnswerSpecificInfo_sequence, hf_index, ett_inap_T_oNoAnswerSpecificInfo);

  return offset;
}
static int dissect_oNoAnswerSpecificInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_oNoAnswerSpecificInfo(TRUE, tvb, offset, pinfo, tree, hf_inap_oNoAnswerSpecificInfo);
}


static const ber_sequence_t T_oAnswerSpecificInfo_sequence[] = {
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_oAnswerSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_oAnswerSpecificInfo_sequence, hf_index, ett_inap_T_oAnswerSpecificInfo);

  return offset;
}
static int dissect_oAnswerSpecificInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_oAnswerSpecificInfo(TRUE, tvb, offset, pinfo, tree, hf_inap_oAnswerSpecificInfo);
}


static const ber_sequence_t T_oMidCallSpecificInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_connectTime_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_oMidCallSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_oMidCallSpecificInfo_sequence, hf_index, ett_inap_T_oMidCallSpecificInfo);

  return offset;
}
static int dissect_oMidCallSpecificInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_oMidCallSpecificInfo(TRUE, tvb, offset, pinfo, tree, hf_inap_oMidCallSpecificInfo);
}


static const ber_sequence_t T_oDisconnectSpecificInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_releaseCause_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_connectTime_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_oDisconnectSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_oDisconnectSpecificInfo_sequence, hf_index, ett_inap_T_oDisconnectSpecificInfo);

  return offset;
}
static int dissect_oDisconnectSpecificInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_oDisconnectSpecificInfo(TRUE, tvb, offset, pinfo, tree, hf_inap_oDisconnectSpecificInfo);
}


static const ber_sequence_t T_tBusySpecificInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_busyCause_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_tBusySpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_tBusySpecificInfo_sequence, hf_index, ett_inap_T_tBusySpecificInfo);

  return offset;
}
static int dissect_tBusySpecificInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_tBusySpecificInfo(TRUE, tvb, offset, pinfo, tree, hf_inap_tBusySpecificInfo);
}


static const ber_sequence_t T_tNoAnswerSpecificInfo_sequence[] = {
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_tNoAnswerSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_tNoAnswerSpecificInfo_sequence, hf_index, ett_inap_T_tNoAnswerSpecificInfo);

  return offset;
}
static int dissect_tNoAnswerSpecificInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_tNoAnswerSpecificInfo(TRUE, tvb, offset, pinfo, tree, hf_inap_tNoAnswerSpecificInfo);
}


static const ber_sequence_t T_tAnswerSpecificInfo_sequence[] = {
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_tAnswerSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_tAnswerSpecificInfo_sequence, hf_index, ett_inap_T_tAnswerSpecificInfo);

  return offset;
}
static int dissect_tAnswerSpecificInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_tAnswerSpecificInfo(TRUE, tvb, offset, pinfo, tree, hf_inap_tAnswerSpecificInfo);
}


static const ber_sequence_t T_tMidCallSpecificInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_connectTime_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_tMidCallSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_tMidCallSpecificInfo_sequence, hf_index, ett_inap_T_tMidCallSpecificInfo);

  return offset;
}
static int dissect_tMidCallSpecificInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_tMidCallSpecificInfo(TRUE, tvb, offset, pinfo, tree, hf_inap_tMidCallSpecificInfo);
}


static const ber_sequence_t T_tDisconnectSpecificInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_releaseCause_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_connectTime_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_tDisconnectSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_tDisconnectSpecificInfo_sequence, hf_index, ett_inap_T_tDisconnectSpecificInfo);

  return offset;
}
static int dissect_tDisconnectSpecificInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_tDisconnectSpecificInfo(TRUE, tvb, offset, pinfo, tree, hf_inap_tDisconnectSpecificInfo);
}


static const value_string inap_T_eventSpecificInformationBCSM_vals[] = {
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

static const ber_choice_t T_eventSpecificInformationBCSM_choice[] = {
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
dissect_inap_T_eventSpecificInformationBCSM(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_eventSpecificInformationBCSM_choice, hf_index, ett_inap_T_eventSpecificInformationBCSM,
                                 NULL);

  return offset;
}
static int dissect_eventSpecificInformationBCSM_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_eventSpecificInformationBCSM(TRUE, tvb, offset, pinfo, tree, hf_inap_eventSpecificInformationBCSM);
}


static const ber_sequence_t EventReportBCSM_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_eventTypeBCSM_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_bcsmEventCorrelationID_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_eventSpecificInformationBCSM_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_legID_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_miscCallInfo_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_EventReportBCSM(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   EventReportBCSM_sequence, hf_index, ett_inap_EventReportBCSM);

  return offset;
}



static int
dissect_inap_FurnishChargingInformationarg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string inap_HoldCallInNetworkarg_vals[] = {
  {   0, "holdcause" },
  {   1, "empty" },
  { 0, NULL }
};

static const ber_choice_t HoldCallInNetworkarg_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_holdcause_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_empty_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_HoldCallInNetworkarg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 HoldCallInNetworkarg_choice, hf_index, ett_inap_HoldCallInNetworkarg,
                                 NULL);

  return offset;
}


static const ber_sequence_t InitialDP_sequence[] = {
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
dissect_inap_InitialDP(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   InitialDP_sequence, hf_index, ett_inap_InitialDP);

  return offset;
}


static const ber_sequence_t InitiateCallAttempt_sequence[] = {
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
dissect_inap_InitiateCallAttempt(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   InitiateCallAttempt_sequence, hf_index, ett_inap_InitiateCallAttempt);

  return offset;
}


static const ber_sequence_t OAnswer_sequence[] = {
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
dissect_inap_OAnswer(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   OAnswer_sequence, hf_index, ett_inap_OAnswer);

  return offset;
}


static const ber_sequence_t OCalledPartyBusy_sequence[] = {
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
dissect_inap_OCalledPartyBusy(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   OCalledPartyBusy_sequence, hf_index, ett_inap_OCalledPartyBusy);

  return offset;
}


static const ber_sequence_t ODisconnect_sequence[] = {
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
dissect_inap_ODisconnect(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ODisconnect_sequence, hf_index, ett_inap_ODisconnect);

  return offset;
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
dissect_inap_FeatureRequestIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_featureRequestIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_FeatureRequestIndicator(TRUE, tvb, offset, pinfo, tree, hf_inap_featureRequestIndicator);
}


static const ber_sequence_t OMidCall_sequence[] = {
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
dissect_inap_OMidCall(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   OMidCall_sequence, hf_index, ett_inap_OMidCall);

  return offset;
}


static const ber_sequence_t ONoAnswer_sequence[] = {
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
dissect_inap_ONoAnswer(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ONoAnswer_sequence, hf_index, ett_inap_ONoAnswer);

  return offset;
}


static const ber_sequence_t OriginationAttemptAuthorized_sequence[] = {
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
dissect_inap_OriginationAttemptAuthorized(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   OriginationAttemptAuthorized_sequence, hf_index, ett_inap_OriginationAttemptAuthorized);

  return offset;
}



static int
dissect_inap_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_disconnectFromIPForbidden_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_BOOLEAN(TRUE, tvb, offset, pinfo, tree, hf_inap_disconnectFromIPForbidden);
}
static int dissect_requestAnnouncementComplete_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_BOOLEAN(TRUE, tvb, offset, pinfo, tree, hf_inap_requestAnnouncementComplete);
}
static int dissect_interruptableAnnInd_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_BOOLEAN(TRUE, tvb, offset, pinfo, tree, hf_inap_interruptableAnnInd);
}
static int dissect_voiceInformation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_BOOLEAN(TRUE, tvb, offset, pinfo, tree, hf_inap_voiceInformation);
}
static int dissect_voiceBack_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_BOOLEAN(TRUE, tvb, offset, pinfo, tree, hf_inap_voiceBack);
}
static int dissect_iA5Information_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_BOOLEAN(TRUE, tvb, offset, pinfo, tree, hf_inap_iA5Information);
}


static const ber_sequence_t PlayAnnouncement_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_informationToSend_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_disconnectFromIPForbidden_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_requestAnnouncementComplete_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_PlayAnnouncement(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PlayAnnouncement_sequence, hf_index, ett_inap_PlayAnnouncement);

  return offset;
}



static int
dissect_inap_OCTET_STRING_SIZE_1_2(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_endOfReplyDigit_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING_SIZE_1_2(TRUE, tvb, offset, pinfo, tree, hf_inap_endOfReplyDigit);
}
static int dissect_cancelDigit_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING_SIZE_1_2(TRUE, tvb, offset, pinfo, tree, hf_inap_cancelDigit);
}
static int dissect_startDigit_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_OCTET_STRING_SIZE_1_2(TRUE, tvb, offset, pinfo, tree, hf_inap_startDigit);
}


static const value_string inap_T_errorTreatment_vals[] = {
  {   0, "reportErrorToScf" },
  {   1, "help" },
  {   2, "repeatPrompt" },
  { 0, NULL }
};


static int
dissect_inap_T_errorTreatment(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_errorTreatment_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_errorTreatment(TRUE, tvb, offset, pinfo, tree, hf_inap_errorTreatment);
}


static const ber_sequence_t T_collectedDigits_sequence[] = {
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
dissect_inap_T_collectedDigits(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_collectedDigits_sequence, hf_index, ett_inap_T_collectedDigits);

  return offset;
}
static int dissect_collectedDigits_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_collectedDigits(TRUE, tvb, offset, pinfo, tree, hf_inap_collectedDigits);
}


static const value_string inap_T_collectedInfo_vals[] = {
  {   0, "collectedDigits" },
  {   1, "iA5Information" },
  { 0, NULL }
};

static const ber_choice_t T_collectedInfo_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_collectedDigits_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iA5Information_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_T_collectedInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_collectedInfo_choice, hf_index, ett_inap_T_collectedInfo,
                                 NULL);

  return offset;
}
static int dissect_collectedInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_collectedInfo(TRUE, tvb, offset, pinfo, tree, hf_inap_collectedInfo);
}


static const ber_sequence_t PromptAndCollectUserInformationarg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_collectedInfo_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_disconnectFromIPForbidden_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_informationToSend_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_PromptAndCollectUserInformationarg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PromptAndCollectUserInformationarg_sequence, hf_index, ett_inap_PromptAndCollectUserInformationarg);

  return offset;
}


static const value_string inap_PromptAndCollectUserInformationres_vals[] = {
  {   0, "digitsResponse" },
  {   1, "iA5Response" },
  { 0, NULL }
};

static const ber_choice_t PromptAndCollectUserInformationres_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_digitsResponse_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_iA5Response_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_PromptAndCollectUserInformationres(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 PromptAndCollectUserInformationres_choice, hf_index, ett_inap_PromptAndCollectUserInformationres,
                                 NULL);

  return offset;
}


static const value_string inap_ResourceStatus_vals[] = {
  {   0, "busy" },
  {   1, "idle" },
  { 0, NULL }
};


static int
dissect_inap_ResourceStatus(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_resourceStatus_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_ResourceStatus(TRUE, tvb, offset, pinfo, tree, hf_inap_resourceStatus);
}



static int
dissect_inap_ReleaseCall(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t T_allCallSegments_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_releaseCause_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_allCallSegments(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_allCallSegments_sequence, hf_index, ett_inap_T_allCallSegments);

  return offset;
}
static int dissect_allCallSegments_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_allCallSegments(TRUE, tvb, offset, pinfo, tree, hf_inap_allCallSegments);
}


static const value_string inap_ReleaseCallArg_vals[] = {
  {   0, "initialCallSegment" },
  {   1, "allCallSegments" },
  { 0, NULL }
};

static const ber_choice_t ReleaseCallArg_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_initialCallSegment },
  {   1, BER_CLASS_CON, 2, 0, dissect_allCallSegments_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_ReleaseCallArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ReleaseCallArg_choice, hf_index, ett_inap_ReleaseCallArg,
                                 NULL);

  return offset;
}


static const value_string inap_RequestCurrentStatusReportarg_vals[] = {
  {   0, "lineID" },
  {   1, "facilityGroupID" },
  {   2, "facilityGroupMemberID" },
  {   3, "trunkGroupID" },
  { 0, NULL }
};

static const ber_choice_t RequestCurrentStatusReportarg_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_lineID_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_facilityGroupID_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_facilityGroupMemberID_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_trunkGroupID_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_RequestCurrentStatusReportarg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 RequestCurrentStatusReportarg_choice, hf_index, ett_inap_RequestCurrentStatusReportarg,
                                 NULL);

  return offset;
}


static const ber_sequence_t RequestCurrentStatusReportres_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_resourceStatus_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_resourceID_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_RequestCurrentStatusReportres(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   RequestCurrentStatusReportres_sequence, hf_index, ett_inap_RequestCurrentStatusReportres);

  return offset;
}


static const ber_sequence_t RequestEveryStatusChangeReport_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_resourceID_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_correlationID_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_monitorDuration_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_RequestEveryStatusChangeReport(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   RequestEveryStatusChangeReport_sequence, hf_index, ett_inap_RequestEveryStatusChangeReport);

  return offset;
}


static const ber_sequence_t RequestFirstStatusMatchReport_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_resourceID_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_resourceStatus_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_correlationID_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_monitorDuration_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_bearerCapability_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_RequestFirstStatusMatchReport(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   RequestFirstStatusMatchReport_sequence, hf_index, ett_inap_RequestFirstStatusMatchReport);

  return offset;
}


static const ber_sequence_t RequestNotificationChargingEvent_item_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_eventTypeCharging_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_monitorMode_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_legID_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_RequestNotificationChargingEvent_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   RequestNotificationChargingEvent_item_sequence, hf_index, ett_inap_RequestNotificationChargingEvent_item);

  return offset;
}
static int dissect_RequestNotificationChargingEvent_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_RequestNotificationChargingEvent_item(FALSE, tvb, offset, pinfo, tree, hf_inap_RequestNotificationChargingEvent_item);
}


static const ber_sequence_t RequestNotificationChargingEvent_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_RequestNotificationChargingEvent_item },
};

static int
dissect_inap_RequestNotificationChargingEvent(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      RequestNotificationChargingEvent_sequence_of, hf_index, ett_inap_RequestNotificationChargingEvent);

  return offset;
}



static int
dissect_inap_INTEGER_1_255(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_numberOfDigits_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_INTEGER_1_255(TRUE, tvb, offset, pinfo, tree, hf_inap_numberOfDigits);
}



static int
dissect_inap_INTEGER_0_2047(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_applicationTimer_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_INTEGER_0_2047(TRUE, tvb, offset, pinfo, tree, hf_inap_applicationTimer);
}


static const value_string inap_T_dpSpecificCriteria_vals[] = {
  {   0, "numberOfDigits" },
  {   1, "applicationTimer" },
  { 0, NULL }
};

static const ber_choice_t T_dpSpecificCriteria_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_numberOfDigits_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_applicationTimer_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_T_dpSpecificCriteria(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_dpSpecificCriteria_choice, hf_index, ett_inap_T_dpSpecificCriteria,
                                 NULL);

  return offset;
}
static int dissect_dpSpecificCriteria_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_dpSpecificCriteria(TRUE, tvb, offset, pinfo, tree, hf_inap_dpSpecificCriteria);
}


static const ber_sequence_t T_bcsmEvents_item_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_eventTypeBCSM_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_monitorMode_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_legID_impl },
  { BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dpSpecificCriteria_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_bcsmEvents_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_bcsmEvents_item_sequence, hf_index, ett_inap_T_bcsmEvents_item);

  return offset;
}
static int dissect_bcsmEvents_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_bcsmEvents_item(FALSE, tvb, offset, pinfo, tree, hf_inap_bcsmEvents_item);
}


static const ber_sequence_t T_bcsmEvents_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_bcsmEvents_item },
};

static int
dissect_inap_T_bcsmEvents(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      T_bcsmEvents_sequence_of, hf_index, ett_inap_T_bcsmEvents);

  return offset;
}
static int dissect_bcsmEvents_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_bcsmEvents(TRUE, tvb, offset, pinfo, tree, hf_inap_bcsmEvents);
}


static const ber_sequence_t RequestReportBCSMEvent_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_bcsmEvents_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_bcsmEventCorrelationID_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_RequestReportBCSMEvent(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   RequestReportBCSMEvent_sequence, hf_index, ett_inap_RequestReportBCSMEvent);

  return offset;
}


static const value_string inap_T_timerID_vals[] = {
  {   0, "tssf" },
  { 0, NULL }
};


static int
dissect_inap_T_timerID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_timerID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_timerID(TRUE, tvb, offset, pinfo, tree, hf_inap_timerID);
}


static const ber_sequence_t ResetTimer_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_timerID_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_timervalue_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_ResetTimer(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ResetTimer_sequence, hf_index, ett_inap_ResetTimer);

  return offset;
}


static const ber_sequence_t RouteSelectFailure_sequence[] = {
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
dissect_inap_RouteSelectFailure(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   RouteSelectFailure_sequence, hf_index, ett_inap_RouteSelectFailure);

  return offset;
}


static const value_string inap_CalledFacilityGroup_vals[] = {
  {   0, "trunkGroupID" },
  {   1, "privateFacilityID" },
  {   2, "huntGroup" },
  {   3, "routeIndex" },
  { 0, NULL }
};

static const ber_choice_t CalledFacilityGroup_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_trunkGroupID_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_privateFacilityID_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_huntGroup_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_routeIndex_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_CalledFacilityGroup(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 CalledFacilityGroup_choice, hf_index, ett_inap_CalledFacilityGroup,
                                 NULL);

  return offset;
}
static int dissect_calledFacilityGroup_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_CalledFacilityGroup(TRUE, tvb, offset, pinfo, tree, hf_inap_calledFacilityGroup);
}


static const ber_sequence_t SelectFacility_sequence[] = {
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
dissect_inap_SelectFacility(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SelectFacility_sequence, hf_index, ett_inap_SelectFacility);

  return offset;
}


static const ber_sequence_t SelectRoute_sequence[] = {
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
dissect_inap_SelectRoute(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SelectRoute_sequence, hf_index, ett_inap_SelectRoute);

  return offset;
}


static const ber_sequence_t SendChargingInformation_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sCIBillingChargingCharacteristics_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_partyToCharge_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_SendChargingInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SendChargingInformation_sequence, hf_index, ett_inap_SendChargingInformation);

  return offset;
}



static int
dissect_inap_INTEGER_0_99(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_counterID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_INTEGER_0_99(TRUE, tvb, offset, pinfo, tree, hf_inap_counterID);
}


static const ber_sequence_t T_countersValue_item_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_counterID_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_counterValue_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_T_countersValue_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_countersValue_item_sequence, hf_index, ett_inap_T_countersValue_item);

  return offset;
}
static int dissect_countersValue_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_countersValue_item(FALSE, tvb, offset, pinfo, tree, hf_inap_countersValue_item);
}


static const ber_sequence_t T_countersValue_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_countersValue_item },
};

static int
dissect_inap_T_countersValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      T_countersValue_sequence_of, hf_index, ett_inap_T_countersValue);

  return offset;
}
static int dissect_countersValue_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_countersValue(TRUE, tvb, offset, pinfo, tree, hf_inap_countersValue);
}


static const value_string inap_T_responseCondition_vals[] = {
  {   0, "intermediateResponse" },
  {   1, "lastResponse" },
  { 0, NULL }
};


static int
dissect_inap_T_responseCondition(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_responseCondition_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_responseCondition(TRUE, tvb, offset, pinfo, tree, hf_inap_responseCondition);
}


static const ber_sequence_t ServiceFilteringResponse_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_countersValue_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_filteringCriteria_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_responseCondition_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_ServiceFilteringResponse(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ServiceFilteringResponse_sequence, hf_index, ett_inap_ServiceFilteringResponse);

  return offset;
}


static const value_string inap_T_reportCondition_vals[] = {
  {   0, "statusReport" },
  {   1, "timerExpired" },
  {   2, "canceled" },
  { 0, NULL }
};


static int
dissect_inap_T_reportCondition(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_reportCondition_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_reportCondition(TRUE, tvb, offset, pinfo, tree, hf_inap_reportCondition);
}


static const ber_sequence_t StatusReport_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_resourceStatus_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_correlationID_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_resourceID_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_reportCondition_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_StatusReport(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   StatusReport_sequence, hf_index, ett_inap_StatusReport);

  return offset;
}


static const ber_sequence_t TAnswer_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_dpSpecificCommonParameters_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_calledPartyBusinessGroupID_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_calledPartySubaddress_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_calledFacilityGroup_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_calledFacilityGroupMember_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_TAnswer(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   TAnswer_sequence, hf_index, ett_inap_TAnswer);

  return offset;
}


static const ber_sequence_t TBusy_sequence[] = {
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
dissect_inap_TBusy(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   TBusy_sequence, hf_index, ett_inap_TBusy);

  return offset;
}


static const ber_sequence_t TDisconnect_sequence[] = {
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
dissect_inap_TDisconnect(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   TDisconnect_sequence, hf_index, ett_inap_TDisconnect);

  return offset;
}


static const ber_sequence_t TermAttemptAuthorized_sequence[] = {
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
dissect_inap_TermAttemptAuthorized(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   TermAttemptAuthorized_sequence, hf_index, ett_inap_TermAttemptAuthorized);

  return offset;
}


static const ber_sequence_t TMidCall_sequence[] = {
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
dissect_inap_TMidCall(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   TMidCall_sequence, hf_index, ett_inap_TMidCall);

  return offset;
}


static const ber_sequence_t TNoAnswer_sequence[] = {
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
dissect_inap_TNoAnswer(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   TNoAnswer_sequence, hf_index, ett_inap_TNoAnswer);

  return offset;
}


static const value_string inap_T_problem_vals[] = {
  {   0, "unknownOperation" },
  {   1, "tooLate" },
  {   2, "operationNotCancellable" },
  { 0, NULL }
};


static int
dissect_inap_T_problem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_problem_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_problem(TRUE, tvb, offset, pinfo, tree, hf_inap_problem);
}


static const ber_sequence_t CancelFailed_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_problem_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_operation_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_CancelFailed(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CancelFailed_sequence, hf_index, ett_inap_CancelFailed);

  return offset;
}


static const value_string inap_RequestedInfoError_vals[] = {
  {   1, "unknownRequestedInfo" },
  {   2, "requestedInfoNotAvailable" },
  { 0, NULL }
};


static int
dissect_inap_RequestedInfoError(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
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
dissect_inap_SystemFailure(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
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
dissect_inap_TaskRefused(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_inap_InvokeIDType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_invidtype(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_InvokeIDType(FALSE, tvb, offset, pinfo, tree, hf_inap_invidtype);
}


static const value_string inap_T_rinvokeID_vals[] = {
  {   0, "invidtype" },
  {   1, "null" },
  { 0, NULL }
};

static const ber_choice_t T_rinvokeID_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_invidtype },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_null },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_T_rinvokeID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_rinvokeID_choice, hf_index, ett_inap_T_rinvokeID,
                                 NULL);

  return offset;
}
static int dissect_rinvokeID(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_rinvokeID(FALSE, tvb, offset, pinfo, tree, hf_inap_rinvokeID);
}


static const value_string inap_GeneralProblem_vals[] = {
  {   0, "unrecognisedAPDU" },
  {   1, "mistypedAPDU" },
  {   2, "badlyStructuredAPDU" },
  { 0, NULL }
};


static int
dissect_inap_GeneralProblem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_gp_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_GeneralProblem(TRUE, tvb, offset, pinfo, tree, hf_inap_gp);
}


static const value_string inap_InvokeProblem_vals[] = {
  {   0, "duplicateInvocation" },
  {   1, "unrecognisedOperation" },
  {   2, "mistypedArgument" },
  {   3, "resourceLimitation" },
  {   4, "initiatorReleasing" },
  {   5, "unrecognisedLinkedID" },
  {   6, "linkedResponseUnexpected" },
  {   7, "unexpectedChildOperation" },
  { 0, NULL }
};


static int
dissect_inap_InvokeProblem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_ip_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_InvokeProblem(TRUE, tvb, offset, pinfo, tree, hf_inap_ip);
}


static const value_string inap_ReturnResultProblem_vals[] = {
  {   0, "unrecognisedInvocation" },
  {   1, "resultResponseUnexpected" },
  {   2, "mistypedResult" },
  { 0, NULL }
};


static int
dissect_inap_ReturnResultProblem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_rrp_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_ReturnResultProblem(TRUE, tvb, offset, pinfo, tree, hf_inap_rrp);
}


static const value_string inap_ReturnErrorProblem_vals[] = {
  {   0, "unrecognisedInvocation" },
  {   1, "errorResponseUnexpected" },
  {   2, "unrecognisedError" },
  {   3, "unexpectedError" },
  {   4, "mistypedParameter" },
  { 0, NULL }
};


static int
dissect_inap_ReturnErrorProblem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_rep_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_ReturnErrorProblem(TRUE, tvb, offset, pinfo, tree, hf_inap_rep);
}


static const value_string inap_T_rproblem_vals[] = {
  {   0, "gp" },
  {   1, "ip" },
  {   2, "rrp" },
  {   3, "rep" },
  { 0, NULL }
};

static const ber_choice_t T_rproblem_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gp_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ip_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_rrp_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_rep_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_T_rproblem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_rproblem_choice, hf_index, ett_inap_T_rproblem,
                                 NULL);

  return offset;
}
static int dissect_rproblem(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_T_rproblem(FALSE, tvb, offset, pinfo, tree, hf_inap_rproblem);
}


static const ber_sequence_t RejectPDU_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_rinvokeID },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_rproblem },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_RejectPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   RejectPDU_sequence, hf_index, ett_inap_RejectPDU);

  return offset;
}


/*--- End of included file: packet-inap-fn.c ---*/



const value_string inap_opr_code_strings[] = {

{16, "AssistRequestInstructions"},
{44, "CallInformationReport"},
{45, "CallInformationRequest"},
{53, "Cancel"},
{20, "Connect"},
{18, "DisconnectForwardConnection"},
	{19,"ConnectToResource"},
	{17,"EstablishTemporaryConnection"},
	{24,"EventReportBCSM"},
	{34,"FurnishChargingInformation"},
	{0,"InitialDP"},
	{47,"PlayAnnouncement"},
	{48,"PromptAndCollectUserInformation"},
	{99,"ReceivedInformation"}, /*???????*/
	{33,"ResetTimer"},
	{23,"RequestReportBCSMEvent"},
	{49,"SpecializedResourceReport"},
	{22,"ReleaseCall"},
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
{0, NULL}
};

const value_string inap_general_problem_strings[] = {
{0,"General Problem Unrecognized Component"},
{1,"General Problem Mistyped Component"},
{3,"General Problem Badly Structured Component"},
{0, NULL}
};



static guint32 opcode=0;

static int
dissect_inap_Opcode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_index, &opcode);

  if (check_col(pinfo->cinfo, COL_INFO)){
    col_set_str(pinfo->cinfo, COL_INFO, val_to_str(opcode, inap_opr_code_strings, "Unknown Inap (%u)"));
  }

  return offset;
}



static int
dissect_inap_errorCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_index, &opcode);

  if (check_col(pinfo->cinfo, COL_INFO)){
    col_set_str(pinfo->cinfo, COL_INFO, val_to_str(opcode, inap_error_code_strings, "Unknown Inap (%u)"));
  }

  return offset;
}


static int dissect_invokeData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  switch(opcode){
  case  16: /*AssistRequestInstructions*/
    offset=dissect_inap_AssistRequestInstructionsarg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case  44: /*CallInformationReport*/
    offset=dissect_inap_CallInformationReportarg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case  45: /*CallInformationRequest*/
    offset=dissect_inap_CallInformationRequestarg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case  53: /*Cancel*/
    offset=dissect_inap_Cancelarg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case  20: /*Connect*/
    offset=dissect_inap_Connectarg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case  18: /*DisconnectForwardConnections*/
    proto_tree_add_text(tree, tvb, offset, -1, "Disconnect Forward Connection");
    break;
  case  19: /*ConnectToResource*/
    offset=dissect_inap_ConnectToResource(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case  17: /*EstablishTemporaryConnection*/
    offset=dissect_inap_EstablishTemporaryConnection(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case  24: /*EventReportBCSM*/
    offset=dissect_inap_EventReportBCSM(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 34: /*FurnishChargingInformation*/
    offset=dissect_inap_FurnishChargingInformationarg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 0: /*InitialDP*/
    offset=dissect_inap_InitialDP(FALSE, tvb, offset, pinfo, tree, -1);
    break;
    
    case 23: /*InitialDP*/
    offset=dissect_inap_RequestReportBCSMEvent(FALSE, tvb, offset, pinfo, tree, -1);
    break;
 
  case 47: /*PlayAnnouncement*/
    offset=dissect_inap_PlayAnnouncement(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 48: /*PromptAndCollectUserInformation*/
    offset=dissect_inap_PromptAndCollectUserInformationarg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 33: /*ResetTimer*/
    offset=dissect_inap_ResetTimer(FALSE, tvb, offset, pinfo, tree, -1);
    break;
   case 22: /*ResetTimer*/
    offset=dissect_inap_ReleaseCallArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
   default:
    proto_tree_add_text(tree, tvb, offset, -1, "Unknown invokeData blob");
    /* todo call the asn.1 dissector */
  }
  return offset;
}


static int dissect_returnResultData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  switch(opcode){
   case 48: /*PromptAndCollectUserInformation*/
    offset=dissect_inap_PromptAndCollectUserInformationres(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  default:
    proto_tree_add_text(tree, tvb, offset, -1, "Unknown returnResultData blob");
  }
  return offset;
}

static int 
dissect_invokeCmd(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_Opcode(FALSE, tvb, offset, pinfo, tree, hf_inap_invokeCmd);
}


static int 
dissect_errorCode(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_errorCode(FALSE, tvb, offset, pinfo, tree, hf_inap_ReturnError);
}

static int dissect_invokeid(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_inap_invokeid, NULL);
}


static const value_string InvokeId_vals[] = {
  {   0, "invokeid" },
  {   1, "absent" },
  { 0, NULL }
};

static int dissect_absent(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_NULL(FALSE, tvb, offset, pinfo, tree, hf_inap_absent);
}


static const ber_choice_t InvokeId_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_invokeid },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_absent },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_inap_InvokeId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              InvokeId_choice, hf_index, ett_inap_InvokeId, NULL);

  return offset;
}
static int dissect_invokeId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_InvokeId(FALSE, tvb, offset, pinfo, tree, hf_inap_invokeId);
}

static const ber_sequence_t InvokePDU_sequence[] = {
  { BER_CLASS_UNI, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_invokeId },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_invokeCmd },
  { BER_CLASS_UNI, -1/*depends on Cmd*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_invokeData },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_InvokePDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                InvokePDU_sequence, hf_index, ett_inap_InvokePDU);

  return offset;
}


static const ber_sequence_t returnErrorPDU_sequence[] = {
  { BER_CLASS_UNI, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_invokeId },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_errorCode },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_returnErrorPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                returnErrorPDU_sequence, hf_index, ett_inap_ReturnErrorPDU);

  return offset;
}


static int dissect_invoke_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_InvokePDU(TRUE, tvb, offset, pinfo, tree, hf_inap_invoke);
}

static int dissect_returnError_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_returnErrorPDU(TRUE, tvb, offset, pinfo, tree, hf_inap_invoke);
}

static const ber_sequence_t ReturnResult_result_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_invokeCmd },
  { BER_CLASS_UNI, -1/*depends on Cmd*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_returnResultData },
  { 0, 0, 0, NULL }
};
static int
dissect_returnResult_result(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  offset = dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset,
                                ReturnResult_result_sequence, hf_inap_returnResult_result, ett_inap_ReturnResult_result);

  return offset;
}

static const ber_sequence_t ReturnResultPDU_sequence[] = {
  { BER_CLASS_UNI, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_invokeId },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_returnResult_result },
  { 0, 0, 0, NULL }
};

static int
dissect_inap_returnResultPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                ReturnResultPDU_sequence, hf_index, ett_inap_ReturnResultPDU);

  return offset;
}
static int dissect_returnResult_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_returnResultPDU(TRUE, tvb, offset, pinfo, tree, hf_inap_returnResult);
}


static int dissect_reject_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_inap_RejectPDU(TRUE, tvb, offset, pinfo, tree, -1);
}

static const value_string INAPPDU_vals[] = {
  {   1, "invoke" },
  {   2, "returnResult" },
  {   3, "returnError" },
  {   4, "reject" },
  { 0, NULL }
};

static const ber_choice_t INAPPDU_choice[] = {
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_invoke_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_returnResult_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_returnError_impl },
  {   4, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_reject_impl },
  { 0, 0, 0, 0, NULL }
};

static guint8 inap_pdu_type = 0;
static guint8 inap_pdu_size = 0;

static int
dissect_inap_INAPPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {

  inap_pdu_type = tvb_get_guint8(tvb, offset)&0x0f;
  /* Get the length and add 2 */
  inap_pdu_size = tvb_get_guint8(tvb, offset+1)+2;

  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              INAPPDU_choice, hf_index, ett_inap_INAPPDU, NULL);

  if (check_col(pinfo->cinfo, COL_INFO)){
    col_prepend_fstr(pinfo->cinfo, COL_INFO, val_to_str(opcode, inap_opr_code_strings, "Unknown INAP (%u)"));
  }

  return offset;
}




static void
dissect_inap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
    proto_item		*item=NULL;
    proto_tree		*tree=NULL;


    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "INAP");
    }

    /* create display subtree for the protocol */
    if(parent_tree){
       item = proto_tree_add_item(parent_tree, proto_inap, tvb, 0, -1, FALSE);
       tree = proto_item_add_subtree(item, ett_inap);
    }

    dissect_inap_INAPPDU(FALSE, tvb, 0, pinfo, tree, -1);


}

/*--- proto_reg_handoff_inap ---------------------------------------*/
void proto_reg_handoff_inap(void) {
    dissector_handle_t	inap_handle;
	static int inap_prefs_initialized = FALSE;
    
    inap_handle = create_dissector_handle(dissect_inap, proto_inap);
	
	if (!inap_prefs_initialized) {
		inap_prefs_initialized = TRUE;
	}
	else {
		dissector_delete("tcap.itu_ssn", tcap_itu_ssn, inap_handle);
		dissector_delete("tcap.itu_ssn", tcap_itu_ssn1, inap_handle);
	}
	tcap_itu_ssn = global_tcap_itu_ssn;
	tcap_itu_ssn1 = global_tcap_itu_ssn1;
    dissector_add("tcap.itu_ssn", global_tcap_itu_ssn, inap_handle);
    dissector_add("tcap.itu_ssn", global_tcap_itu_ssn1, inap_handle);
   
}


void proto_register_inap(void) {
	module_t *inap_module;
  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_inap_invokeCmd,
      { "invokeCmd", "inap.invokeCmd",
        FT_UINT32, BASE_DEC, VALS(inap_opr_code_strings), 0,
        "InvokePDU/invokeCmd", HFILL }},
   { &hf_inap_ReturnError,
      { "ReturnError", "inap.ReturnError",
        FT_UINT32, BASE_DEC, VALS(inap_error_code_strings), 0,
        "InvokePDU/ReturnError", HFILL }},
     { &hf_inap_invokeid,
      { "invokeid", "inap.invokeid",
        FT_INT32, BASE_DEC, NULL, 0,
        "InvokeId/invokeid", HFILL }},
    { &hf_inap_absent,
      { "absent", "inap.absent",
        FT_NONE, BASE_NONE, NULL, 0,
        "InvokeId/absent", HFILL }},
    { &hf_inap_invokeId,
      { "invokeId", "inap.invokeId",
        FT_UINT32, BASE_DEC, VALS(InvokeId_vals), 0,
        "InvokePDU/invokeId", HFILL }},
    { &hf_inap_invoke,
      { "invoke", "inap.invoke",
        FT_NONE, BASE_NONE, NULL, 0,
        "INAPPDU/invoke", HFILL }},
    { &hf_inap_returnResult,
      { "returnResult", "inap.returnResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "INAPPDU/returnResult", HFILL }},
     


/*--- Included file: packet-inap-hfarr.c ---*/

    { &hf_inap_originalCallID,
      { "originalCallID", "inap.originalCallID",
        FT_INT32, BASE_DEC, NULL, 0,
        "AddPartyArg/originalCallID", HFILL }},
    { &hf_inap_destinationCallID,
      { "destinationCallID", "inap.destinationCallID",
        FT_INT32, BASE_DEC, NULL, 0,
        "AddPartyArg/destinationCallID", HFILL }},
    { &hf_inap_newLegID,
      { "newLegID", "inap.newLegID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "AttachArg/newLegID", HFILL }},
    { &hf_inap_correlationidentifier,
      { "correlationidentifier", "inap.correlationidentifier",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_CallPartyHandlingResultsArg_item,
      { "Item", "inap.CallPartyHandlingResultsArg_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallPartyHandlingResultsArg/_item", HFILL }},
    { &hf_inap_callID,
      { "callID", "inap.callID",
        FT_INT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_inap_targetCallID,
      { "targetCallID", "inap.targetCallID",
        FT_INT32, BASE_DEC, NULL, 0,
        "ChangePartiesArg/targetCallID", HFILL }},
    { &hf_inap_legToBeConnectedID,
      { "legToBeConnectedID", "inap.legToBeConnectedID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ChangePartiesArg/legToBeConnectedID", HFILL }},
    { &hf_inap_legToBeDetached,
      { "legToBeDetached", "inap.legToBeDetached",
        FT_BYTES, BASE_HEX, NULL, 0,
        "DetachArg/legToBeDetached", HFILL }},
    { &hf_inap_legID,
      { "legID", "inap.legID",
        FT_UINT32, BASE_DEC, VALS(inap_LegID_vals), 0,
        "", HFILL }},
    { &hf_inap_sendingSideID,
      { "sendingSideID", "inap.sendingSideID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_receivingSideID,
      { "receivingSideID", "inap.receivingSideID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_heldLegID,
      { "heldLegID", "inap.heldLegID",
        FT_UINT32, BASE_DEC, VALS(inap_LegID_vals), 0,
        "ReconnectArg/heldLegID", HFILL }},
    { &hf_inap_legToBeReleased,
      { "legToBeReleased", "inap.legToBeReleased",
        FT_UINT32, BASE_DEC, VALS(inap_LegID_vals), 0,
        "ReleaseCallPartyConnectionArg/legToBeReleased", HFILL }},
    { &hf_inap_releaseCause,
      { "releaseCause", "inap.releaseCause",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_legStatus,
      { "legStatus", "inap.legStatus",
        FT_UINT32, BASE_DEC, VALS(inap_LegStatus_vals), 0,
        "LegInformation/legStatus", HFILL }},
    { &hf_inap_VariableParts_item,
      { "Item", "inap.VariableParts_item",
        FT_UINT32, BASE_DEC, VALS(inap_VariableParts_item_vals), 0,
        "VariableParts/_item", HFILL }},
    { &hf_inap_integer,
      { "integer", "inap.integer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "VariableParts/_item/integer", HFILL }},
    { &hf_inap_number,
      { "number", "inap.number",
        FT_BYTES, BASE_HEX, NULL, 0,
        "VariableParts/_item/number", HFILL }},
    { &hf_inap_time,
      { "time", "inap.time",
        FT_BYTES, BASE_HEX, NULL, 0,
        "VariableParts/_item/time", HFILL }},
    { &hf_inap_date,
      { "date", "inap.date",
        FT_BYTES, BASE_HEX, NULL, 0,
        "VariableParts/_item/date", HFILL }},
    { &hf_inap_price,
      { "price", "inap.price",
        FT_BYTES, BASE_HEX, NULL, 0,
        "VariableParts/_item/price", HFILL }},
    { &hf_inap_elementaryMessageID,
      { "elementaryMessageID", "inap.elementaryMessageID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_inap_variableParts,
      { "variableParts", "inap.variableParts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "VariableMessage/variableParts", HFILL }},
    { &hf_inap_toneID,
      { "toneID", "inap.toneID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Tone/toneID", HFILL }},
    { &hf_inap_tduration,
      { "tduration", "inap.tduration",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Tone/tduration", HFILL }},
    { &hf_inap_messageContent,
      { "messageContent", "inap.messageContent",
        FT_STRING, BASE_NONE, NULL, 0,
        "Text/messageContent", HFILL }},
    { &hf_inap_attributes,
      { "attributes", "inap.attributes",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Text/attributes", HFILL }},
    { &hf_inap_text,
      { "text", "inap.text",
        FT_NONE, BASE_NONE, NULL, 0,
        "MessageID/text", HFILL }},
    { &hf_inap_elementaryMessageIDs,
      { "elementaryMessageIDs", "inap.elementaryMessageIDs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MessageID/elementaryMessageIDs", HFILL }},
    { &hf_inap_elementaryMessageIDs_item,
      { "Item", "inap.elementaryMessageIDs_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MessageID/elementaryMessageIDs/_item", HFILL }},
    { &hf_inap_variableMessage,
      { "variableMessage", "inap.variableMessage",
        FT_NONE, BASE_NONE, NULL, 0,
        "MessageID/variableMessage", HFILL }},
    { &hf_inap_inbandInfo,
      { "inbandInfo", "inap.inbandInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "InformationToSend/inbandInfo", HFILL }},
    { &hf_inap_messageID,
      { "messageID", "inap.messageID",
        FT_UINT32, BASE_DEC, VALS(inap_MessageID_vals), 0,
        "InformationToSend/inbandInfo/messageID", HFILL }},
    { &hf_inap_numberOfRepetitions,
      { "numberOfRepetitions", "inap.numberOfRepetitions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "InformationToSend/inbandInfo/numberOfRepetitions", HFILL }},
    { &hf_inap_mduration,
      { "mduration", "inap.mduration",
        FT_UINT32, BASE_DEC, NULL, 0,
        "InformationToSend/inbandInfo/mduration", HFILL }},
    { &hf_inap_interval,
      { "interval", "inap.interval",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_inap_tone,
      { "tone", "inap.tone",
        FT_NONE, BASE_NONE, NULL, 0,
        "InformationToSend/tone", HFILL }},
    { &hf_inap_displayInformation,
      { "displayInformation", "inap.displayInformation",
        FT_STRING, BASE_NONE, NULL, 0,
        "InformationToSend/displayInformation", HFILL }},
    { &hf_inap_dialledNumber,
      { "dialledNumber", "inap.dialledNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "FilteringCriteria/dialledNumber", HFILL }},
    { &hf_inap_callingLineID,
      { "callingLineID", "inap.callingLineID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "FilteringCriteria/callingLineID", HFILL }},
    { &hf_inap_serviceKey,
      { "serviceKey", "inap.serviceKey",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_inap_addressAndService,
      { "addressAndService", "inap.addressAndService",
        FT_NONE, BASE_NONE, NULL, 0,
        "FilteringCriteria/addressAndService", HFILL }},
    { &hf_inap_calledAddressValue,
      { "calledAddressValue", "inap.calledAddressValue",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_callingAddressValue,
      { "callingAddressValue", "inap.callingAddressValue",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_locationNumber,
      { "locationNumber", "inap.locationNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_Extensions_item,
      { "Item", "inap.Extensions_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "Extensions/_item", HFILL }},
    { &hf_inap_type,
      { "type", "inap.type",
        FT_INT32, BASE_DEC, NULL, 0,
        "Extensions/_item/type", HFILL }},
    { &hf_inap_criticality,
      { "criticality", "inap.criticality",
        FT_UINT32, BASE_DEC, VALS(inap_T_criticality_vals), 0,
        "Extensions/_item/criticality", HFILL }},
    { &hf_inap_value,
      { "value", "inap.value",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Extensions/_item/value", HFILL }},
    { &hf_inap_filteredCallTreatment,
      { "filteredCallTreatment", "inap.filteredCallTreatment",
        FT_NONE, BASE_NONE, NULL, 0,
        "ActivateServiceFilteringarg/filteredCallTreatment", HFILL }},
    { &hf_inap_sFBillingChargingCharacteristics,
      { "sFBillingChargingCharacteristics", "inap.sFBillingChargingCharacteristics",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ActivateServiceFilteringarg/filteredCallTreatment/sFBillingChargingCharacteristics", HFILL }},
    { &hf_inap_informationToSend,
      { "informationToSend", "inap.informationToSend",
        FT_UINT32, BASE_DEC, VALS(inap_InformationToSend_vals), 0,
        "", HFILL }},
    { &hf_inap_maximumNumberOfCounters,
      { "maximumNumberOfCounters", "inap.maximumNumberOfCounters",
        FT_INT32, BASE_DEC, NULL, 0,
        "ActivateServiceFilteringarg/filteredCallTreatment/maximumNumberOfCounters", HFILL }},
    { &hf_inap_filteringCharacteristics,
      { "filteringCharacteristics", "inap.filteringCharacteristics",
        FT_UINT32, BASE_DEC, VALS(inap_T_filteringCharacteristics_vals), 0,
        "ActivateServiceFilteringarg/filteringCharacteristics", HFILL }},
    { &hf_inap_numberOfCalls,
      { "numberOfCalls", "inap.numberOfCalls",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ActivateServiceFilteringarg/filteringCharacteristics/numberOfCalls", HFILL }},
    { &hf_inap_filteringTimeOut,
      { "filteringTimeOut", "inap.filteringTimeOut",
        FT_UINT32, BASE_DEC, VALS(inap_T_filteringTimeOut_vals), 0,
        "ActivateServiceFilteringarg/filteringTimeOut", HFILL }},
    { &hf_inap_aduration,
      { "aduration", "inap.aduration",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ActivateServiceFilteringarg/filteringTimeOut/aduration", HFILL }},
    { &hf_inap_stopTime,
      { "stopTime", "inap.stopTime",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ActivateServiceFilteringarg/filteringTimeOut/stopTime", HFILL }},
    { &hf_inap_filteringCriteria,
      { "filteringCriteria", "inap.filteringCriteria",
        FT_UINT32, BASE_DEC, VALS(inap_FilteringCriteria_vals), 0,
        "", HFILL }},
    { &hf_inap_startTime,
      { "startTime", "inap.startTime",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ActivateServiceFilteringarg/startTime", HFILL }},
    { &hf_inap_extensions,
      { "extensions", "inap.extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_inap_messageType,
      { "messageType", "inap.messageType",
        FT_UINT32, BASE_DEC, VALS(inap_T_messageType_vals), 0,
        "MiscCallInfo/messageType", HFILL }},
    { &hf_inap_dpAssignment,
      { "dpAssignment", "inap.dpAssignment",
        FT_UINT32, BASE_DEC, VALS(inap_T_dpAssignment_vals), 0,
        "MiscCallInfo/dpAssignment", HFILL }},
    { &hf_inap_miscCallInfo,
      { "miscCallInfo", "inap.miscCallInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_inap_triggerType,
      { "triggerType", "inap.triggerType",
        FT_UINT32, BASE_DEC, VALS(inap_TriggerType_vals), 0,
        "", HFILL }},
    { &hf_inap_RouteList_item,
      { "Item", "inap.RouteList_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "RouteList/_item", HFILL }},
    { &hf_inap_bearerCap,
      { "bearerCap", "inap.bearerCap",
        FT_BYTES, BASE_HEX, NULL, 0,
        "BearerCapability/bearerCap", HFILL }},
    { &hf_inap_tmr,
      { "tmr", "inap.tmr",
        FT_BYTES, BASE_HEX, NULL, 0,
        "BearerCapability/tmr", HFILL }},
    { &hf_inap_serviceAddressInformation,
      { "serviceAddressInformation", "inap.serviceAddressInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "DpSpecificCommonParameters/serviceAddressInformation", HFILL }},
    { &hf_inap_bearerCapability,
      { "bearerCapability", "inap.bearerCapability",
        FT_UINT32, BASE_DEC, VALS(inap_BearerCapability_vals), 0,
        "", HFILL }},
    { &hf_inap_calledPartyNumber,
      { "calledPartyNumber", "inap.calledPartyNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_callingPartyNumber,
      { "callingPartyNumber", "inap.callingPartyNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_callingPartysCategory,
      { "callingPartysCategory", "inap.callingPartysCategory",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_iPSSPCapabilities,
      { "iPSSPCapabilities", "inap.iPSSPCapabilities",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_iPAvailable,
      { "iPAvailable", "inap.iPAvailable",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_iSDNAccessRelatedInformation,
      { "iSDNAccessRelatedInformation", "inap.iSDNAccessRelatedInformation",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_cGEncountered,
      { "cGEncountered", "inap.cGEncountered",
        FT_UINT32, BASE_DEC, VALS(inap_CGEncountered_vals), 0,
        "", HFILL }},
    { &hf_inap_serviceProfileIdentifier,
      { "serviceProfileIdentifier", "inap.serviceProfileIdentifier",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_terminalType,
      { "terminalType", "inap.terminalType",
        FT_UINT32, BASE_DEC, VALS(inap_TerminalType_vals), 0,
        "", HFILL }},
    { &hf_inap_chargeNumber,
      { "chargeNumber", "inap.chargeNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_servingAreaID,
      { "servingAreaID", "inap.servingAreaID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "DpSpecificCommonParameters/servingAreaID", HFILL }},
    { &hf_inap_trunkGroupID,
      { "trunkGroupID", "inap.trunkGroupID",
        FT_INT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_inap_privateFacilityID,
      { "privateFacilityID", "inap.privateFacilityID",
        FT_INT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_inap_huntGroup,
      { "huntGroup", "inap.huntGroup",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_routeIndex,
      { "routeIndex", "inap.routeIndex",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_dpSpecificCommonParameters,
      { "dpSpecificCommonParameters", "inap.dpSpecificCommonParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_inap_dialledDigits,
      { "dialledDigits", "inap.dialledDigits",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_callingPartyBusinessGroupID,
      { "callingPartyBusinessGroupID", "inap.callingPartyBusinessGroupID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_callingPartySubaddress,
      { "callingPartySubaddress", "inap.callingPartySubaddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_callingFacilityGroup,
      { "callingFacilityGroup", "inap.callingFacilityGroup",
        FT_UINT32, BASE_DEC, VALS(inap_CallingFacilityGroup_vals), 0,
        "", HFILL }},
    { &hf_inap_callingFacilityGroupMember,
      { "callingFacilityGroupMember", "inap.callingFacilityGroupMember",
        FT_INT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_inap_originalCalledPartyID,
      { "originalCalledPartyID", "inap.originalCalledPartyID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_prefix,
      { "prefix", "inap.prefix",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_redirectingPartyID,
      { "redirectingPartyID", "inap.redirectingPartyID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_redirectionInformation,
      { "redirectionInformation", "inap.redirectionInformation",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_routeList,
      { "routeList", "inap.routeList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_inap_travellingClassMark,
      { "travellingClassMark", "inap.travellingClassMark",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_featureCode,
      { "featureCode", "inap.featureCode",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_accessCode,
      { "accessCode", "inap.accessCode",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_carrier,
      { "carrier", "inap.carrier",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_destinationRoutingAddress,
      { "destinationRoutingAddress", "inap.destinationRoutingAddress",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_inap_destinationRoutingAddress_item,
      { "Item", "inap.destinationRoutingAddress_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_alertingPattern,
      { "alertingPattern", "inap.alertingPattern",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_aChBillingChargingCharacteristics,
      { "aChBillingChargingCharacteristics", "inap.aChBillingChargingCharacteristics",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ApplyChargingarg/aChBillingChargingCharacteristics", HFILL }},
    { &hf_inap_partyToCharge,
      { "partyToCharge", "inap.partyToCharge",
        FT_UINT32, BASE_DEC, VALS(inap_PartyToCharge_vals), 0,
        "", HFILL }},
    { &hf_inap_correlationID,
      { "correlationID", "inap.correlationID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_gapCriteria,
      { "gapCriteria", "inap.gapCriteria",
        FT_UINT32, BASE_DEC, VALS(inap_T_gapCriteria_vals), 0,
        "CallGaparg/gapCriteria", HFILL }},
    { &hf_inap_gapOnService,
      { "gapOnService", "inap.gapOnService",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallGaparg/gapCriteria/gapOnService", HFILL }},
    { &hf_inap_dpCriteria,
      { "dpCriteria", "inap.dpCriteria",
        FT_UINT32, BASE_DEC, VALS(inap_T_dpCriteria_vals), 0,
        "CallGaparg/gapCriteria/gapOnService/dpCriteria", HFILL }},
    { &hf_inap_calledAddressAndService,
      { "calledAddressAndService", "inap.calledAddressAndService",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallGaparg/gapCriteria/calledAddressAndService", HFILL }},
    { &hf_inap_callingAddressAndService,
      { "callingAddressAndService", "inap.callingAddressAndService",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallGaparg/gapCriteria/callingAddressAndService", HFILL }},
    { &hf_inap_gapIndicators,
      { "gapIndicators", "inap.gapIndicators",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallGaparg/gapIndicators", HFILL }},
    { &hf_inap_cgduration,
      { "cgduration", "inap.cgduration",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CallGaparg/gapIndicators/cgduration", HFILL }},
    { &hf_inap_gapInterval,
      { "gapInterval", "inap.gapInterval",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CallGaparg/gapIndicators/gapInterval", HFILL }},
    { &hf_inap_controlType,
      { "controlType", "inap.controlType",
        FT_UINT32, BASE_DEC, VALS(inap_T_controlType_vals), 0,
        "CallGaparg/controlType", HFILL }},
    { &hf_inap_gapTreatment,
      { "gapTreatment", "inap.gapTreatment",
        FT_UINT32, BASE_DEC, VALS(inap_T_gapTreatment_vals), 0,
        "CallGaparg/gapTreatment", HFILL }},
    { &hf_inap_both,
      { "both", "inap.both",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_inap_requestedInformationList,
      { "requestedInformationList", "inap.requestedInformationList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CallInformationReportarg/requestedInformationList", HFILL }},
    { &hf_inap_requestedInformationList_item,
      { "Item", "inap.requestedInformationList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallInformationReportarg/requestedInformationList/_item", HFILL }},
    { &hf_inap_requestedInformationType,
      { "requestedInformationType", "inap.requestedInformationType",
        FT_UINT32, BASE_DEC, VALS(inap_T_requestedInformationType_vals), 0,
        "CallInformationReportarg/requestedInformationList/_item/requestedInformationType", HFILL }},
    { &hf_inap_requestedInformationValue,
      { "requestedInformationValue", "inap.requestedInformationValue",
        FT_UINT32, BASE_DEC, VALS(inap_T_requestedInformationValue_vals), 0,
        "CallInformationReportarg/requestedInformationList/_item/requestedInformationValue", HFILL }},
    { &hf_inap_callAttemptElapsedTimeValue,
      { "callAttemptElapsedTimeValue", "inap.callAttemptElapsedTimeValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CallInformationReportarg/requestedInformationList/_item/requestedInformationValue/callAttemptElapsedTimeValue", HFILL }},
    { &hf_inap_callStopTimeValue,
      { "callStopTimeValue", "inap.callStopTimeValue",
        FT_BYTES, BASE_HEX, NULL, 0,
        "CallInformationReportarg/requestedInformationList/_item/requestedInformationValue/callStopTimeValue", HFILL }},
    { &hf_inap_callConnectedElapsedTimeValue,
      { "callConnectedElapsedTimeValue", "inap.callConnectedElapsedTimeValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CallInformationReportarg/requestedInformationList/_item/requestedInformationValue/callConnectedElapsedTimeValue", HFILL }},
    { &hf_inap_releaseCauseValue,
      { "releaseCauseValue", "inap.releaseCauseValue",
        FT_BYTES, BASE_HEX, NULL, 0,
        "CallInformationReportarg/requestedInformationList/_item/requestedInformationValue/releaseCauseValue", HFILL }},
    { &hf_inap_requestedInformationTypeList,
      { "requestedInformationTypeList", "inap.requestedInformationTypeList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CallInformationRequestarg/requestedInformationTypeList", HFILL }},
    { &hf_inap_requestedInformationTypeList_item,
      { "Item", "inap.requestedInformationTypeList_item",
        FT_UINT32, BASE_DEC, VALS(inap_T_requestedInformationTypeList_item_vals), 0,
        "CallInformationRequestarg/requestedInformationTypeList/_item", HFILL }},
    { &hf_inap_invokeID,
      { "invokeID", "inap.invokeID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Cancelarg/invokeID", HFILL }},
    { &hf_inap_allRequests,
      { "allRequests", "inap.allRequests",
        FT_NONE, BASE_NONE, NULL, 0,
        "Cancelarg/allRequests", HFILL }},
    { &hf_inap_lineID,
      { "lineID", "inap.lineID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_facilityGroupID,
      { "facilityGroupID", "inap.facilityGroupID",
        FT_UINT32, BASE_DEC, VALS(inap_FacilityGroupID_vals), 0,
        "", HFILL }},
    { &hf_inap_facilityGroupMemberID,
      { "facilityGroupMemberID", "inap.facilityGroupMemberID",
        FT_INT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_inap_resourceID,
      { "resourceID", "inap.resourceID",
        FT_UINT32, BASE_DEC, VALS(inap_ResourceID_vals), 0,
        "", HFILL }},
    { &hf_inap_numberingPlan,
      { "numberingPlan", "inap.numberingPlan",
        FT_BYTES, BASE_HEX, NULL, 0,
        "CollectInformationarg/numberingPlan", HFILL }},
    { &hf_inap_cutAndPaste,
      { "cutAndPaste", "inap.cutAndPaste",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Connectarg/cutAndPaste", HFILL }},
    { &hf_inap_forwardingCondition,
      { "forwardingCondition", "inap.forwardingCondition",
        FT_UINT32, BASE_DEC, VALS(inap_T_forwardingCondition_vals), 0,
        "Connectarg/forwardingCondition", HFILL }},
    { &hf_inap_scfID,
      { "scfID", "inap.scfID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_serviceInteractionIndicators,
      { "serviceInteractionIndicators", "inap.serviceInteractionIndicators",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_resourceAddress,
      { "resourceAddress", "inap.resourceAddress",
        FT_UINT32, BASE_DEC, VALS(inap_T_resourceAddress_vals), 0,
        "ConnectToResource/resourceAddress", HFILL }},
    { &hf_inap_ipRoutingAddress,
      { "ipRoutingAddress", "inap.ipRoutingAddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ConnectToResource/resourceAddress/ipRoutingAddress", HFILL }},
    { &hf_inap_none,
      { "none", "inap.none",
        FT_NONE, BASE_NONE, NULL, 0,
        "ConnectToResource/resourceAddress/none", HFILL }},
    { &hf_inap_assistingSSPIPRoutingAddress,
      { "assistingSSPIPRoutingAddress", "inap.assistingSSPIPRoutingAddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "EstablishTemporaryConnection/assistingSSPIPRoutingAddress", HFILL }},
    { &hf_inap_eventTypeCharging,
      { "eventTypeCharging", "inap.eventTypeCharging",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_eventSpecificInformationCharging,
      { "eventSpecificInformationCharging", "inap.eventSpecificInformationCharging",
        FT_BYTES, BASE_HEX, NULL, 0,
        "EventNotificationChargingarg/eventSpecificInformationCharging", HFILL }},
    { &hf_inap_monitorMode,
      { "monitorMode", "inap.monitorMode",
        FT_UINT32, BASE_DEC, VALS(inap_MonitorMode_vals), 0,
        "", HFILL }},
    { &hf_inap_eventTypeBCSM,
      { "eventTypeBCSM", "inap.eventTypeBCSM",
        FT_UINT32, BASE_DEC, VALS(inap_EventTypeBCSM_vals), 0,
        "", HFILL }},
    { &hf_inap_bcsmEventCorrelationID,
      { "bcsmEventCorrelationID", "inap.bcsmEventCorrelationID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_eventSpecificInformationBCSM,
      { "eventSpecificInformationBCSM", "inap.eventSpecificInformationBCSM",
        FT_UINT32, BASE_DEC, VALS(inap_T_eventSpecificInformationBCSM_vals), 0,
        "EventReportBCSM/eventSpecificInformationBCSM", HFILL }},
    { &hf_inap_collectedInfoSpecificInfo,
      { "collectedInfoSpecificInfo", "inap.collectedInfoSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventReportBCSM/eventSpecificInformationBCSM/collectedInfoSpecificInfo", HFILL }},
    { &hf_inap_calledPartynumber,
      { "calledPartynumber", "inap.calledPartynumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_analyzedInfoSpecificInfo,
      { "analyzedInfoSpecificInfo", "inap.analyzedInfoSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventReportBCSM/eventSpecificInformationBCSM/analyzedInfoSpecificInfo", HFILL }},
    { &hf_inap_routeSelectFailureSpecificInfo,
      { "routeSelectFailureSpecificInfo", "inap.routeSelectFailureSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventReportBCSM/eventSpecificInformationBCSM/routeSelectFailureSpecificInfo", HFILL }},
    { &hf_inap_failureCause,
      { "failureCause", "inap.failureCause",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_oCalledPartyBusySpecificInfo,
      { "oCalledPartyBusySpecificInfo", "inap.oCalledPartyBusySpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventReportBCSM/eventSpecificInformationBCSM/oCalledPartyBusySpecificInfo", HFILL }},
    { &hf_inap_busyCause,
      { "busyCause", "inap.busyCause",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_oNoAnswerSpecificInfo,
      { "oNoAnswerSpecificInfo", "inap.oNoAnswerSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventReportBCSM/eventSpecificInformationBCSM/oNoAnswerSpecificInfo", HFILL }},
    { &hf_inap_oAnswerSpecificInfo,
      { "oAnswerSpecificInfo", "inap.oAnswerSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventReportBCSM/eventSpecificInformationBCSM/oAnswerSpecificInfo", HFILL }},
    { &hf_inap_oMidCallSpecificInfo,
      { "oMidCallSpecificInfo", "inap.oMidCallSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventReportBCSM/eventSpecificInformationBCSM/oMidCallSpecificInfo", HFILL }},
    { &hf_inap_connectTime,
      { "connectTime", "inap.connectTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_inap_oDisconnectSpecificInfo,
      { "oDisconnectSpecificInfo", "inap.oDisconnectSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventReportBCSM/eventSpecificInformationBCSM/oDisconnectSpecificInfo", HFILL }},
    { &hf_inap_tBusySpecificInfo,
      { "tBusySpecificInfo", "inap.tBusySpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventReportBCSM/eventSpecificInformationBCSM/tBusySpecificInfo", HFILL }},
    { &hf_inap_tNoAnswerSpecificInfo,
      { "tNoAnswerSpecificInfo", "inap.tNoAnswerSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventReportBCSM/eventSpecificInformationBCSM/tNoAnswerSpecificInfo", HFILL }},
    { &hf_inap_tAnswerSpecificInfo,
      { "tAnswerSpecificInfo", "inap.tAnswerSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventReportBCSM/eventSpecificInformationBCSM/tAnswerSpecificInfo", HFILL }},
    { &hf_inap_tMidCallSpecificInfo,
      { "tMidCallSpecificInfo", "inap.tMidCallSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventReportBCSM/eventSpecificInformationBCSM/tMidCallSpecificInfo", HFILL }},
    { &hf_inap_tDisconnectSpecificInfo,
      { "tDisconnectSpecificInfo", "inap.tDisconnectSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "EventReportBCSM/eventSpecificInformationBCSM/tDisconnectSpecificInfo", HFILL }},
    { &hf_inap_holdcause,
      { "holdcause", "inap.holdcause",
        FT_BYTES, BASE_HEX, NULL, 0,
        "HoldCallInNetworkarg/holdcause", HFILL }},
    { &hf_inap_empty,
      { "empty", "inap.empty",
        FT_NONE, BASE_NONE, NULL, 0,
        "HoldCallInNetworkarg/empty", HFILL }},
    { &hf_inap_highLayerCompatibility,
      { "highLayerCompatibility", "inap.highLayerCompatibility",
        FT_BYTES, BASE_HEX, NULL, 0,
        "InitialDP/highLayerCompatibility", HFILL }},
    { &hf_inap_additionalCallingPartyNumber,
      { "additionalCallingPartyNumber", "inap.additionalCallingPartyNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "InitialDP/additionalCallingPartyNumber", HFILL }},
    { &hf_inap_forwardCallIndicators,
      { "forwardCallIndicators", "inap.forwardCallIndicators",
        FT_BYTES, BASE_HEX, NULL, 0,
        "InitialDP/forwardCallIndicators", HFILL }},
    { &hf_inap_calledPartyBusinessGroupID,
      { "calledPartyBusinessGroupID", "inap.calledPartyBusinessGroupID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_calledPartySubaddress,
      { "calledPartySubaddress", "inap.calledPartySubaddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_inap_featureRequestIndicator,
      { "featureRequestIndicator", "inap.featureRequestIndicator",
        FT_UINT32, BASE_DEC, VALS(inap_FeatureRequestIndicator_vals), 0,
        "", HFILL }},
    { &hf_inap_disconnectFromIPForbidden,
      { "disconnectFromIPForbidden", "inap.disconnectFromIPForbidden",
        FT_BOOLEAN, 8, NULL, 0,
        "", HFILL }},
    { &hf_inap_requestAnnouncementComplete,
      { "requestAnnouncementComplete", "inap.requestAnnouncementComplete",
        FT_BOOLEAN, 8, NULL, 0,
        "PlayAnnouncement/requestAnnouncementComplete", HFILL }},
    { &hf_inap_collectedInfo,
      { "collectedInfo", "inap.collectedInfo",
        FT_UINT32, BASE_DEC, VALS(inap_T_collectedInfo_vals), 0,
        "PromptAndCollectUserInformationarg/collectedInfo", HFILL }},
    { &hf_inap_collectedDigits,
      { "collectedDigits", "inap.collectedDigits",
        FT_NONE, BASE_NONE, NULL, 0,
        "PromptAndCollectUserInformationarg/collectedInfo/collectedDigits", HFILL }},
    { &hf_inap_minimumNbOfDigits,
      { "minimumNbOfDigits", "inap.minimumNbOfDigits",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PromptAndCollectUserInformationarg/collectedInfo/collectedDigits/minimumNbOfDigits", HFILL }},
    { &hf_inap_maximumNbOfDigits,
      { "maximumNbOfDigits", "inap.maximumNbOfDigits",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PromptAndCollectUserInformationarg/collectedInfo/collectedDigits/maximumNbOfDigits", HFILL }},
    { &hf_inap_endOfReplyDigit,
      { "endOfReplyDigit", "inap.endOfReplyDigit",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PromptAndCollectUserInformationarg/collectedInfo/collectedDigits/endOfReplyDigit", HFILL }},
    { &hf_inap_cancelDigit,
      { "cancelDigit", "inap.cancelDigit",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PromptAndCollectUserInformationarg/collectedInfo/collectedDigits/cancelDigit", HFILL }},
    { &hf_inap_startDigit,
      { "startDigit", "inap.startDigit",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PromptAndCollectUserInformationarg/collectedInfo/collectedDigits/startDigit", HFILL }},
    { &hf_inap_firstDigitTimeOut,
      { "firstDigitTimeOut", "inap.firstDigitTimeOut",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PromptAndCollectUserInformationarg/collectedInfo/collectedDigits/firstDigitTimeOut", HFILL }},
    { &hf_inap_interDigitTimeOut,
      { "interDigitTimeOut", "inap.interDigitTimeOut",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PromptAndCollectUserInformationarg/collectedInfo/collectedDigits/interDigitTimeOut", HFILL }},
    { &hf_inap_errorTreatment,
      { "errorTreatment", "inap.errorTreatment",
        FT_UINT32, BASE_DEC, VALS(inap_T_errorTreatment_vals), 0,
        "PromptAndCollectUserInformationarg/collectedInfo/collectedDigits/errorTreatment", HFILL }},
    { &hf_inap_interruptableAnnInd,
      { "interruptableAnnInd", "inap.interruptableAnnInd",
        FT_BOOLEAN, 8, NULL, 0,
        "PromptAndCollectUserInformationarg/collectedInfo/collectedDigits/interruptableAnnInd", HFILL }},
    { &hf_inap_voiceInformation,
      { "voiceInformation", "inap.voiceInformation",
        FT_BOOLEAN, 8, NULL, 0,
        "PromptAndCollectUserInformationarg/collectedInfo/collectedDigits/voiceInformation", HFILL }},
    { &hf_inap_voiceBack,
      { "voiceBack", "inap.voiceBack",
        FT_BOOLEAN, 8, NULL, 0,
        "PromptAndCollectUserInformationarg/collectedInfo/collectedDigits/voiceBack", HFILL }},
    { &hf_inap_iA5Information,
      { "iA5Information", "inap.iA5Information",
        FT_BOOLEAN, 8, NULL, 0,
        "PromptAndCollectUserInformationarg/collectedInfo/iA5Information", HFILL }},
    { &hf_inap_digitsResponse,
      { "digitsResponse", "inap.digitsResponse",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PromptAndCollectUserInformationres/digitsResponse", HFILL }},
    { &hf_inap_iA5Response,
      { "iA5Response", "inap.iA5Response",
        FT_STRING, BASE_NONE, NULL, 0,
        "PromptAndCollectUserInformationres/iA5Response", HFILL }},
    { &hf_inap_initialCallSegment,
      { "initialCallSegment", "inap.initialCallSegment",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ReleaseCallArg/initialCallSegment", HFILL }},
    { &hf_inap_allCallSegments,
      { "allCallSegments", "inap.allCallSegments",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReleaseCallArg/allCallSegments", HFILL }},
    { &hf_inap_resourceStatus,
      { "resourceStatus", "inap.resourceStatus",
        FT_UINT32, BASE_DEC, VALS(inap_ResourceStatus_vals), 0,
        "", HFILL }},
    { &hf_inap_monitorDuration,
      { "monitorDuration", "inap.monitorDuration",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_inap_RequestNotificationChargingEvent_item,
      { "Item", "inap.RequestNotificationChargingEvent_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestNotificationChargingEvent/_item", HFILL }},
    { &hf_inap_bcsmEvents,
      { "bcsmEvents", "inap.bcsmEvents",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RequestReportBCSMEvent/bcsmEvents", HFILL }},
    { &hf_inap_bcsmEvents_item,
      { "Item", "inap.bcsmEvents_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestReportBCSMEvent/bcsmEvents/_item", HFILL }},
    { &hf_inap_dpSpecificCriteria,
      { "dpSpecificCriteria", "inap.dpSpecificCriteria",
        FT_UINT32, BASE_DEC, VALS(inap_T_dpSpecificCriteria_vals), 0,
        "RequestReportBCSMEvent/bcsmEvents/_item/dpSpecificCriteria", HFILL }},
    { &hf_inap_numberOfDigits,
      { "numberOfDigits", "inap.numberOfDigits",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RequestReportBCSMEvent/bcsmEvents/_item/dpSpecificCriteria/numberOfDigits", HFILL }},
    { &hf_inap_applicationTimer,
      { "applicationTimer", "inap.applicationTimer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RequestReportBCSMEvent/bcsmEvents/_item/dpSpecificCriteria/applicationTimer", HFILL }},
    { &hf_inap_timerID,
      { "timerID", "inap.timerID",
        FT_UINT32, BASE_DEC, VALS(inap_T_timerID_vals), 0,
        "ResetTimer/timerID", HFILL }},
    { &hf_inap_timervalue,
      { "timervalue", "inap.timervalue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ResetTimer/timervalue", HFILL }},
    { &hf_inap_destinationNumberRoutingAddress,
      { "destinationNumberRoutingAddress", "inap.destinationNumberRoutingAddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SelectFacility/destinationNumberRoutingAddress", HFILL }},
    { &hf_inap_calledFacilityGroup,
      { "calledFacilityGroup", "inap.calledFacilityGroup",
        FT_UINT32, BASE_DEC, VALS(inap_CalledFacilityGroup_vals), 0,
        "", HFILL }},
    { &hf_inap_calledFacilityGroupMember,
      { "calledFacilityGroupMember", "inap.calledFacilityGroupMember",
        FT_INT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_inap_sCIBillingChargingCharacteristics,
      { "sCIBillingChargingCharacteristics", "inap.sCIBillingChargingCharacteristics",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SendChargingInformation/sCIBillingChargingCharacteristics", HFILL }},
    { &hf_inap_countersValue,
      { "countersValue", "inap.countersValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ServiceFilteringResponse/countersValue", HFILL }},
    { &hf_inap_countersValue_item,
      { "Item", "inap.countersValue_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServiceFilteringResponse/countersValue/_item", HFILL }},
    { &hf_inap_counterID,
      { "counterID", "inap.counterID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ServiceFilteringResponse/countersValue/_item/counterID", HFILL }},
    { &hf_inap_counterValue,
      { "counterValue", "inap.counterValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ServiceFilteringResponse/countersValue/_item/counterValue", HFILL }},
    { &hf_inap_responseCondition,
      { "responseCondition", "inap.responseCondition",
        FT_UINT32, BASE_DEC, VALS(inap_T_responseCondition_vals), 0,
        "ServiceFilteringResponse/responseCondition", HFILL }},
    { &hf_inap_reportCondition,
      { "reportCondition", "inap.reportCondition",
        FT_UINT32, BASE_DEC, VALS(inap_T_reportCondition_vals), 0,
        "StatusReport/reportCondition", HFILL }},
    { &hf_inap_problem,
      { "problem", "inap.problem",
        FT_UINT32, BASE_DEC, VALS(inap_T_problem_vals), 0,
        "CancelFailed/problem", HFILL }},
    { &hf_inap_operation,
      { "operation", "inap.operation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CancelFailed/operation", HFILL }},
    { &hf_inap_rinvokeID,
      { "rinvokeID", "inap.rinvokeID",
        FT_UINT32, BASE_DEC, VALS(inap_T_rinvokeID_vals), 0,
        "RejectPDU/rinvokeID", HFILL }},
    { &hf_inap_invidtype,
      { "invidtype", "inap.invidtype",
        FT_INT32, BASE_DEC, NULL, 0,
        "RejectPDU/rinvokeID/invidtype", HFILL }},
    { &hf_inap_null,
      { "null", "inap.null",
        FT_NONE, BASE_NONE, NULL, 0,
        "RejectPDU/rinvokeID/null", HFILL }},
    { &hf_inap_rproblem,
      { "rproblem", "inap.rproblem",
        FT_UINT32, BASE_DEC, VALS(inap_T_rproblem_vals), 0,
        "RejectPDU/rproblem", HFILL }},
    { &hf_inap_gp,
      { "gp", "inap.gp",
        FT_INT32, BASE_DEC, VALS(inap_GeneralProblem_vals), 0,
        "RejectPDU/rproblem/gp", HFILL }},
    { &hf_inap_ip,
      { "ip", "inap.ip",
        FT_INT32, BASE_DEC, VALS(inap_InvokeProblem_vals), 0,
        "RejectPDU/rproblem/ip", HFILL }},
    { &hf_inap_rrp,
      { "rrp", "inap.rrp",
        FT_INT32, BASE_DEC, VALS(inap_ReturnResultProblem_vals), 0,
        "RejectPDU/rproblem/rrp", HFILL }},
    { &hf_inap_rep,
      { "rep", "inap.rep",
        FT_INT32, BASE_DEC, VALS(inap_ReturnErrorProblem_vals), 0,
        "RejectPDU/rproblem/rep", HFILL }},

/*--- End of included file: packet-inap-hfarr.c ---*/

  };






  /* List of subtrees */
  static gint *ett[] = {
    &ett_inap,
    &ett_inap_InvokeId,
    &ett_inap_InvokePDU,
    &ett_inap_ReturnErrorPDU,
    &ett_inap_ReturnResultPDU,
    &ett_inap_ReturnResult_result,
    &ett_inap_INAPPDU,
    &ett_inapisup_parameter,

/*--- Included file: packet-inap-ettarr.c ---*/

    &ett_inap_AddPartyArg,
    &ett_inap_AttachArg,
    &ett_inap_CallPartyHandlingResultsArg,
    &ett_inap_ChangePartiesArg,
    &ett_inap_DetachArg,
    &ett_inap_HoldCallPartyConnectionArg,
    &ett_inap_LegID,
    &ett_inap_ReconnectArg,
    &ett_inap_ReleaseCallPartyConnectionArg,
    &ett_inap_LegInformation,
    &ett_inap_VariableParts,
    &ett_inap_VariableParts_item,
    &ett_inap_VariableMessage,
    &ett_inap_Tone,
    &ett_inap_Text,
    &ett_inap_MessageID,
    &ett_inap_T_elementaryMessageIDs,
    &ett_inap_InformationToSend,
    &ett_inap_T_inbandInfo,
    &ett_inap_FilteringCriteria,
    &ett_inap_T_addressAndService,
    &ett_inap_Extensions,
    &ett_inap_Extensions_item,
    &ett_inap_ActivateServiceFilteringarg,
    &ett_inap_T_filteredCallTreatment,
    &ett_inap_T_filteringCharacteristics,
    &ett_inap_T_filteringTimeOut,
    &ett_inap_MiscCallInfo,
    &ett_inap_ServiceAddressInformation,
    &ett_inap_RouteList,
    &ett_inap_BearerCapability,
    &ett_inap_DpSpecificCommonParameters,
    &ett_inap_CallingFacilityGroup,
    &ett_inap_AnalysedInformationarg,
    &ett_inap_AnalyseInformationarg,
    &ett_inap_SEQUENCE_SIZE_1_3_OF_DestinationAddress,
    &ett_inap_PartyToCharge,
    &ett_inap_ApplyChargingarg,
    &ett_inap_AssistRequestInstructionsarg,
    &ett_inap_CallGaparg,
    &ett_inap_T_gapCriteria,
    &ett_inap_T_gapOnService,
    &ett_inap_T_calledAddressAndService,
    &ett_inap_T_callingAddressAndService,
    &ett_inap_T_gapIndicators,
    &ett_inap_T_gapTreatment,
    &ett_inap_Both,
    &ett_inap_CallInformationReportarg,
    &ett_inap_T_requestedInformationList,
    &ett_inap_T_requestedInformationList_item,
    &ett_inap_T_requestedInformationValue,
    &ett_inap_CallInformationRequestarg,
    &ett_inap_T_requestedInformationTypeList,
    &ett_inap_Cancelarg,
    &ett_inap_FacilityGroupID,
    &ett_inap_ResourceID,
    &ett_inap_CancelStatusReportRequestarg,
    &ett_inap_CollectedInformationarg,
    &ett_inap_CollectInformationarg,
    &ett_inap_Connectarg,
    &ett_inap_ConnectToResource,
    &ett_inap_T_resourceAddress,
    &ett_inap_EstablishTemporaryConnection,
    &ett_inap_EventNotificationChargingarg,
    &ett_inap_EventReportBCSM,
    &ett_inap_T_eventSpecificInformationBCSM,
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
    &ett_inap_HoldCallInNetworkarg,
    &ett_inap_InitialDP,
    &ett_inap_InitiateCallAttempt,
    &ett_inap_OAnswer,
    &ett_inap_OCalledPartyBusy,
    &ett_inap_ODisconnect,
    &ett_inap_OMidCall,
    &ett_inap_ONoAnswer,
    &ett_inap_OriginationAttemptAuthorized,
    &ett_inap_PlayAnnouncement,
    &ett_inap_PromptAndCollectUserInformationarg,
    &ett_inap_T_collectedInfo,
    &ett_inap_T_collectedDigits,
    &ett_inap_PromptAndCollectUserInformationres,
    &ett_inap_ReleaseCallArg,
    &ett_inap_T_allCallSegments,
    &ett_inap_RequestCurrentStatusReportarg,
    &ett_inap_RequestCurrentStatusReportres,
    &ett_inap_RequestEveryStatusChangeReport,
    &ett_inap_RequestFirstStatusMatchReport,
    &ett_inap_RequestNotificationChargingEvent,
    &ett_inap_RequestNotificationChargingEvent_item,
    &ett_inap_RequestReportBCSMEvent,
    &ett_inap_T_bcsmEvents,
    &ett_inap_T_bcsmEvents_item,
    &ett_inap_T_dpSpecificCriteria,
    &ett_inap_ResetTimer,
    &ett_inap_RouteSelectFailure,
    &ett_inap_CalledFacilityGroup,
    &ett_inap_SelectFacility,
    &ett_inap_SelectRoute,
    &ett_inap_SendChargingInformation,
    &ett_inap_ServiceFilteringResponse,
    &ett_inap_T_countersValue,
    &ett_inap_T_countersValue_item,
    &ett_inap_StatusReport,
    &ett_inap_TAnswer,
    &ett_inap_TBusy,
    &ett_inap_TDisconnect,
    &ett_inap_TermAttemptAuthorized,
    &ett_inap_TMidCall,
    &ett_inap_TNoAnswer,
    &ett_inap_CancelFailed,
    &ett_inap_RejectPDU,
    &ett_inap_T_rinvokeID,
    &ett_inap_T_rproblem,

/*--- End of included file: packet-inap-ettarr.c ---*/

  };

  /* Register protocol */
  proto_inap = proto_register_protocol(PNAME, PSNAME, PFNAME);
/*XXX  register_dissector("inap", dissect_inap, proto_inap);*/
  /* Register fields and subtrees */
  proto_register_field_array(proto_inap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  
  
  inap_module = prefs_register_protocol(proto_inap, proto_reg_handoff_inap);
  
  prefs_register_uint_preference(inap_module, "tcap.itu_ssn",
		"Subsystem number used for INAP",
		"Set Subsystem number used for INAP",
		10, &global_tcap_itu_ssn);

 prefs_register_uint_preference(inap_module, "tcap.itu_ssn1",
		"Subsystem number used for INAP",
		"Set Subsystem number used for INAP",
		10, &global_tcap_itu_ssn1);

}



