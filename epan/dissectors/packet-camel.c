/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* .\packet-camel.c                                                           */
/* ../../tools/asn2wrs.py -b -X -e -p camel -c camel.cnf -s packet-camel-template camel.asn */

/* Input file: packet-camel-template.c */

#line 1 "packet-camel-template.c"
/* packet-camel-template.c
 * Routines for Camel
 * Copyright 2004, Tim Endean <endeant@hotmail.com>
 * Copyright 2005, Olivier Jacques <olivier.jacques@hp.com>
 * Copyright 2005, Javier Acu«Òa <javier.acuna@sixbell.com>
 * Updated to ETSI TS 129 078 V6.4.0 (2004-3GPP TS 29.078 version 6.4.0 Release 6 1 12)
 * Copyright 2005-2006, Anders Broman <anders.broman@ericsson.com>
 * Updated to 3GPP TS 29.078 version 7.3.0 Release 7 (2006-06)
 * Built from the gsm-map dissector Copyright 2004, Anders Broman <anders.broman@ericsson.com>
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
 * References: ETSI 300 374
 */
/* 
 * Indentation logic: this file is indented with 2 spaces indentation. 
 *                    there are no tabs.
 */
#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/oid_resolv.h>
#include <epan/tap.h>
#include <epan/asn1.h>
#include "epan/expert.h"

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-camel.h"
#include "packet-q931.h"
#include "packet-e164.h"
#include "packet-isup.h"
#include "packet-gsm_map.h"
#include "packet-gsm_a.h"
#include "packet-tcap.h"
#include "epan/camel-persistentdata.h"
#include "epan/tcap-persistentdata.h"

#define PNAME  "Camel"
#define PSNAME "CAMEL"
#define PFNAME "camel"

/* Initialize the protocol and registered fields */
int proto_camel = -1;
int date_format = 1; /*assume european date format */
int camel_tap = -1;
/* Global variables */
static guint32 opcode=0;
static guint32 errorCode=0;


static int hf_digit = -1; 
static int hf_camel_addr_extension = -1;
static int hf_camel_addr_natureOfAddressIndicator = -1;
static int hf_camel_addr_numberingPlanInd = -1;
static int hf_camel_addr_digits = -1;
static int hf_camel_cause_indicator = -1;
static int hf_camel_PDPTypeNumber_etsi = -1;
static int hf_camel_PDPTypeNumber_ietf = -1;
static int hf_camel_PDPAddress_IPv4 = -1;
static int hf_camel_PDPAddress_IPv6 = -1;
static int hf_camel_cellGlobalIdOrServiceAreaIdFixedLength = -1;
static int hf_camel_RP_Cause = -1;

/* Used by camel-persistentdata.c */
int hf_camelsrt_SessionId=-1;
int hf_camelsrt_RequestNumber=-1;
int hf_camelsrt_Duplicate=-1;
int hf_camelsrt_RequestFrame=-1;
int hf_camelsrt_ResponseFrame=-1;
int hf_camelsrt_DeltaTime=-1;
int hf_camelsrt_SessionTime=-1;
int hf_camelsrt_DeltaTime31=-1;
int hf_camelsrt_DeltaTime75=-1;
int hf_camelsrt_DeltaTime65=-1;
int hf_camelsrt_DeltaTime22=-1;
int hf_camelsrt_DeltaTime35=-1;
int hf_camelsrt_DeltaTime80=-1;

static struct camelsrt_info_t * gp_camelsrt_info;

/* Forward declarations */
static int dissect_invokeData(proto_tree *tree, tvbuff_t *tvb, int offset,asn1_ctx_t *actx);
static int dissect_returnResultData(proto_tree *tree, tvbuff_t *tvb, int offset,asn1_ctx_t *actx);
static int dissect_returnErrorData(proto_tree *tree, tvbuff_t *tvb, int offset,asn1_ctx_t *actx);



/*--- Included file: packet-camel-hf.c ---*/
#line 1 "packet-camel-hf.c"
static int hf_camel_Component_PDU = -1;           /* Component */
static int hf_camel_invoke = -1;                  /* Invoke */
static int hf_camel_returnResultLast = -1;        /* ReturnResult */
static int hf_camel_returnError = -1;             /* ReturnError */
static int hf_camel_reject = -1;                  /* Reject */
static int hf_camel_invokeID = -1;                /* InvokeIdType */
static int hf_camel_linkedID = -1;                /* InvokeIdType */
static int hf_camel_opCode = -1;                  /* OPERATION */
static int hf_camel_invokeparameter = -1;         /* InvokeParameter */
static int hf_camel_resultretres = -1;            /* T_resultretres */
static int hf_camel_returnparameter = -1;         /* ReturnResultParameter */
static int hf_camel_errorCode = -1;               /* ERROR */
static int hf_camel_parameter = -1;               /* ReturnErrorParameter */
static int hf_camel_invokeIDRej = -1;             /* T_invokeIDRej */
static int hf_camel_derivable = -1;               /* InvokeIdType */
static int hf_camel_not_derivable = -1;           /* NULL */
static int hf_camel_problem = -1;                 /* T_problem */
static int hf_camel_generalProblem = -1;          /* GeneralProblem */
static int hf_camel_invokeProblem = -1;           /* InvokeProblem */
static int hf_camel_returnResultProblem = -1;     /* ReturnResultProblem */
static int hf_camel_returnErrorProblem = -1;      /* ReturnErrorProblem */
static int hf_camel_localValue = -1;              /* OperationLocalvalue */
static int hf_camel_globalValue = -1;             /* OBJECT_IDENTIFIER */
static int hf_camel_localErrorValue = -1;         /* LocalErrorcode */
static int hf_camel_globalErrorValue = -1;        /* OBJECT_IDENTIFIER */
static int hf_camel_actimeDurationCharging = -1;  /* T_actimeDurationCharging */
static int hf_camel_maxCallPeriodDuration = -1;   /* INTEGER_1_864000 */
static int hf_camel_releaseIfdurationExceeded = -1;  /* BOOLEAN */
static int hf_camel_tariffSwitchInterval = -1;    /* INTEGER_1_86400 */
static int hf_camel_actone = -1;                  /* BOOLEAN */
static int hf_camel_extensions = -1;              /* ExtensionsArray */
static int hf_camel_legID = -1;                   /* LegID */
static int hf_camel_srfConnection = -1;           /* CallSegmentID */
static int hf_camel_aOCInitial = -1;              /* CAI_Gsm0224 */
static int hf_camel_aOCSubsequent = -1;           /* AOCSubsequent */
static int hf_camel_cAI_GSM0224 = -1;             /* CAI_Gsm0224 */
static int hf_camel_istone = -1;                  /* BOOLEAN */
static int hf_camel_burstList = -1;               /* BurstList */
static int hf_camel_conferenceTreatmentIndicator = -1;  /* OCTET_STRING_SIZE_1 */
static int hf_camel_callCompletionTreatmentIndicator = -1;  /* OCTET_STRING_SIZE_1 */
static int hf_camel_calledAddressValue = -1;      /* Digits */
static int hf_camel_gapOnService = -1;            /* GapOnService */
static int hf_camel_calledAddressAndService = -1;  /* T_calledAddressAndService */
static int hf_camel_serviceKey = -1;              /* ServiceKey */
static int hf_camel_callingAddressAndService = -1;  /* T_callingAddressAndService */
static int hf_camel_callingAddressValue = -1;     /* Digits */
static int hf_camel_eventTypeBCSM = -1;           /* EventTypeBCSM */
static int hf_camel_monitorMode = -1;             /* MonitorMode */
static int hf_camel_legID6 = -1;                  /* LegID */
static int hf_camel_dpSpecificCriteria = -1;      /* DpSpecificCriteria */
static int hf_camel_automaticRearm = -1;          /* NULL */
static int hf_camel_cause = -1;                   /* Cause */
static int hf_camel_bearerCap = -1;               /* BearerCap */
static int hf_camel_numberOfBursts = -1;          /* INTEGER_1_3 */
static int hf_camel_burstInterval = -1;           /* INTEGER_1_1200 */
static int hf_camel_numberOfTonesInBurst = -1;    /* INTEGER_1_3 */
static int hf_camel_toneDuration = -1;            /* INTEGER_1_20 */
static int hf_camel_toneInterval = -1;            /* INTEGER_1_20 */
static int hf_camel_warningPeriod = -1;           /* INTEGER_1_1200 */
static int hf_camel_bursts = -1;                  /* Burst */
static int hf_camel_e1 = -1;                      /* INTEGER_0_8191 */
static int hf_camel_e2 = -1;                      /* INTEGER_0_8191 */
static int hf_camel_e3 = -1;                      /* INTEGER_0_8191 */
static int hf_camel_e4 = -1;                      /* INTEGER_0_8191 */
static int hf_camel_e5 = -1;                      /* INTEGER_0_8191 */
static int hf_camel_e6 = -1;                      /* INTEGER_0_8191 */
static int hf_camel_e7 = -1;                      /* INTEGER_0_8191 */
static int hf_camel_callSegmentID = -1;           /* CallSegmentID */
static int hf_camel_callInvokeID = -1;            /* InvokeID */
static int hf_camel_timeDurationCharging = -1;    /* T_timeDurationCharging */
static int hf_camel_audibleIndicator = -1;        /* AudibleIndicator */
static int hf_camel_timeDurationChargingResult = -1;  /* TimeDurationChargingResult */
static int hf_camel_void = -1;                    /* NULL */
static int hf_camel_partyToCharge = -1;           /* ReceivingSideID */
static int hf_camel_timeInformation = -1;         /* TimeInformation */
static int hf_camel_legActive = -1;               /* BOOLEAN */
static int hf_camel_callLegReleasedAtTcpExpiry = -1;  /* NULL */
static int hf_camel_aChChargingAddress = -1;      /* AChChargingAddress */
static int hf_camel_fCIBCCCAMELsequence1 = -1;    /* T_fCIBCCCAMELsequence1 */
static int hf_camel_freeFormatData = -1;          /* FreeFormatData */
static int hf_camel_partyToCharge4 = -1;          /* SendingSideID */
static int hf_camel_appendFreeFormatData = -1;    /* AppendFreeFormatData */
static int hf_camel_fCIBCCCAMELsequence2 = -1;    /* T_fCIBCCCAMELsequence2 */
static int hf_camel_pDPID = -1;                   /* PDPId */
static int hf_camel_fCIBCCCAMELsequence3 = -1;    /* T_fCIBCCCAMELsequence3 */
static int hf_camel_aOCBeforeAnswer = -1;         /* AOCBeforeAnswer */
static int hf_camel_aOCAfterAnswer = -1;          /* AOCSubsequent */
static int hf_camel_aOC_extension = -1;           /* CAMEL_SCIBillingChargingCharacteristicsAlt */
static int hf_camel_aOCGPRS = -1;                 /* AOCGprs */
static int hf_camel_ChangeOfPositionControlInfo_item = -1;  /* ChangeOfLocation */
static int hf_camel_cellGlobalId = -1;            /* CellGlobalIdOrServiceAreaIdFixedLength */
static int hf_camel_serviceAreaId = -1;           /* CellGlobalIdOrServiceAreaIdFixedLength */
static int hf_camel_locationAreaId = -1;          /* LAIFixedLength */
static int hf_camel_inter_SystemHandOver = -1;    /* NULL */
static int hf_camel_inter_PLMNHandOver = -1;      /* NULL */
static int hf_camel_inter_MSCHandOver = -1;       /* NULL */
static int hf_camel_changeOfLocationAlt = -1;     /* ChangeOfLocationAlt */
static int hf_camel_maxTransferredVolume = -1;    /* INTEGER_1_4294967295 */
static int hf_camel_maxElapsedTime = -1;          /* INTEGER_1_86400 */
static int hf_camel_transferredVolume = -1;       /* TransferredVolume */
static int hf_camel_elapsedTime = -1;             /* ElapsedTime */
static int hf_camel_transferredVolumeRollOver = -1;  /* TransferredVolumeRollOver */
static int hf_camel_elapsedTimeRollOver = -1;     /* ElapsedTimeRollOver */
static int hf_camel_minimumNbOfDigits = -1;       /* INTEGER_1_30 */
static int hf_camel_maximumNbOfDigits = -1;       /* INTEGER_1_30 */
static int hf_camel_endOfReplyDigit = -1;         /* OCTET_STRING_SIZE_1_2 */
static int hf_camel_cancelDigit = -1;             /* OCTET_STRING_SIZE_1_2 */
static int hf_camel_startDigit = -1;              /* OCTET_STRING_SIZE_1_2 */
static int hf_camel_firstDigitTimeOut = -1;       /* INTEGER_1_127 */
static int hf_camel_interDigitTimeOut = -1;       /* INTEGER_1_127 */
static int hf_camel_errorTreatment = -1;          /* ErrorTreatment */
static int hf_camel_interruptableAnnInd = -1;     /* BOOLEAN */
static int hf_camel_voiceInformation = -1;        /* BOOLEAN */
static int hf_camel_voiceBack = -1;               /* BOOLEAN */
static int hf_camel_collectedDigits = -1;         /* CollectedDigits */
static int hf_camel_basicGapCriteria = -1;        /* BasicGapCriteria */
static int hf_camel_scfID = -1;                   /* ScfID */
static int hf_camel_DestinationRoutingAddress_item = -1;  /* CalledPartyNumber */
static int hf_camel_applicationTimer = -1;        /* ApplicationTimer */
static int hf_camel_midCallControlInfo = -1;      /* MidCallControlInfo */
static int hf_camel_dpSpecificCriteriaAlt = -1;   /* DpSpecificCriteriaAlt */
static int hf_camel_changeOfPositionControlInfo = -1;  /* ChangeOfPositionControlInfo */
static int hf_camel_numberOfDigits = -1;          /* NumberOfDigits */
static int hf_camel_interDigitTimeout = -1;       /* INTEGER_1_127 */
static int hf_camel_oServiceChangeSpecificInfo = -1;  /* T_oServiceChangeSpecificInfo */
static int hf_camel_ext_basicServiceCode = -1;    /* Ext_BasicServiceCode */
static int hf_camel_initiatorOfServiceChange = -1;  /* InitiatorOfServiceChange */
static int hf_camel_natureOfServiceChange = -1;   /* NatureOfServiceChange */
static int hf_camel_tServiceChangeSpecificInfo = -1;  /* T_tServiceChangeSpecificInfo */
static int hf_camel_timeGPRSIfNoTariffSwitch = -1;  /* INTEGER_0_86400 */
static int hf_camel_timeGPRSIfTariffSwitch = -1;  /* T_timeGPRSIfTariffSwitch */
static int hf_camel_timeGPRSSinceLastTariffSwitch = -1;  /* INTEGER_0_86400 */
static int hf_camel_timeGPRSTariffSwitchInterval = -1;  /* INTEGER_0_86400 */
static int hf_camel_rOTimeGPRSIfNoTariffSwitch = -1;  /* INTEGER_0_255 */
static int hf_camel_rOTimeGPRSIfTariffSwitch = -1;  /* T_rOTimeGPRSIfTariffSwitch */
static int hf_camel_rOTimeGPRSSinceLastTariffSwitch = -1;  /* INTEGER_0_255 */
static int hf_camel_rOTimeGPRSTariffSwitchInterval = -1;  /* INTEGER_0_255 */
static int hf_camel_routeSelectFailureSpecificInfo = -1;  /* T_routeSelectFailureSpecificInfo */
static int hf_camel_failureCause = -1;            /* Cause */
static int hf_camel_oCalledPartyBusySpecificInfo = -1;  /* T_oCalledPartyBusySpecificInfo */
static int hf_camel_busyCause = -1;               /* Cause */
static int hf_camel_oNoAnswerSpecificInfo = -1;   /* T_oNoAnswerSpecificInfo */
static int hf_camel_oAnswerSpecificInfo = -1;     /* T_oAnswerSpecificInfo */
static int hf_camel_destinationAddress = -1;      /* CalledPartyNumber */
static int hf_camel_or_Call = -1;                 /* NULL */
static int hf_camel_forwardedCall = -1;           /* NULL */
static int hf_camel_chargeIndicator = -1;         /* ChargeIndicator */
static int hf_camel_ext_basicServiceCode2 = -1;   /* Ext_BasicServiceCode */
static int hf_camel_oMidCallSpecificInfo = -1;    /* T_oMidCallSpecificInfo */
static int hf_camel_omidCallEvents = -1;          /* T_omidCallEvents */
static int hf_camel_dTMFDigitsCompleted = -1;     /* Digits */
static int hf_camel_dTMFDigitsTimeOut = -1;       /* Digits */
static int hf_camel_oDisconnectSpecificInfo = -1;  /* T_oDisconnectSpecificInfo */
static int hf_camel_releaseCause = -1;            /* Cause */
static int hf_camel_tBusySpecificInfo = -1;       /* T_tBusySpecificInfo */
static int hf_camel_callForwarded = -1;           /* NULL */
static int hf_camel_routeNotPermitted = -1;       /* NULL */
static int hf_camel_forwardingDestinationNumber = -1;  /* CalledPartyNumber */
static int hf_camel_tNoAnswerSpecificInfo = -1;   /* T_tNoAnswerSpecificInfo */
static int hf_camel_tAnswerSpecificInfo = -1;     /* T_tAnswerSpecificInfo */
static int hf_camel_tMidCallSpecificInfo = -1;    /* T_tMidCallSpecificInfo */
static int hf_camel_tmidCallEvents = -1;          /* T_tmidCallEvents */
static int hf_camel_tDisconnectSpecificInfo = -1;  /* T_tDisconnectSpecificInfo */
static int hf_camel_oTermSeizedSpecificInfo = -1;  /* T_oTermSeizedSpecificInfo */
static int hf_camel_locationInformation = -1;     /* LocationInformation */
static int hf_camel_callAcceptedSpecificInfo = -1;  /* T_callAcceptedSpecificInfo */
static int hf_camel_oAbandonSpecificInfo = -1;    /* T_oAbandonSpecificInfo */
static int hf_camel_oChangeOfPositionSpecificInfo = -1;  /* T_oChangeOfPositionSpecificInfo */
static int hf_camel_metDPCriteriaList = -1;       /* MetDPCriteriaList */
static int hf_camel_tChangeOfPositionSpecificInfo = -1;  /* T_tChangeOfPositionSpecificInfo */
static int hf_camel_dpSpecificInfoAlt = -1;       /* DpSpecificInfoAlt */
static int hf_camel_o_smsFailureSpecificInfo = -1;  /* T_o_smsFailureSpecificInfo */
static int hf_camel_smsfailureCause = -1;         /* MO_SMSCause */
static int hf_camel_o_smsSubmittedSpecificInfo = -1;  /* T_o_smsSubmittedSpecificInfo */
static int hf_camel_foo = -1;                     /* INTEGER_0 */
static int hf_camel_t_smsFailureSpecificInfo = -1;  /* T_t_smsFailureSpecificInfo */
static int hf_camel_failureMTSMSCause = -1;       /* MT_SMSCause */
static int hf_camel_t_smsDeliverySpecificInfo = -1;  /* T_t_smsDeliverySpecificInfo */
static int hf_camel_callDiversionTreatmentIndicator = -1;  /* OCTET_STRING_SIZE_1 */
static int hf_camel_callingPartyRestrictionIndicator = -1;  /* OCTET_STRING_SIZE_1 */
static int hf_camel_compoundGapCriteria = -1;     /* CompoundCriteria */
static int hf_camel_duration1 = -1;               /* Duration */
static int hf_camel_gapInterval = -1;             /* Interval */
static int hf_camel_informationToSend = -1;       /* InformationToSend */
static int hf_camel_GenericNumbers_item = -1;     /* GenericNumber */
static int hf_camel_short_QoS_format = -1;        /* QoS_Subscribed */
static int hf_camel_long_QoS_format = -1;         /* Ext_QoS_Subscribed */
static int hf_camel_supplement_to_long_QoS_format = -1;  /* Ext2_QoS_Subscribed */
static int hf_camel_gPRSEventType = -1;           /* GPRSEventType */
static int hf_camel_attachChangeOfPositionSpecificInformation = -1;  /* T_attachChangeOfPositionSpecificInformation */
static int hf_camel_locationInformationGPRS = -1;  /* LocationInformationGPRS */
static int hf_camel_pdp_ContextchangeOfPositionSpecificInformation = -1;  /* T_pdp_ContextchangeOfPositionSpecificInformation */
static int hf_camel_accessPointName = -1;         /* AccessPointName */
static int hf_camel_chargingID = -1;              /* GPRSChargingID */
static int hf_camel_pDPType = -1;                 /* PDPType */
static int hf_camel_qualityOfService = -1;        /* QualityOfService */
static int hf_camel_timeAndTimeZone = -1;         /* TimeAndTimezone */
static int hf_camel_gGSNAddress = -1;             /* GSN_Address */
static int hf_camel_detachSpecificInformation = -1;  /* T_detachSpecificInformation */
static int hf_camel_inititatingEntity = -1;       /* InitiatingEntity */
static int hf_camel_routeingAreaUpdate = -1;      /* NULL */
static int hf_camel_disconnectSpecificInformation = -1;  /* T_disconnectSpecificInformation */
static int hf_camel_pDPContextEstablishmentSpecificInformation = -1;  /* T_pDPContextEstablishmentSpecificInformation */
static int hf_camel_pDPInitiationType = -1;       /* PDPInitiationType */
static int hf_camel_secondaryPDPContext = -1;     /* NULL */
static int hf_camel_pDPContextEstablishmentAcknowledgementSpecificInformation = -1;  /* T_pDPContextEstablishmentAcknowledgementSpecificInformation */
static int hf_camel_mSNetworkCapability = -1;     /* MSNetworkCapability */
static int hf_camel_mSRadioAccessCapability = -1;  /* MSRadioAccessCapability */
static int hf_camel_messageID = -1;               /* MessageID */
static int hf_camel_numberOfRepetitions = -1;     /* INTEGER_1_127 */
static int hf_camel_duration2 = -1;               /* INTEGER_0_32767 */
static int hf_camel_interval = -1;                /* INTEGER_0_32767 */
static int hf_camel_inbandInfo = -1;              /* InbandInfo */
static int hf_camel_tone = -1;                    /* Tone */
static int hf_camel_cellGlobalIdOrServiceAreaIdOrLAI = -1;  /* CellGlobalIdOrServiceAreaIdOrLAI */
static int hf_camel_routeingAreaIdentity = -1;    /* RAIdentity */
static int hf_camel_geographicalInformation = -1;  /* GeographicalInformation */
static int hf_camel_sgsn_Number = -1;             /* ISDN_AddressString */
static int hf_camel_selectedLSAIdentity = -1;     /* LSAIdentity */
static int hf_camel_extensionContainer = -1;      /* ExtensionContainer */
static int hf_camel_saiPresent = -1;              /* NULL */
static int hf_camel_elementaryMessageID = -1;     /* Integer4 */
static int hf_camel_text = -1;                    /* T_text */
static int hf_camel_messageContent = -1;          /* IA5String_SIZE_cAPSpecificBoundSetminMessageContentLength_cAPSpecificBoundSetmaxMessageContentLength */
static int hf_camel_attributes = -1;              /* OCTET_STRING_SIZE_cAPSpecificBoundSetminAttributesLength_cAPSpecificBoundSetmaxAttributesLength */
static int hf_camel_elementaryMessageIDs = -1;    /* SEQUENCE_SIZE_1_cAPSpecificBoundSetnumOfMessageIDs_OF_Integer4 */
static int hf_camel_elementaryMessageIDs_item = -1;  /* Integer4 */
static int hf_camel_variableMessage = -1;         /* T_variableMessage */
static int hf_camel_variableParts = -1;           /* VariablePartsArray */
static int hf_camel_MetDPCriteriaList_item = -1;  /* MetDPCriterion */
static int hf_camel_enteringCellGlobalId = -1;    /* CellGlobalIdOrServiceAreaIdFixedLength */
static int hf_camel_leavingCellGlobalId = -1;     /* CellGlobalIdOrServiceAreaIdFixedLength */
static int hf_camel_enteringServiceAreaId = -1;   /* CellGlobalIdOrServiceAreaIdFixedLength */
static int hf_camel_leavingServiceAreaId = -1;    /* CellGlobalIdOrServiceAreaIdFixedLength */
static int hf_camel_enteringLocationAreaId = -1;  /* LAIFixedLength */
static int hf_camel_leavingLocationAreaId = -1;   /* LAIFixedLength */
static int hf_camel_inter_SystemHandOverToUMTS = -1;  /* NULL */
static int hf_camel_inter_SystemHandOverToGSM = -1;  /* NULL */
static int hf_camel_metDPCriterionAlt = -1;       /* MetDPCriterionAlt */
static int hf_camel_minimumNumberOfDigits = -1;   /* INTEGER_1_30 */
static int hf_camel_maximumNumberOfDigits = -1;   /* INTEGER_1_30 */
static int hf_camel_requested_QoS = -1;           /* GPRS_QoS */
static int hf_camel_subscribed_QoS = -1;          /* GPRS_QoS */
static int hf_camel_negotiated_QoS = -1;          /* GPRS_QoS */
static int hf_camel_requested_QoS_Extension = -1;  /* GPRS_QoS_Extension */
static int hf_camel_subscribed_QoS_Extension = -1;  /* GPRS_QoS_Extension */
static int hf_camel_negotiated_QoS_Extension = -1;  /* GPRS_QoS_Extension */
static int hf_camel_receivingSideID = -1;         /* LegType */
static int hf_camel_RequestedInformationList_item = -1;  /* RequestedInformation */
static int hf_camel_RequestedInformationTypeList_item = -1;  /* RequestedInformationType */
static int hf_camel_requestedInformationType = -1;  /* RequestedInformationType */
static int hf_camel_requestedInformationValue = -1;  /* RequestedInformationValue */
static int hf_camel_callAttemptElapsedTimeValue = -1;  /* INTEGER_0_255 */
static int hf_camel_callStopTimeValue = -1;       /* DateAndTime */
static int hf_camel_callConnectedElapsedTimeValue = -1;  /* Integer4 */
static int hf_camel_releaseCauseValue = -1;       /* Cause */
static int hf_camel_sendingSideID = -1;           /* LegType */
static int hf_camel_forwardServiceInteractionInd = -1;  /* ForwardServiceInteractionInd */
static int hf_camel_backwardServiceInteractionInd = -1;  /* BackwardServiceInteractionInd */
static int hf_camel_bothwayThroughConnectionInd = -1;  /* BothwayThroughConnectionInd */
static int hf_camel_connectedNumberTreatmentInd = -1;  /* ConnectedNumberTreatmentInd */
static int hf_camel_nonCUGCall = -1;              /* NULL */
static int hf_camel_holdTreatmentIndicator = -1;  /* OCTET_STRING_SIZE_1 */
static int hf_camel_cwTreatmentIndicator = -1;    /* OCTET_STRING_SIZE_1 */
static int hf_camel_ectTreatmentIndicator = -1;   /* OCTET_STRING_SIZE_1 */
static int hf_camel_eventTypeSMS = -1;            /* EventTypeSMS */
static int hf_camel_timeSinceTariffSwitch = -1;   /* INTEGER_0_864000 */
static int hf_camel_tttariffSwitchInterval = -1;  /* INTEGER_1_864000 */
static int hf_camel_timeIfNoTariffSwitch = -1;    /* TimeIfNoTariffSwitch */
static int hf_camel_timeIfTariffSwitch = -1;      /* TimeIfTariffSwitch */
static int hf_camel_toneID = -1;                  /* Integer4 */
static int hf_camel_duration3 = -1;               /* Integer4 */
static int hf_camel_volumeIfNoTariffSwitch = -1;  /* INTEGER_0_4294967295 */
static int hf_camel_volumeIfTariffSwitch = -1;    /* T_volumeIfTariffSwitch */
static int hf_camel_volumeSinceLastTariffSwitch = -1;  /* INTEGER_0_4294967295 */
static int hf_camel_volumeTariffSwitchInterval = -1;  /* INTEGER_0_4294967295 */
static int hf_camel_rOVolumeIfNoTariffSwitch = -1;  /* INTEGER_0_255 */
static int hf_camel_rOVolumeIfTariffSwitch = -1;  /* T_rOVolumeIfTariffSwitch */
static int hf_camel_rOVolumeSinceLastTariffSwitch = -1;  /* INTEGER_0_255 */
static int hf_camel_rOVolumeTariffSwitchInterval = -1;  /* INTEGER_0_255 */
static int hf_camel_integer = -1;                 /* Integer4 */
static int hf_camel_number = -1;                  /* Digits */
static int hf_camel_time = -1;                    /* OCTET_STRING_SIZE_2 */
static int hf_camel_date = -1;                    /* OCTET_STRING_SIZE_4 */
static int hf_camel_price = -1;                   /* OCTET_STRING_SIZE_4 */
static int hf_camel_allAnnouncementsComplete = -1;  /* NULL */
static int hf_camel_firstAnnouncementStarted = -1;  /* NULL */
static int hf_camel_pDPTypeOrganization = -1;     /* PDPTypeOrganization */
static int hf_camel_pDPTypeNumber = -1;           /* PDPTypeNumber */
static int hf_camel_pDPAddress = -1;              /* PDPAddress */
static int hf_camel_local = -1;                   /* INTEGER */
static int hf_camel_global = -1;                  /* OBJECT_IDENTIFIER */
static int hf_camel_messageType = -1;             /* T_messageType */
static int hf_camel_firstExtensionExtensionType = -1;  /* NULL */
static int hf_camel_extId = -1;                   /* ExtensionSetextensionId */
static int hf_camel_callresultOctet = -1;         /* CAMEL_CallResult */
static int hf_camel_allRequests = -1;             /* NULL */
static int hf_camel_callSegmentToCancel = -1;     /* CallSegmentToCancel */
static int hf_camel_digitsResponse = -1;          /* Digits */
static int hf_camel_pdpID = -1;                   /* PDPId */
static int hf_camel_gPRSCause = -1;               /* GPRSCause */
static int hf_camel_gprsCause = -1;               /* GPRSCause */
static int hf_camel_gPRSEvent = -1;               /* GPRSEventArray */
static int hf_camel_GPRSEventArray_item = -1;     /* GPRSEvent */
static int hf_camel_sCIGPRSBillingChargingCharacteristics = -1;  /* SCIGPRSBillingChargingCharacteristics */
static int hf_camel_assumedIdle = -1;             /* NULL */
static int hf_camel_camelBusy = -1;               /* NULL */
static int hf_camel_netDetNotReachable = -1;      /* NotReachableReason */
static int hf_camel_notProvidedFromVLR = -1;      /* NULL */
static int hf_camel_PrivateExtensionList_item = -1;  /* PrivateExtension */
static int hf_camel_VariablePartsArray_item = -1;  /* VariablePart */
static int hf_camel_gmscAddress = -1;             /* ISDN_AddressString */
static int hf_camel_ms_Classmark2 = -1;           /* MS_Classmark2 */
static int hf_camel_iMEI = -1;                    /* IMEI */
static int hf_camel_supportedCamelPhases = -1;    /* SupportedCamelPhases */
static int hf_camel_offeredCamel4Functionalities = -1;  /* OfferedCamel4Functionalities */
static int hf_camel_bearerCapability2 = -1;       /* BearerCapability */
static int hf_camel_highLayerCompatibility2 = -1;  /* HighLayerCompatibility */
static int hf_camel_lowLayerCompatibility = -1;   /* LowLayerCompatibility */
static int hf_camel_lowLayerCompatibility2 = -1;  /* LowLayerCompatibility */
static int hf_camel_enhancedDialledServicesAllowed = -1;  /* NULL */
static int hf_camel_uu_Data = -1;                 /* UU_Data */
static int hf_camel_collectInformationAllowed = -1;  /* NULL */
static int hf_camel_destinationRoutingAddress = -1;  /* DestinationRoutingAddress */
static int hf_camel_legToBeCreated = -1;          /* LegID */
static int hf_camel_newCallSegment = -1;          /* CallSegmentID */
static int hf_camel_callingPartyNumber = -1;      /* CallingPartyNumber */
static int hf_camel_callReferenceNumber = -1;     /* CallReferenceNumber */
static int hf_camel_gsmSCFAddress = -1;           /* ISDN_AddressString */
static int hf_camel_suppress_T_CSI = -1;          /* NULL */
static int hf_camel_legIDToMove = -1;             /* LegID */
static int hf_camel_legOrCallSegment = -1;        /* LegOrCallSegment */
static int hf_camel_miscGPRSInfo = -1;            /* MiscCallInfo */
static int hf_camel_gPRSEventSpecificInformation = -1;  /* GPRSEventSpecificInformation */
static int hf_camel_type = -1;                    /* SupportedExtensionsid */
static int hf_camel_criticality = -1;             /* CriticalityType */
static int hf_camel_value = -1;                   /* SupportedExtensionsExtensionType */
static int hf_camel_aChBillingChargingCharacteristics = -1;  /* AChBillingChargingCharacteristics */
static int hf_camel_partyToCharge1 = -1;          /* SendingSideID */
static int hf_camel_ExtensionsArray_item = -1;    /* ExtensionField */
static int hf_camel_correlationID = -1;           /* CorrelationID */
static int hf_camel_iPSSPCapabilities = -1;       /* IPSSPCapabilities */
static int hf_camel_requestedInformationTypeList = -1;  /* RequestedInformationTypeList */
static int hf_camel_legID3 = -1;                  /* SendingSideID */
static int hf_camel_alertingPattern = -1;         /* AlertingPattern */
static int hf_camel_originalCalledPartyID = -1;   /* OriginalCalledPartyID */
static int hf_camel_carrier = -1;                 /* Carrier */
static int hf_camel_callingPartysCategory = -1;   /* CallingPartysCategory */
static int hf_camel_redirectingPartyID = -1;      /* RedirectingPartyID */
static int hf_camel_redirectionInformation = -1;  /* RedirectionInformation */
static int hf_camel_genericNumbers = -1;          /* GenericNumbers */
static int hf_camel_serviceInteractionIndicatorsTwo = -1;  /* ServiceInteractionIndicatorsTwo */
static int hf_camel_chargeNumber = -1;            /* ChargeNumber */
static int hf_camel_legToBeConnected = -1;        /* LegID */
static int hf_camel_cug_Interlock = -1;           /* CUG_Interlock */
static int hf_camel_cug_OutgoingAccess = -1;      /* NULL */
static int hf_camel_suppressionOfAnnouncement = -1;  /* SuppressionOfAnnouncement */
static int hf_camel_oCSIApplicable = -1;          /* OCSIApplicable */
static int hf_camel_naOliInfo = -1;               /* NAOliInfo */
static int hf_camel_bor_InterrogationRequested = -1;  /* NULL */
static int hf_camel_suppress_N_CSI = -1;          /* NULL */
static int hf_camel_resourceAddress = -1;         /* T_resourceAddress */
static int hf_camel_ipRoutingAddress = -1;        /* IPRoutingAddress */
static int hf_camel_none = -1;                    /* NULL */
static int hf_camel_suppress_O_CSI = -1;          /* NULL */
static int hf_camel_continueWithArgumentArgExtension = -1;  /* ContinueWithArgumentArgExtension */
static int hf_camel_suppress_D_CSI = -1;          /* NULL */
static int hf_camel_suppressOutgoingCallBarring = -1;  /* NULL */
static int hf_camel_legToBeReleased = -1;         /* LegID */
static int hf_camel_callSegmentFailure = -1;      /* CallSegmentFailure */
static int hf_camel_bCSM_Failure = -1;            /* BCSM_Failure */
static int hf_camel_assistingSSPIPRoutingAddress = -1;  /* AssistingSSPIPRoutingAddress */
static int hf_camel_eventSpecificInformationBCSM = -1;  /* EventSpecificInformationBCSM */
static int hf_camel_legID4 = -1;                  /* ReceivingSideID */
static int hf_camel_miscCallInfo = -1;            /* MiscCallInfo */
static int hf_camel_timerID = -1;                 /* TimerID */
static int hf_camel_timervalue = -1;              /* TimerValue */
static int hf_camel_sCIBillingChargingCharacteristics = -1;  /* SCIBillingChargingCharacteristics */
static int hf_camel_partyToCharge2 = -1;          /* SendingSideID */
static int hf_camel_legToBeSplit = -1;            /* LegID */
static int hf_camel_destinationReference = -1;    /* Integer4 */
static int hf_camel_originationReference = -1;    /* Integer4 */
static int hf_camel_eventSpecificInformationSMS = -1;  /* EventSpecificInformationSMS */
static int hf_camel_bcsmEvents = -1;              /* BCSMEventArray */
static int hf_camel_BCSMEventArray_item = -1;     /* BCSMEvent */
static int hf_camel_callingPartysNumber = -1;     /* SMS_AddressString */
static int hf_camel_destinationSubscriberNumber = -1;  /* CalledPartyBCDNumber */
static int hf_camel_sMSCAddress = -1;             /* ISDN_AddressString */
static int hf_camel_requestedInformationList = -1;  /* RequestedInformationList */
static int hf_camel_legID5 = -1;                  /* ReceivingSideID */
static int hf_camel_disconnectFromIPForbidden = -1;  /* BOOLEAN */
static int hf_camel_requestAnnouncementComplete = -1;  /* BOOLEAN */
static int hf_camel_requestAnnouncementStartedNotification = -1;  /* BOOLEAN */
static int hf_camel_collectedInfo = -1;           /* CollectedInfo */
static int hf_camel_mSISDN = -1;                  /* ISDN_AddressString */
static int hf_camel_iMSI = -1;                    /* IMSI */
static int hf_camel_gPRSMSClass = -1;             /* GPRSMSClass */
static int hf_camel_sGSNCapabilities = -1;        /* SGSNCapabilities */
static int hf_camel_gapCriteria = -1;             /* GapCriteria */
static int hf_camel_gapIndicators = -1;           /* GapIndicators */
static int hf_camel_controlType = -1;             /* ControlType */
static int hf_camel_gapTreatment = -1;            /* GapTreatment */
static int hf_camel_calledPartyNumber = -1;       /* CalledPartyNumber */
static int hf_camel_cGEncountered = -1;           /* CGEncountered */
static int hf_camel_locationNumber = -1;          /* LocationNumber */
static int hf_camel_highLayerCompatibility = -1;  /* HighLayerCompatibility */
static int hf_camel_additionalCallingPartyNumber = -1;  /* AdditionalCallingPartyNumber */
static int hf_camel_bearerCapability = -1;        /* BearerCapability */
static int hf_camel_cug_Index = -1;               /* CUG_Index */
static int hf_camel_subscriberState = -1;         /* SubscriberState */
static int hf_camel_mscAddress = -1;              /* ISDN_AddressString */
static int hf_camel_calledPartyBCDNumber = -1;    /* CalledPartyBCDNumber */
static int hf_camel_timeAndTimezone = -1;         /* TimeAndTimezone */
static int hf_camel_gsm_ForwardingPending = -1;   /* NULL */
static int hf_camel_initialDPArgExtension = -1;   /* InitialDPArgExtension */
static int hf_camel_callingPartyNumberas = -1;    /* SMS_AddressString */
static int hf_camel_locationInformationMSC = -1;  /* LocationInformation */
static int hf_camel_tPShortMessageSpecificInfo = -1;  /* TPShortMessageSpecificInfo */
static int hf_camel_tPProtocolIdentifier = -1;    /* TPProtocolIdentifier */
static int hf_camel_tPDataCodingScheme = -1;      /* TPDataCodingScheme */
static int hf_camel_tPValidityPeriod = -1;        /* TPValidityPeriod */
static int hf_camel_smsReferenceNumber = -1;      /* CallReferenceNumber */
static int hf_camel_sgsnNumber = -1;              /* ISDN_AddressString */
static int hf_camel_calledPartyNumberSMS = -1;    /* ISDN_AddressString */
static int hf_camel_sMSEvents = -1;               /* SMSEventArray */
static int hf_camel_SMSEventArray_item = -1;      /* SMSEvent */
static int hf_camel_privateExtensionList = -1;    /* PrivateExtensionList */
static int hf_camel_pcs_Extensions = -1;          /* PCS_Extensions */
static int hf_camel_chargingCharacteristics = -1;  /* ChargingCharacteristics */
static int hf_camel_chargingResult = -1;          /* ChargingResult */
static int hf_camel_active = -1;                  /* BOOLEAN */
static int hf_camel_chargingRollOver = -1;        /* ChargingRollOver */
static int hf_camel_cancelproblem = -1;           /* T_cancelproblem */
static int hf_camel_operation = -1;               /* InvokeID */
/* named bits */
static int hf_camel_SupportedCamelPhases_phase1 = -1;
static int hf_camel_SupportedCamelPhases_phase2 = -1;
static int hf_camel_SupportedCamelPhases_phase3 = -1;
static int hf_camel_SupportedCamelPhases_phase4 = -1;
static int hf_camel_OfferedCamel4Functionalities_initiateCallAttempt = -1;
static int hf_camel_OfferedCamel4Functionalities_splitLeg = -1;
static int hf_camel_OfferedCamel4Functionalities_moveLeg = -1;
static int hf_camel_OfferedCamel4Functionalities_disconnectLeg = -1;
static int hf_camel_OfferedCamel4Functionalities_entityReleased = -1;
static int hf_camel_OfferedCamel4Functionalities_dfc_WithArgument = -1;
static int hf_camel_OfferedCamel4Functionalities_playTone = -1;
static int hf_camel_OfferedCamel4Functionalities_dtmf_MidCall = -1;
static int hf_camel_OfferedCamel4Functionalities_chargingIndicator = -1;
static int hf_camel_OfferedCamel4Functionalities_alertingDP = -1;
static int hf_camel_OfferedCamel4Functionalities_locationAtAlerting = -1;
static int hf_camel_OfferedCamel4Functionalities_changeOfPositionDP = -1;
static int hf_camel_OfferedCamel4Functionalities_or_Interactions = -1;
static int hf_camel_OfferedCamel4Functionalities_warningToneEnhancements = -1;
static int hf_camel_OfferedCamel4Functionalities_cf_Enhancements = -1;
static int hf_camel_OfferedCamel4Functionalities_subscribedEnhancedDialledServices = -1;
static int hf_camel_OfferedCamel4Functionalities_servingNetworkEnhancedDialledServices = -1;
static int hf_camel_OfferedCamel4Functionalities_criteriaForChangeOfPositionDP = -1;
static int hf_camel_OfferedCamel4Functionalities_serviceChangeDP = -1;

/*--- End of included file: packet-camel-hf.c ---*/
#line 113 "packet-camel-template.c"

gboolean gcamel_HandleSRT=FALSE;
extern gboolean gcamel_PersistentSRT;
extern gboolean gcamel_DisplaySRT;

/* Initialize the subtree pointers */
static gint ett_camel = -1;
static gint ett_camelisup_parameter = -1;
static gint ett_camel_isdn_address_string = -1;
static gint ett_camel_MSRadioAccessCapability = -1;
static gint ett_camel_MSNetworkCapability = -1;
static gint ett_camel_AccessPointName = -1;
static gint ett_camel_pdptypenumber = -1;
static gint ett_camel_stat = -1;


/*--- Included file: packet-camel-ett.c ---*/
#line 1 "packet-camel-ett.c"
static gint ett_camel_Component = -1;
static gint ett_camel_Invoke = -1;
static gint ett_camel_ReturnResult = -1;
static gint ett_camel_T_resultretres = -1;
static gint ett_camel_ReturnError = -1;
static gint ett_camel_Reject = -1;
static gint ett_camel_T_invokeIDRej = -1;
static gint ett_camel_T_problem = -1;
static gint ett_camel_OPERATION = -1;
static gint ett_camel_ERROR = -1;
static gint ett_camel_AChBillingChargingCharacteristics = -1;
static gint ett_camel_T_actimeDurationCharging = -1;
static gint ett_camel_AChChargingAddress = -1;
static gint ett_camel_AOCBeforeAnswer = -1;
static gint ett_camel_AOCGprs = -1;
static gint ett_camel_AOCSubsequent = -1;
static gint ett_camel_AudibleIndicator = -1;
static gint ett_camel_BackwardServiceInteractionInd = -1;
static gint ett_camel_BasicGapCriteria = -1;
static gint ett_camel_T_calledAddressAndService = -1;
static gint ett_camel_T_callingAddressAndService = -1;
static gint ett_camel_BCSMEvent = -1;
static gint ett_camel_BCSM_Failure = -1;
static gint ett_camel_BearerCapability = -1;
static gint ett_camel_Burst = -1;
static gint ett_camel_BurstList = -1;
static gint ett_camel_CAI_Gsm0224 = -1;
static gint ett_camel_CallSegmentFailure = -1;
static gint ett_camel_CallSegmentToCancel = -1;
static gint ett_camel_CAMEL_AChBillingChargingCharacteristics = -1;
static gint ett_camel_T_timeDurationCharging = -1;
static gint ett_camel_CAMEL_CallResult = -1;
static gint ett_camel_TimeDurationChargingResult = -1;
static gint ett_camel_CAMEL_FCIBillingChargingCharacteristics = -1;
static gint ett_camel_T_fCIBCCCAMELsequence1 = -1;
static gint ett_camel_CAMEL_FCIGPRSBillingChargingCharacteristics = -1;
static gint ett_camel_T_fCIBCCCAMELsequence2 = -1;
static gint ett_camel_CAMEL_FCISMSBillingChargingCharacteristics = -1;
static gint ett_camel_T_fCIBCCCAMELsequence3 = -1;
static gint ett_camel_CAMEL_SCIBillingChargingCharacteristics = -1;
static gint ett_camel_CAMEL_SCIBillingChargingCharacteristicsAlt = -1;
static gint ett_camel_CamelSCIGPRSBillingChargingCharacteristics = -1;
static gint ett_camel_ChangeOfPositionControlInfo = -1;
static gint ett_camel_ChangeOfLocation = -1;
static gint ett_camel_ChangeOfLocationAlt = -1;
static gint ett_camel_ChargingCharacteristics = -1;
static gint ett_camel_ChargingResult = -1;
static gint ett_camel_ChargingRollOver = -1;
static gint ett_camel_CollectedDigits = -1;
static gint ett_camel_CollectedInfo = -1;
static gint ett_camel_CompoundCriteria = -1;
static gint ett_camel_DestinationRoutingAddress = -1;
static gint ett_camel_DpSpecificCriteria = -1;
static gint ett_camel_DpSpecificCriteriaAlt = -1;
static gint ett_camel_DpSpecificInfoAlt = -1;
static gint ett_camel_T_oServiceChangeSpecificInfo = -1;
static gint ett_camel_T_tServiceChangeSpecificInfo = -1;
static gint ett_camel_ElapsedTime = -1;
static gint ett_camel_T_timeGPRSIfTariffSwitch = -1;
static gint ett_camel_ElapsedTimeRollOver = -1;
static gint ett_camel_T_rOTimeGPRSIfTariffSwitch = -1;
static gint ett_camel_EventSpecificInformationBCSM = -1;
static gint ett_camel_T_routeSelectFailureSpecificInfo = -1;
static gint ett_camel_T_oCalledPartyBusySpecificInfo = -1;
static gint ett_camel_T_oNoAnswerSpecificInfo = -1;
static gint ett_camel_T_oAnswerSpecificInfo = -1;
static gint ett_camel_T_oMidCallSpecificInfo = -1;
static gint ett_camel_T_omidCallEvents = -1;
static gint ett_camel_T_oDisconnectSpecificInfo = -1;
static gint ett_camel_T_tBusySpecificInfo = -1;
static gint ett_camel_T_tNoAnswerSpecificInfo = -1;
static gint ett_camel_T_tAnswerSpecificInfo = -1;
static gint ett_camel_T_tMidCallSpecificInfo = -1;
static gint ett_camel_T_tmidCallEvents = -1;
static gint ett_camel_T_tDisconnectSpecificInfo = -1;
static gint ett_camel_T_oTermSeizedSpecificInfo = -1;
static gint ett_camel_T_callAcceptedSpecificInfo = -1;
static gint ett_camel_T_oAbandonSpecificInfo = -1;
static gint ett_camel_T_oChangeOfPositionSpecificInfo = -1;
static gint ett_camel_T_tChangeOfPositionSpecificInfo = -1;
static gint ett_camel_EventSpecificInformationSMS = -1;
static gint ett_camel_T_o_smsFailureSpecificInfo = -1;
static gint ett_camel_T_o_smsSubmittedSpecificInfo = -1;
static gint ett_camel_T_t_smsFailureSpecificInfo = -1;
static gint ett_camel_T_t_smsDeliverySpecificInfo = -1;
static gint ett_camel_ForwardServiceInteractionInd = -1;
static gint ett_camel_GapCriteria = -1;
static gint ett_camel_GapIndicators = -1;
static gint ett_camel_GapOnService = -1;
static gint ett_camel_GapTreatment = -1;
static gint ett_camel_GenericNumbers = -1;
static gint ett_camel_GPRS_QoS = -1;
static gint ett_camel_GPRS_QoS_Extension = -1;
static gint ett_camel_GPRSEvent = -1;
static gint ett_camel_GPRSEventSpecificInformation = -1;
static gint ett_camel_T_attachChangeOfPositionSpecificInformation = -1;
static gint ett_camel_T_pdp_ContextchangeOfPositionSpecificInformation = -1;
static gint ett_camel_T_detachSpecificInformation = -1;
static gint ett_camel_T_disconnectSpecificInformation = -1;
static gint ett_camel_T_pDPContextEstablishmentSpecificInformation = -1;
static gint ett_camel_T_pDPContextEstablishmentAcknowledgementSpecificInformation = -1;
static gint ett_camel_GPRSMSClass = -1;
static gint ett_camel_InbandInfo = -1;
static gint ett_camel_InformationToSend = -1;
static gint ett_camel_LegOrCallSegment = -1;
static gint ett_camel_LocationInformationGPRS = -1;
static gint ett_camel_MessageID = -1;
static gint ett_camel_T_text = -1;
static gint ett_camel_SEQUENCE_SIZE_1_cAPSpecificBoundSetnumOfMessageIDs_OF_Integer4 = -1;
static gint ett_camel_T_variableMessage = -1;
static gint ett_camel_MetDPCriteriaList = -1;
static gint ett_camel_MetDPCriterion = -1;
static gint ett_camel_MetDPCriterionAlt = -1;
static gint ett_camel_MidCallControlInfo = -1;
static gint ett_camel_QualityOfService = -1;
static gint ett_camel_ReceivingSideID = -1;
static gint ett_camel_RequestedInformationList = -1;
static gint ett_camel_RequestedInformationTypeList = -1;
static gint ett_camel_RequestedInformation = -1;
static gint ett_camel_RequestedInformationValue = -1;
static gint ett_camel_SendingSideID = -1;
static gint ett_camel_ServiceInteractionIndicatorsTwo = -1;
static gint ett_camel_SMSEvent = -1;
static gint ett_camel_TimeIfTariffSwitch = -1;
static gint ett_camel_TimeInformation = -1;
static gint ett_camel_Tone = -1;
static gint ett_camel_TransferredVolume = -1;
static gint ett_camel_T_volumeIfTariffSwitch = -1;
static gint ett_camel_TransferredVolumeRollOver = -1;
static gint ett_camel_T_rOVolumeIfTariffSwitch = -1;
static gint ett_camel_VariablePart = -1;
static gint ett_camel_SpecializedResourceReportArg = -1;
static gint ett_camel_PDPType = -1;
static gint ett_camel_Code = -1;
static gint ett_camel_PCS_Extensions = -1;
static gint ett_camel_MiscCallInfo = -1;
static gint ett_camel_SupportedExtensionsExtensionType = -1;
static gint ett_camel_PrivateExtension = -1;
static gint ett_camel_ApplyChargingReportArg = -1;
static gint ett_camel_CancelArg = -1;
static gint ett_camel_CollectInformationArg = -1;
static gint ett_camel_ReceivedInformationArg = -1;
static gint ett_camel_ConnectGPRSArg = -1;
static gint ett_camel_EntityReleasedGPRSArg = -1;
static gint ett_camel_ReleaseGPRSArg = -1;
static gint ett_camel_RequestReportGPRSEventArg = -1;
static gint ett_camel_GPRSEventArray = -1;
static gint ett_camel_SendChargingInformationGPRSArg = -1;
static gint ett_camel_SubscriberState = -1;
static gint ett_camel_PrivateExtensionList = -1;
static gint ett_camel_LegID = -1;
static gint ett_camel_VariablePartsArray = -1;
static gint ett_camel_InitialDPArgExtension = -1;
static gint ett_camel_InitiateCallAttemptArg = -1;
static gint ett_camel_InitiateCallAttemptRes = -1;
static gint ett_camel_MoveLegArg = -1;
static gint ett_camel_PlayToneArg = -1;
static gint ett_camel_SupportedCamelPhases = -1;
static gint ett_camel_OfferedCamel4Functionalities = -1;
static gint ett_camel_EventReportGPRSArg = -1;
static gint ett_camel_ExtensionField = -1;
static gint ett_camel_ApplyChargingArg = -1;
static gint ett_camel_ExtensionsArray = -1;
static gint ett_camel_AssistRequestInstructionsArg = -1;
static gint ett_camel_CallInformationRequestArg = -1;
static gint ett_camel_ConnectArg = -1;
static gint ett_camel_ConnectToResourceArg = -1;
static gint ett_camel_T_resourceAddress = -1;
static gint ett_camel_ContinueWithArgumentArg = -1;
static gint ett_camel_ContinueWithArgumentArgExtension = -1;
static gint ett_camel_DisconnectLegArg = -1;
static gint ett_camel_EntityReleasedArg = -1;
static gint ett_camel_DisconnectForwardConnectionWithArgumentArg = -1;
static gint ett_camel_EstablishTemporaryConnectionArg = -1;
static gint ett_camel_EventReportBCSMArg = -1;
static gint ett_camel_ResetTimerArg = -1;
static gint ett_camel_SendChargingInformationArg = -1;
static gint ett_camel_SplitLegArg = -1;
static gint ett_camel_CAPGPRSReferenceNumber = -1;
static gint ett_camel_EventReportSMSArg = -1;
static gint ett_camel_ResetTimerSMSArg = -1;
static gint ett_camel_RequestReportBCSMEventArg = -1;
static gint ett_camel_BCSMEventArray = -1;
static gint ett_camel_ConnectSMSArg = -1;
static gint ett_camel_CallInformationReportArg = -1;
static gint ett_camel_PlayAnnouncementArg = -1;
static gint ett_camel_PromptAndCollectUserInformationArg = -1;
static gint ett_camel_InitialDPGPRSArg = -1;
static gint ett_camel_CallGapArg = -1;
static gint ett_camel_InitialDPArg = -1;
static gint ett_camel_InitialDPSMSArg = -1;
static gint ett_camel_RequestReportSMSEventArg = -1;
static gint ett_camel_SMSEventArray = -1;
static gint ett_camel_ExtensionContainer = -1;
static gint ett_camel_ApplyChargingGPRSArg = -1;
static gint ett_camel_ApplyChargingReportGPRSArg = -1;
static gint ett_camel_CancelGPRSArg = -1;
static gint ett_camel_ContinueGPRSArg = -1;
static gint ett_camel_ResetTimerGPRSArg = -1;
static gint ett_camel_CancelFailedPARAM = -1;

/*--- End of included file: packet-camel-ett.c ---*/
#line 129 "packet-camel-template.c"


/* Preference settings default */
#define MAX_SSN 254
static range_t *global_ssn_range;
static range_t *ssn_range;
static dissector_handle_t  camel_handle;

/* Global variables */

static int application_context_version;
static guint8 PDPTypeOrganization;
static guint8 PDPTypeNumber;

static char camel_number_to_char(int );
static guint8 dissect_RP_cause_ie(tvbuff_t *tvb, guint32 offset, guint len,
				  proto_tree *tree, int hf_cause_value, guint8 *cause_value);

static const true_false_string camel_extension_value = {
  "No Extension",
  "Extension"
};
#define EUROPEAN_DATE 1
#define AMERICAN_DATE 2
#define CAMEL_DATE_AND_TIME_LEN 20 /* 2*5 + 4 + 5 + 1 (HH:MM:SS;mm/dd/yyyy) */

static enum_val_t date_options[] = {
  { "european",         "DD/MM/YYYY",       EUROPEAN_DATE },
  { "american",        "MM/DD/YYYY",        AMERICAN_DATE },
  { NULL, NULL, 0 }
};

static const value_string digit_value[] = {
    { 0,  "0"},
    { 1,  "1"},
    { 2,  "2"},
    { 3,  "3"},
    { 4,  "4"},
    { 5,  "5"},
    { 6,  "6"},
    { 7,  "7"},
    { 8,  "8"},
    { 9,  "9"},
    { 10, "spare"},
    { 11, "spare"},
    { 12, "spare"},
    { 13, "spare"},
    { 0,  NULL}};
  
  
static const value_string camel_nature_of_addr_indicator_values[] = {
  {   0x00,  "unknown" },
  {   0x01,  "International Number" },
  {   0x02,  "National Significant Number" },
  {   0x03,  "Network Specific Number" },
  {   0x04,  "Subscriber Number" },
  {   0x05,  "Reserved" },
  {   0x06,  "Abbreviated Number" },
  {   0x07,  "Reserved for extension" },
  { 0, NULL }
};
static const value_string camel_number_plan_values[] = {
  {   0x00,  "unknown" },
  {   0x01,  "ISDN/Telephony Numbering (Rec ITU-T E.164)" },
  {   0x02,  "spare" },
  {   0x03,  "Data Numbering (ITU-T Rec. X.121)" },
  {   0x04,  "Telex Numbering (ITU-T Rec. F.69)" },
  {   0x05,  "spare" },
  {   0x06,  "Land Mobile Numbering (ITU-T Rec. E.212)" },
  {   0x07,  "spare" },
  {   0x08,  "National Numbering" },
  {   0x09,  "Private Numbering" },
  {   0x0f,  "Reserved for extension" },
  { 0, NULL }
};

/* End includes from old" packet-camel.c */

static const value_string camel_RP_Cause_values[] = {
  { 1, "Unassigned (unallocated) number" },
  { 8, "Operator determined barring" },
  { 10, "Call barred" },
  { 11, "Reserved" },
  { 21, "Short message transfer rejected" },
  { 27, "Destination out of order" },
  { 28, "Unidentified subscriber" },
  { 29, "Facility Rejected" },
  { 30, "Unknown subscriber" },
  { 38, "Network out of order" },
  { 41, "Temporary failure" },
  { 42, "Congestion" },
  { 47, "Resources unavailable, unspecified" },
  { 50, "Requested facility not subscribed" },
  { 69, "Requested facility not implemented" },
  { 81, "Invalid short message transfer reference value" },
  { 95, "Semantically incorrect message" },
  { 96, "Invalid mandatory information" },
  { 97, " Message Type non-existent or not implemented" },
  { 98, "Message not compatible with short message protocol state" },
  { 99, "Information element non existent or not implemented" },
  { 111, "Protocol error, unspecified" },
  { 127, "Interworking, unspecified" },
  { 22,"Memory capacity exceeded" },
  { 0, NULL }
};


/*--- Included file: packet-camel-fn.c ---*/
#line 1 "packet-camel-fn.c"


static int
dissect_camel_InvokeIdType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string camel_CAMELOperationLocalvalue_vals[] = {
  {   0, "initialDP" },
  {  16, "assistRequestInstructions" },
  {  17, "establishTemporaryConnection" },
  {  18, "disconnectForwardConnection" },
  {  19, "connectToResource" },
  {  20, "connect" },
  {  22, "releaseCall" },
  {  23, "requestReportBCSMEvent" },
  {  24, "eventReportBCSM" },
  {  27, "collectInformation" },
  {  31, "continue" },
  {  32, "initiateCallAttempt" },
  {  33, "resetTimer" },
  {  34, "furnishChargingInformation" },
  {  35, "applyCharging" },
  {  36, "applyChargingReport" },
  {  41, "callGap" },
  {  44, "callInformationReport" },
  {  45, "callInformationRequest" },
  {  46, "sendChargingInformation" },
  {  47, "playAnnouncement" },
  {  48, "promptAndCollectUserInformation" },
  {  49, "specializedResourceReport" },
  {  53, "cancel" },
  {  55, "activityTest" },
  {  56, "continueWithArgument" },
  {  60, "initialDPSMS" },
  {  61, "furnishChargingInformationSMS" },
  {  62, "connectSMS" },
  {  63, "requestReportSMSEvent" },
  {  64, "eventReportSMS" },
  {  65, "continueSMS" },
  {  66, "releaseSMS" },
  {  67, "resetTimerSMS" },
  {  70, "activityTestGPRS" },
  {  71, "applyChargingGPRS" },
  {  72, "applyChargingReportGPRS" },
  {  73, "cancelGPRS" },
  {  74, "connectGPRS" },
  {  75, "continueGPRS" },
  {  76, "entityReleasedGPRS" },
  {  77, "furnishChargingInformationGPRS" },
  {  78, "initialDPGPRS" },
  {  79, "releaseGPRS" },
  {  80, "eventReportGPRS" },
  {  81, "requestReportGPRSEvent" },
  {  82, "resetTimerGPRS" },
  {  83, "sendChargingInformationGPRS" },
  {  86, "dFCWithArgument" },
  {  88, "continueWithArgument" },
  {  90, "disconnectLeg" },
  {  93, "moveLeg" },
  {  95, "splitLeg" },
  {  96, "entityReleased" },
  {  97, "playTone" },
  { 0, NULL }
};


static int
dissect_camel_CAMELOperationLocalvalue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 43 "camel.cnf"

  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  &opcode);
 
  if (check_col(actx->pinfo->cinfo, COL_INFO)){
    col_append_fstr(actx->pinfo->cinfo, COL_INFO, 
       val_to_str(opcode, camel_opr_code_strings, "Unknown CAMEL (%u)"));
    col_append_str(actx->pinfo->cinfo, COL_INFO, " ");
    col_set_fence(actx->pinfo->cinfo, COL_INFO);
  }
  gp_camelsrt_info->opcode=opcode;



  return offset;
}



static int
dissect_camel_OperationLocalvalue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_camel_CAMELOperationLocalvalue(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_camel_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const value_string camel_OPERATION_vals[] = {
  {   0, "localValue" },
  {   1, "globalValue" },
  { 0, NULL }
};

static const ber_choice_t OPERATION_choice[] = {
  {   0, &hf_camel_localValue    , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_camel_OperationLocalvalue },
  {   1, &hf_camel_globalValue   , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_camel_OBJECT_IDENTIFIER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_OPERATION(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 OPERATION_choice, hf_index, ett_camel_OPERATION,
                                 NULL);

  return offset;
}



static int
dissect_camel_InvokeParameter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 27 "camel.cnf"
	offset = dissect_invokeData(tree, tvb, offset, actx);



  return offset;
}


static const ber_sequence_t Invoke_sequence[] = {
  { &hf_camel_invokeID      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_camel_InvokeIdType },
  { &hf_camel_linkedID      , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_InvokeIdType },
  { &hf_camel_opCode        , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_OPERATION },
  { &hf_camel_invokeparameter, BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_camel_InvokeParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_Invoke(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Invoke_sequence, hf_index, ett_camel_Invoke);

  return offset;
}



static int
dissect_camel_ReturnResultParameter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 31 "camel.cnf"
	offset = dissect_returnResultData(tree, tvb, offset, actx);



  return offset;
}


static const ber_sequence_t T_resultretres_sequence[] = {
  { &hf_camel_opCode        , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_OPERATION },
  { &hf_camel_returnparameter, BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_camel_ReturnResultParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_resultretres(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_resultretres_sequence, hf_index, ett_camel_T_resultretres);

  return offset;
}


static const ber_sequence_t ReturnResult_sequence[] = {
  { &hf_camel_invokeID      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_camel_InvokeIdType },
  { &hf_camel_resultretres  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_camel_T_resultretres },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_ReturnResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReturnResult_sequence, hf_index, ett_camel_ReturnResult);

  return offset;
}


static const value_string camel_CAMELLocalErrorcode_vals[] = {
  {   0, "canceled" },
  {   1, "cancelFailed" },
  {   3, "eTCFailed" },
  {   4, "improperCallerResponse" },
  {   6, "missingCustomerRecord" },
  {   7, "missingParameter" },
  {   8, "parameterOutOfRange" },
  {  10, "requestedInfoError" },
  {  11, "systemFailure" },
  {  12, "taskRefused" },
  {  13, "unavailableResource" },
  {  14, "unexpectedComponentSequence" },
  {  15, "unexpectedDataValue" },
  {  16, "unexpectedParameter" },
  {  17, "unknownLegID" },
  {  50, "unknownPDPID" },
  {  51, "unknownCSID" },
  { 0, NULL }
};


static int
dissect_camel_CAMELLocalErrorcode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  &errorCode);

  return offset;
}



static int
dissect_camel_LocalErrorcode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_camel_CAMELLocalErrorcode(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string camel_ERROR_vals[] = {
  {   0, "localErrorValue" },
  {   1, "globalErrorValue" },
  { 0, NULL }
};

static const ber_choice_t ERROR_choice[] = {
  {   0, &hf_camel_localErrorValue, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_camel_LocalErrorcode },
  {   1, &hf_camel_globalErrorValue, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_camel_OBJECT_IDENTIFIER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_ERROR(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ERROR_choice, hf_index, ett_camel_ERROR,
                                 NULL);

  return offset;
}



static int
dissect_camel_ReturnErrorParameter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 35 "camel.cnf"
	offset = dissect_returnErrorData(tree, tvb, offset, actx);



  return offset;
}


static const ber_sequence_t ReturnError_sequence[] = {
  { &hf_camel_invokeID      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_camel_InvokeIdType },
  { &hf_camel_errorCode     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_ERROR },
  { &hf_camel_parameter     , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_camel_ReturnErrorParameter },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_ReturnError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReturnError_sequence, hf_index, ett_camel_ReturnError);

  return offset;
}



static int
dissect_camel_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string camel_T_invokeIDRej_vals[] = {
  {   0, "derivable" },
  {   1, "not-derivable" },
  { 0, NULL }
};

static const ber_choice_t T_invokeIDRej_choice[] = {
  {   0, &hf_camel_derivable     , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_camel_InvokeIdType },
  {   1, &hf_camel_not_derivable , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_camel_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_invokeIDRej(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_invokeIDRej_choice, hf_index, ett_camel_T_invokeIDRej,
                                 NULL);

  return offset;
}


static const value_string camel_GeneralProblem_vals[] = {
  {   0, "unrecognizedComponent" },
  {   1, "mistypedComponent" },
  {   2, "badlyStructuredComponent" },
  { 0, NULL }
};


static int
dissect_camel_GeneralProblem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string camel_InvokeProblem_vals[] = {
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
dissect_camel_InvokeProblem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string camel_ReturnResultProblem_vals[] = {
  {   0, "unrecognizedInvokeID" },
  {   1, "returnResultUnexpected" },
  {   2, "mistypedParameter" },
  { 0, NULL }
};


static int
dissect_camel_ReturnResultProblem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string camel_ReturnErrorProblem_vals[] = {
  {   0, "unrecognizedInvokeID" },
  {   1, "returnErrorUnexpected" },
  {   2, "unrecognizedError" },
  {   3, "unexpectedError" },
  {   4, "mistypedParameter" },
  { 0, NULL }
};


static int
dissect_camel_ReturnErrorProblem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string camel_T_problem_vals[] = {
  {   0, "generalProblem" },
  {   1, "invokeProblem" },
  {   2, "returnResultProblem" },
  {   3, "returnErrorProblem" },
  { 0, NULL }
};

static const ber_choice_t T_problem_choice[] = {
  {   0, &hf_camel_generalProblem, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_GeneralProblem },
  {   1, &hf_camel_invokeProblem , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_InvokeProblem },
  {   2, &hf_camel_returnResultProblem, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_camel_ReturnResultProblem },
  {   3, &hf_camel_returnErrorProblem, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_camel_ReturnErrorProblem },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_problem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_problem_choice, hf_index, ett_camel_T_problem,
                                 NULL);

  return offset;
}


static const ber_sequence_t Reject_sequence[] = {
  { &hf_camel_invokeIDRej   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_T_invokeIDRej },
  { &hf_camel_problem       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_T_problem },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_Reject(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Reject_sequence, hf_index, ett_camel_Reject);

  return offset;
}


static const value_string camel_Component_vals[] = {
  {   1, "invoke" },
  {   2, "returnResultLast" },
  {   3, "returnError" },
  {   4, "reject" },
  { 0, NULL }
};

static const ber_choice_t Component_choice[] = {
  {   1, &hf_camel_invoke        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_Invoke },
  {   2, &hf_camel_returnResultLast, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_camel_ReturnResult },
  {   3, &hf_camel_returnError   , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_camel_ReturnError },
  {   4, &hf_camel_reject        , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_camel_Reject },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_Component(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Component_choice, hf_index, ett_camel_Component,
                                 NULL);

  return offset;
}



static int
dissect_camel_AccessPointName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_camel_INTEGER_1_864000(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_camel_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_camel_INTEGER_1_86400(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_camel_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string camel_Code_vals[] = {
  {   0, "local" },
  {   1, "global" },
  { 0, NULL }
};

static const ber_choice_t Code_choice[] = {
  {   0, &hf_camel_local         , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_camel_INTEGER },
  {   1, &hf_camel_global        , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_camel_OBJECT_IDENTIFIER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_Code(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Code_choice, hf_index, ett_camel_Code,
                                 NULL);

  return offset;
}



static int
dissect_camel_SupportedExtensionsid(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_camel_Code(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string camel_CriticalityType_vals[] = {
  {   0, "ignore" },
  {   1, "abort" },
  { 0, NULL }
};


static int
dissect_camel_CriticalityType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string camel_SupportedExtensionsExtensionType_vals[] = {
  {   0, "firstExtensionExtensionType" },
  { 0, NULL }
};

static const ber_choice_t SupportedExtensionsExtensionType_choice[] = {
  {   0, &hf_camel_firstExtensionExtensionType, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_camel_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_SupportedExtensionsExtensionType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SupportedExtensionsExtensionType_choice, hf_index, ett_camel_SupportedExtensionsExtensionType,
                                 NULL);

  return offset;
}


static const ber_sequence_t ExtensionField_sequence[] = {
  { &hf_camel_type          , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_SupportedExtensionsid },
  { &hf_camel_criticality   , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_camel_CriticalityType },
  { &hf_camel_value         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_SupportedExtensionsExtensionType },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_ExtensionField(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ExtensionField_sequence, hf_index, ett_camel_ExtensionField);

  return offset;
}


static const ber_sequence_t ExtensionsArray_sequence_of[1] = {
  { &hf_camel_ExtensionsArray_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_camel_ExtensionField },
};

static int
dissect_camel_ExtensionsArray(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      ExtensionsArray_sequence_of, hf_index, ett_camel_ExtensionsArray);

  return offset;
}


static const ber_sequence_t T_actimeDurationCharging_sequence[] = {
  { &hf_camel_maxCallPeriodDuration, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_1_864000 },
  { &hf_camel_releaseIfdurationExceeded, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_BOOLEAN },
  { &hf_camel_tariffSwitchInterval, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_1_86400 },
  { &hf_camel_actone        , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_BOOLEAN },
  { &hf_camel_extensions    , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ExtensionsArray },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_actimeDurationCharging(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_actimeDurationCharging_sequence, hf_index, ett_camel_T_actimeDurationCharging);

  return offset;
}


static const value_string camel_AChBillingChargingCharacteristics_vals[] = {
  {   0, "actimeDurationCharging" },
  { 0, NULL }
};

static const ber_choice_t AChBillingChargingCharacteristics_choice[] = {
  {   0, &hf_camel_actimeDurationCharging, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_T_actimeDurationCharging },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_AChBillingChargingCharacteristics(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AChBillingChargingCharacteristics_choice, hf_index, ett_camel_AChBillingChargingCharacteristics,
                                 NULL);

  return offset;
}



static int
dissect_camel_LegType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string camel_LegID_vals[] = {
  {   0, "sendingSideID" },
  {   1, "receivingSideID" },
  { 0, NULL }
};

static const ber_choice_t LegID_choice[] = {
  {   0, &hf_camel_sendingSideID , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_LegType },
  {   1, &hf_camel_receivingSideID, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_LegType },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_LegID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 LegID_choice, hf_index, ett_camel_LegID,
                                 NULL);

  return offset;
}



static int
dissect_camel_CallSegmentID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string camel_AChChargingAddress_vals[] = {
  {   2, "legID" },
  {  50, "srfConnection" },
  { 0, NULL }
};

static const ber_choice_t AChChargingAddress_choice[] = {
  {   2, &hf_camel_legID         , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_camel_LegID },
  {  50, &hf_camel_srfConnection , BER_CLASS_CON, 50, BER_FLAGS_IMPLTAG, dissect_camel_CallSegmentID },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_AChChargingAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AChChargingAddress_choice, hf_index, ett_camel_AChChargingAddress,
                                 NULL);

  return offset;
}



static int
dissect_camel_Digits(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_camel_AdditionalCallingPartyNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_camel_Digits(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_camel_AlertingPattern(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_camel_INTEGER_0_8191(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t CAI_Gsm0224_sequence[] = {
  { &hf_camel_e1            , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_0_8191 },
  { &hf_camel_e2            , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_0_8191 },
  { &hf_camel_e3            , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_0_8191 },
  { &hf_camel_e4            , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_0_8191 },
  { &hf_camel_e5            , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_0_8191 },
  { &hf_camel_e6            , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_0_8191 },
  { &hf_camel_e7            , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_0_8191 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_CAI_Gsm0224(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CAI_Gsm0224_sequence, hf_index, ett_camel_CAI_Gsm0224);

  return offset;
}


static const ber_sequence_t AOCSubsequent_sequence[] = {
  { &hf_camel_cAI_GSM0224   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_CAI_Gsm0224 },
  { &hf_camel_tariffSwitchInterval, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_1_86400 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_AOCSubsequent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AOCSubsequent_sequence, hf_index, ett_camel_AOCSubsequent);

  return offset;
}


static const ber_sequence_t AOCBeforeAnswer_sequence[] = {
  { &hf_camel_aOCInitial    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_CAI_Gsm0224 },
  { &hf_camel_aOCSubsequent , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_AOCSubsequent },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_AOCBeforeAnswer(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AOCBeforeAnswer_sequence, hf_index, ett_camel_AOCBeforeAnswer);

  return offset;
}


static const ber_sequence_t AOCGprs_sequence[] = {
  { &hf_camel_aOCInitial    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_CAI_Gsm0224 },
  { &hf_camel_aOCSubsequent , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_AOCSubsequent },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_AOCGprs(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AOCGprs_sequence, hf_index, ett_camel_AOCGprs);

  return offset;
}


static const value_string camel_AppendFreeFormatData_vals[] = {
  {   0, "overwrite" },
  {   1, "append" },
  { 0, NULL }
};


static int
dissect_camel_AppendFreeFormatData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_camel_ApplicationTimer(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_camel_AssistingSSPIPRoutingAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_camel_Digits(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_camel_INTEGER_1_1200(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_camel_INTEGER_1_3(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_camel_INTEGER_1_20(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t Burst_sequence[] = {
  { &hf_camel_numberOfBursts, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_1_3 },
  { &hf_camel_burstInterval , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_1_1200 },
  { &hf_camel_numberOfTonesInBurst, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_1_3 },
  { &hf_camel_toneDuration  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_1_20 },
  { &hf_camel_toneInterval  , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_1_20 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_Burst(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Burst_sequence, hf_index, ett_camel_Burst);

  return offset;
}


static const ber_sequence_t BurstList_sequence[] = {
  { &hf_camel_warningPeriod , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_1_1200 },
  { &hf_camel_bursts        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_Burst },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_BurstList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   BurstList_sequence, hf_index, ett_camel_BurstList);

  return offset;
}


static const value_string camel_AudibleIndicator_vals[] = {
  {   0, "istone" },
  {   1, "burstList" },
  { 0, NULL }
};

static const ber_choice_t AudibleIndicator_choice[] = {
  {   0, &hf_camel_istone        , BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_NOOWNTAG, dissect_camel_BOOLEAN },
  {   1, &hf_camel_burstList     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_BurstList },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_AudibleIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AudibleIndicator_choice, hf_index, ett_camel_AudibleIndicator,
                                 NULL);

  return offset;
}



static int
dissect_camel_OCTET_STRING_SIZE_1(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t BackwardServiceInteractionInd_sequence[] = {
  { &hf_camel_conferenceTreatmentIndicator, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_OCTET_STRING_SIZE_1 },
  { &hf_camel_callCompletionTreatmentIndicator, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_OCTET_STRING_SIZE_1 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_BackwardServiceInteractionInd(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   BackwardServiceInteractionInd_sequence, hf_index, ett_camel_BackwardServiceInteractionInd);

  return offset;
}



static int
dissect_camel_ServiceKey(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t GapOnService_sequence[] = {
  { &hf_camel_serviceKey    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_ServiceKey },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_GapOnService(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GapOnService_sequence, hf_index, ett_camel_GapOnService);

  return offset;
}


static const ber_sequence_t T_calledAddressAndService_sequence[] = {
  { &hf_camel_calledAddressValue, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_Digits },
  { &hf_camel_serviceKey    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_ServiceKey },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_calledAddressAndService(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_calledAddressAndService_sequence, hf_index, ett_camel_T_calledAddressAndService);

  return offset;
}


static const ber_sequence_t T_callingAddressAndService_sequence[] = {
  { &hf_camel_callingAddressValue, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_Digits },
  { &hf_camel_serviceKey    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_ServiceKey },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_callingAddressAndService(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_callingAddressAndService_sequence, hf_index, ett_camel_T_callingAddressAndService);

  return offset;
}


static const value_string camel_BasicGapCriteria_vals[] = {
  {   0, "calledAddressValue" },
  {   2, "gapOnService" },
  {  29, "calledAddressAndService" },
  {  30, "callingAddressAndService" },
  { 0, NULL }
};

static const ber_choice_t BasicGapCriteria_choice[] = {
  {   0, &hf_camel_calledAddressValue, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_Digits },
  {   2, &hf_camel_gapOnService  , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_camel_GapOnService },
  {  29, &hf_camel_calledAddressAndService, BER_CLASS_CON, 29, BER_FLAGS_IMPLTAG, dissect_camel_T_calledAddressAndService },
  {  30, &hf_camel_callingAddressAndService, BER_CLASS_CON, 30, BER_FLAGS_IMPLTAG, dissect_camel_T_callingAddressAndService },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_BasicGapCriteria(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 BasicGapCriteria_choice, hf_index, ett_camel_BasicGapCriteria,
                                 NULL);

  return offset;
}


static const value_string camel_EventTypeBCSM_vals[] = {
  {   2, "collectedInfo" },
  {   3, "analyzedInformation" },
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
  {  19, "oTermSeized" },
  {  27, "callAccepted" },
  {  50, "oChangeOfPosition" },
  {  51, "tChangeOfPosition" },
  {  52, "oServiceChange" },
  {  53, "tServiceChange" },
  { 0, NULL }
};


static int
dissect_camel_EventTypeBCSM(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string camel_MonitorMode_vals[] = {
  {   0, "interrupted" },
  {   1, "notifyAndContinue" },
  {   2, "transparent" },
  { 0, NULL }
};


static int
dissect_camel_MonitorMode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_camel_INTEGER_1_30(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_camel_OCTET_STRING_SIZE_1_2(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_camel_INTEGER_1_127(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t MidCallControlInfo_sequence[] = {
  { &hf_camel_minimumNumberOfDigits, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_1_30 },
  { &hf_camel_maximumNumberOfDigits, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_1_30 },
  { &hf_camel_endOfReplyDigit, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_OCTET_STRING_SIZE_1_2 },
  { &hf_camel_cancelDigit   , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_OCTET_STRING_SIZE_1_2 },
  { &hf_camel_startDigit    , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_OCTET_STRING_SIZE_1_2 },
  { &hf_camel_interDigitTimeout, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_1_127 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_MidCallControlInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MidCallControlInfo_sequence, hf_index, ett_camel_MidCallControlInfo);

  return offset;
}


static const ber_sequence_t ChangeOfLocationAlt_sequence[] = {
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_ChangeOfLocationAlt(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ChangeOfLocationAlt_sequence, hf_index, ett_camel_ChangeOfLocationAlt);

  return offset;
}


static const value_string camel_ChangeOfLocation_vals[] = {
  {   0, "cellGlobalId" },
  {   1, "serviceAreaId" },
  {   2, "locationAreaId" },
  {   3, "inter-SystemHandOver" },
  {   4, "inter-PLMNHandOver" },
  {   5, "inter-MSCHandOver" },
  {   6, "changeOfLocationAlt" },
  { 0, NULL }
};

static const ber_choice_t ChangeOfLocation_choice[] = {
  {   0, &hf_camel_cellGlobalId  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gsm_map_CellGlobalIdOrServiceAreaIdFixedLength },
  {   1, &hf_camel_serviceAreaId , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gsm_map_CellGlobalIdOrServiceAreaIdFixedLength },
  {   2, &hf_camel_locationAreaId, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_gsm_map_LAIFixedLength },
  {   3, &hf_camel_inter_SystemHandOver, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  {   4, &hf_camel_inter_PLMNHandOver, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  {   5, &hf_camel_inter_MSCHandOver, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  {   6, &hf_camel_changeOfLocationAlt, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_camel_ChangeOfLocationAlt },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_ChangeOfLocation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ChangeOfLocation_choice, hf_index, ett_camel_ChangeOfLocation,
                                 NULL);

  return offset;
}


static const ber_sequence_t ChangeOfPositionControlInfo_sequence_of[1] = {
  { &hf_camel_ChangeOfPositionControlInfo_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_ChangeOfLocation },
};

static int
dissect_camel_ChangeOfPositionControlInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      ChangeOfPositionControlInfo_sequence_of, hf_index, ett_camel_ChangeOfPositionControlInfo);

  return offset;
}



static int
dissect_camel_NumberOfDigits(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t DpSpecificCriteriaAlt_sequence[] = {
  { &hf_camel_changeOfPositionControlInfo, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_ChangeOfPositionControlInfo },
  { &hf_camel_numberOfDigits, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_NumberOfDigits },
  { &hf_camel_interDigitTimeout, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_1_127 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_DpSpecificCriteriaAlt(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DpSpecificCriteriaAlt_sequence, hf_index, ett_camel_DpSpecificCriteriaAlt);

  return offset;
}


static const value_string camel_DpSpecificCriteria_vals[] = {
  {   1, "applicationTimer" },
  {   2, "midCallControlInfo" },
  {   3, "dpSpecificCriteriaAlt" },
  { 0, NULL }
};

static const ber_choice_t DpSpecificCriteria_choice[] = {
  {   1, &hf_camel_applicationTimer, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_ApplicationTimer },
  {   2, &hf_camel_midCallControlInfo, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_camel_MidCallControlInfo },
  {   3, &hf_camel_dpSpecificCriteriaAlt, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_camel_DpSpecificCriteriaAlt },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_DpSpecificCriteria(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 DpSpecificCriteria_choice, hf_index, ett_camel_DpSpecificCriteria,
                                 NULL);

  return offset;
}


static const ber_sequence_t BCSMEvent_sequence[] = {
  { &hf_camel_eventTypeBCSM , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_EventTypeBCSM },
  { &hf_camel_monitorMode   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_MonitorMode },
  { &hf_camel_legID6        , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_LegID },
  { &hf_camel_dpSpecificCriteria, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_DpSpecificCriteria },
  { &hf_camel_automaticRearm, BER_CLASS_CON, 50, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_BCSMEvent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   BCSMEvent_sequence, hf_index, ett_camel_BCSMEvent);

  return offset;
}



static int
dissect_camel_Cause(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 135 "camel.cnf"

       tvbuff_t *camel_tvb;
       guint8 Cause_value;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &camel_tvb);


       if (camel_tvb)
           dissect_q931_cause_ie(camel_tvb, 0, tvb_length_remaining(camel_tvb,0), tree, hf_camel_cause_indicator, &Cause_value);


       return offset;


  return offset;
}


static const ber_sequence_t BCSM_Failure_sequence[] = {
  { &hf_camel_legID         , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_LegID },
  { &hf_camel_cause         , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_Cause },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_BCSM_Failure(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   BCSM_Failure_sequence, hf_index, ett_camel_BCSM_Failure);

  return offset;
}



static int
dissect_camel_BearerCap(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 286 "camel.cnf"

 tvbuff_t	*parameter_tvb;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


 if (!parameter_tvb)
	return offset;

 dissect_q931_bearer_capability_ie(parameter_tvb, 0, tvb_length_remaining(parameter_tvb,0), tree);


  return offset;
}


static const value_string camel_BearerCapability_vals[] = {
  {   0, "bearerCap" },
  { 0, NULL }
};

static const ber_choice_t BearerCapability_choice[] = {
  {   0, &hf_camel_bearerCap     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_BearerCap },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_BearerCapability(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 BearerCapability_choice, hf_index, ett_camel_BearerCapability,
                                 NULL);

  return offset;
}



static int
dissect_camel_ISDN_AddressString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 94 "camel.cnf"

 tvbuff_t	*parameter_tvb;
 char		*digit_str;
 proto_item *item;
 proto_tree *subtree;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


 if (!parameter_tvb)
	return offset;
 item = get_ber_last_created_item();
 subtree = proto_item_add_subtree(item, ett_camel_isdn_address_string);
  
 proto_tree_add_item(subtree, hf_camel_addr_extension, parameter_tvb, 0,1,FALSE);
 
 proto_tree_add_item(subtree, hf_camel_addr_natureOfAddressIndicator, parameter_tvb, 0,1,FALSE);
 proto_tree_add_item(subtree, hf_camel_addr_numberingPlanInd, parameter_tvb, 0,1,FALSE);
 digit_str = unpack_digits(parameter_tvb, 1);

 proto_tree_add_string(subtree, hf_camel_addr_digits, parameter_tvb, 1, -1, digit_str);


  return offset;
}



static int
dissect_camel_CalledPartyBCDNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_camel_ISDN_AddressString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_camel_CalledPartyNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 77 "camel.cnf"


 tvbuff_t *isup_tvb;
 guint32 len;

 len=tvb_length_remaining(tvb,offset);
 isup_tvb = tvb_new_subset(tvb, offset,-1 , -1 );
 dissect_isup_called_party_number_parameter(isup_tvb, tree, NULL);
 offset += len;
 


  return offset;
}



static int
dissect_camel_CallingPartyNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 60 "camel.cnf"


 proto_item* parameter_item;
 proto_item* parameter_tree;
 tvbuff_t *isup_tvb;
 guint32 len;

 len=tvb_length_remaining(tvb,offset);
 parameter_item = proto_tree_add_item(tree, hf_index, tvb, offset, -1, FALSE);
 parameter_tree = proto_item_add_subtree(parameter_item, ett_camelisup_parameter);
 isup_tvb = tvb_new_subset(tvb, offset,-1 , -1 );
 dissect_isup_calling_party_number_parameter(isup_tvb, parameter_tree, parameter_item);
 offset += len;


  return offset;
}


static const value_string camel_ReceivingSideID_vals[] = {
  {   1, "receivingSideID" },
  { 0, NULL }
};

static const ber_choice_t ReceivingSideID_choice[] = {
  {   1, &hf_camel_receivingSideID, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_LegType },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_ReceivingSideID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ReceivingSideID_choice, hf_index, ett_camel_ReceivingSideID,
                                 NULL);

  return offset;
}



static int
dissect_camel_TimeIfNoTariffSwitch(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_camel_INTEGER_0_864000(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t TimeIfTariffSwitch_sequence[] = {
  { &hf_camel_timeSinceTariffSwitch, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_0_864000 },
  { &hf_camel_tttariffSwitchInterval, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_1_864000 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_TimeIfTariffSwitch(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TimeIfTariffSwitch_sequence, hf_index, ett_camel_TimeIfTariffSwitch);

  return offset;
}


static const value_string camel_TimeInformation_vals[] = {
  {   0, "timeIfNoTariffSwitch" },
  {   1, "timeIfTariffSwitch" },
  { 0, NULL }
};

static const ber_choice_t TimeInformation_choice[] = {
  {   0, &hf_camel_timeIfNoTariffSwitch, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_TimeIfNoTariffSwitch },
  {   1, &hf_camel_timeIfTariffSwitch, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_TimeIfTariffSwitch },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_TimeInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 TimeInformation_choice, hf_index, ett_camel_TimeInformation,
                                 NULL);

  return offset;
}


static const ber_sequence_t TimeDurationChargingResult_sequence[] = {
  { &hf_camel_partyToCharge , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_ReceivingSideID },
  { &hf_camel_timeInformation, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_TimeInformation },
  { &hf_camel_legActive     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_BOOLEAN },
  { &hf_camel_callLegReleasedAtTcpExpiry, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  { &hf_camel_extensions    , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ExtensionsArray },
  { &hf_camel_aChChargingAddress, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_AChChargingAddress },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_TimeDurationChargingResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TimeDurationChargingResult_sequence, hf_index, ett_camel_TimeDurationChargingResult);

  return offset;
}


static const value_string camel_CAMEL_CallResult_vals[] = {
  {   0, "timeDurationChargingResult" },
  {  99, "void" },
  { 0, NULL }
};

static const ber_choice_t CAMEL_CallResult_choice[] = {
  {   0, &hf_camel_timeDurationChargingResult, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_TimeDurationChargingResult },
  {  99, &hf_camel_void          , BER_CLASS_CON, 99, BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_CAMEL_CallResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CAMEL_CallResult_choice, hf_index, ett_camel_CAMEL_CallResult,
                                 NULL);

  return offset;
}



static int
dissect_camel_CallResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_camel_CAMEL_CallResult(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t CallSegmentFailure_sequence[] = {
  { &hf_camel_callSegmentID , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_CallSegmentID },
  { &hf_camel_cause         , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_Cause },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_CallSegmentFailure(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CallSegmentFailure_sequence, hf_index, ett_camel_CallSegmentFailure);

  return offset;
}



static int
dissect_camel_InvokeID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_camel_InvokeIdType(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t CallSegmentToCancel_sequence[] = {
  { &hf_camel_callInvokeID  , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_InvokeID },
  { &hf_camel_callSegmentID , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_CallSegmentID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_CallSegmentToCancel(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CallSegmentToCancel_sequence, hf_index, ett_camel_CallSegmentToCancel);

  return offset;
}


static const ber_sequence_t T_timeDurationCharging_sequence[] = {
  { &hf_camel_maxCallPeriodDuration, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_1_864000 },
  { &hf_camel_releaseIfdurationExceeded, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_BOOLEAN },
  { &hf_camel_tariffSwitchInterval, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_1_86400 },
  { &hf_camel_audibleIndicator, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_AudibleIndicator },
  { &hf_camel_extensions    , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ExtensionsArray },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_timeDurationCharging(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_timeDurationCharging_sequence, hf_index, ett_camel_T_timeDurationCharging);

  return offset;
}


static const value_string camel_CAMEL_AChBillingChargingCharacteristics_vals[] = {
  {   0, "timeDurationCharging" },
  { 0, NULL }
};

static const ber_choice_t CAMEL_AChBillingChargingCharacteristics_choice[] = {
  {   0, &hf_camel_timeDurationCharging, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_T_timeDurationCharging },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_CAMEL_AChBillingChargingCharacteristics(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CAMEL_AChBillingChargingCharacteristics_choice, hf_index, ett_camel_CAMEL_AChBillingChargingCharacteristics,
                                 NULL);

  return offset;
}



static int
dissect_camel_FreeFormatData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string camel_SendingSideID_vals[] = {
  {   0, "sendingSideID" },
  { 0, NULL }
};

static const ber_choice_t SendingSideID_choice[] = {
  {   0, &hf_camel_sendingSideID , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_LegType },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_SendingSideID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SendingSideID_choice, hf_index, ett_camel_SendingSideID,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_fCIBCCCAMELsequence1_sequence[] = {
  { &hf_camel_freeFormatData, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_FreeFormatData },
  { &hf_camel_partyToCharge4, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_SendingSideID },
  { &hf_camel_appendFreeFormatData, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_AppendFreeFormatData },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_fCIBCCCAMELsequence1(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_fCIBCCCAMELsequence1_sequence, hf_index, ett_camel_T_fCIBCCCAMELsequence1);

  return offset;
}


static const value_string camel_CAMEL_FCIBillingChargingCharacteristics_vals[] = {
  {   0, "fCIBCCCAMELsequence1" },
  { 0, NULL }
};

static const ber_choice_t CAMEL_FCIBillingChargingCharacteristics_choice[] = {
  {   0, &hf_camel_fCIBCCCAMELsequence1, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_T_fCIBCCCAMELsequence1 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_CAMEL_FCIBillingChargingCharacteristics(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CAMEL_FCIBillingChargingCharacteristics_choice, hf_index, ett_camel_CAMEL_FCIBillingChargingCharacteristics,
                                 NULL);

  return offset;
}



static int
dissect_camel_PDPId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t T_fCIBCCCAMELsequence2_sequence[] = {
  { &hf_camel_freeFormatData, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_FreeFormatData },
  { &hf_camel_pDPID         , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_PDPId },
  { &hf_camel_appendFreeFormatData, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_AppendFreeFormatData },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_fCIBCCCAMELsequence2(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_fCIBCCCAMELsequence2_sequence, hf_index, ett_camel_T_fCIBCCCAMELsequence2);

  return offset;
}


static const ber_sequence_t CAMEL_FCIGPRSBillingChargingCharacteristics_sequence[] = {
  { &hf_camel_fCIBCCCAMELsequence2, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_T_fCIBCCCAMELsequence2 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_CAMEL_FCIGPRSBillingChargingCharacteristics(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CAMEL_FCIGPRSBillingChargingCharacteristics_sequence, hf_index, ett_camel_CAMEL_FCIGPRSBillingChargingCharacteristics);

  return offset;
}


static const ber_sequence_t T_fCIBCCCAMELsequence3_sequence[] = {
  { &hf_camel_freeFormatData, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_FreeFormatData },
  { &hf_camel_appendFreeFormatData, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_AppendFreeFormatData },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_fCIBCCCAMELsequence3(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_fCIBCCCAMELsequence3_sequence, hf_index, ett_camel_T_fCIBCCCAMELsequence3);

  return offset;
}


static const value_string camel_CAMEL_FCISMSBillingChargingCharacteristics_vals[] = {
  {   0, "fCIBCCCAMELsequence3" },
  { 0, NULL }
};

static const ber_choice_t CAMEL_FCISMSBillingChargingCharacteristics_choice[] = {
  {   0, &hf_camel_fCIBCCCAMELsequence3, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_T_fCIBCCCAMELsequence3 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_CAMEL_FCISMSBillingChargingCharacteristics(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CAMEL_FCISMSBillingChargingCharacteristics_choice, hf_index, ett_camel_CAMEL_FCISMSBillingChargingCharacteristics,
                                 NULL);

  return offset;
}


static const ber_sequence_t CAMEL_SCIBillingChargingCharacteristicsAlt_sequence[] = {
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_CAMEL_SCIBillingChargingCharacteristicsAlt(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CAMEL_SCIBillingChargingCharacteristicsAlt_sequence, hf_index, ett_camel_CAMEL_SCIBillingChargingCharacteristicsAlt);

  return offset;
}


static const value_string camel_CAMEL_SCIBillingChargingCharacteristics_vals[] = {
  {   0, "aOCBeforeAnswer" },
  {   1, "aOCAfterAnswer" },
  {   2, "aOC-extension" },
  { 0, NULL }
};

static const ber_choice_t CAMEL_SCIBillingChargingCharacteristics_choice[] = {
  {   0, &hf_camel_aOCBeforeAnswer, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_AOCBeforeAnswer },
  {   1, &hf_camel_aOCAfterAnswer, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_AOCSubsequent },
  {   2, &hf_camel_aOC_extension , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_camel_CAMEL_SCIBillingChargingCharacteristicsAlt },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_CAMEL_SCIBillingChargingCharacteristics(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CAMEL_SCIBillingChargingCharacteristics_choice, hf_index, ett_camel_CAMEL_SCIBillingChargingCharacteristics,
                                 NULL);

  return offset;
}


static const ber_sequence_t CamelSCIGPRSBillingChargingCharacteristics_sequence[] = {
  { &hf_camel_aOCGPRS       , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_AOCGprs },
  { &hf_camel_pDPID         , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_PDPId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_CamelSCIGPRSBillingChargingCharacteristics(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CamelSCIGPRSBillingChargingCharacteristics_sequence, hf_index, ett_camel_CamelSCIGPRSBillingChargingCharacteristics);

  return offset;
}



static int
dissect_camel_Carrier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string camel_CGEncountered_vals[] = {
  {   0, "noCGencountered" },
  {   1, "manualCGencountered" },
  {   2, "scpOverload" },
  { 0, NULL }
};


static int
dissect_camel_CGEncountered(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_camel_ChargeIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_camel_LocationNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_camel_ChargeNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_camel_LocationNumber(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_camel_INTEGER_1_4294967295(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string camel_ChargingCharacteristics_vals[] = {
  {   0, "maxTransferredVolume" },
  {   1, "maxElapsedTime" },
  { 0, NULL }
};

static const ber_choice_t ChargingCharacteristics_choice[] = {
  {   0, &hf_camel_maxTransferredVolume, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_1_4294967295 },
  {   1, &hf_camel_maxElapsedTime, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_1_86400 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_ChargingCharacteristics(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ChargingCharacteristics_choice, hf_index, ett_camel_ChargingCharacteristics,
                                 NULL);

  return offset;
}



static int
dissect_camel_INTEGER_0_4294967295(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t T_volumeIfTariffSwitch_sequence[] = {
  { &hf_camel_volumeSinceLastTariffSwitch, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_0_4294967295 },
  { &hf_camel_volumeTariffSwitchInterval, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_0_4294967295 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_volumeIfTariffSwitch(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_volumeIfTariffSwitch_sequence, hf_index, ett_camel_T_volumeIfTariffSwitch);

  return offset;
}


static const value_string camel_TransferredVolume_vals[] = {
  {   0, "volumeIfNoTariffSwitch" },
  {   1, "volumeIfTariffSwitch" },
  { 0, NULL }
};

static const ber_choice_t TransferredVolume_choice[] = {
  {   0, &hf_camel_volumeIfNoTariffSwitch, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_0_4294967295 },
  {   1, &hf_camel_volumeIfTariffSwitch, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_T_volumeIfTariffSwitch },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_TransferredVolume(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 TransferredVolume_choice, hf_index, ett_camel_TransferredVolume,
                                 NULL);

  return offset;
}



static int
dissect_camel_INTEGER_0_86400(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t T_timeGPRSIfTariffSwitch_sequence[] = {
  { &hf_camel_timeGPRSSinceLastTariffSwitch, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_0_86400 },
  { &hf_camel_timeGPRSTariffSwitchInterval, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_0_86400 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_timeGPRSIfTariffSwitch(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_timeGPRSIfTariffSwitch_sequence, hf_index, ett_camel_T_timeGPRSIfTariffSwitch);

  return offset;
}


static const value_string camel_ElapsedTime_vals[] = {
  {   0, "timeGPRSIfNoTariffSwitch" },
  {   1, "timeGPRSIfTariffSwitch" },
  { 0, NULL }
};

static const ber_choice_t ElapsedTime_choice[] = {
  {   0, &hf_camel_timeGPRSIfNoTariffSwitch, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_0_86400 },
  {   1, &hf_camel_timeGPRSIfTariffSwitch, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_T_timeGPRSIfTariffSwitch },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_ElapsedTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ElapsedTime_choice, hf_index, ett_camel_ElapsedTime,
                                 NULL);

  return offset;
}


static const value_string camel_ChargingResult_vals[] = {
  {   0, "transferredVolume" },
  {   1, "elapsedTime" },
  { 0, NULL }
};

static const ber_choice_t ChargingResult_choice[] = {
  {   0, &hf_camel_transferredVolume, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_TransferredVolume },
  {   1, &hf_camel_elapsedTime   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_ElapsedTime },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_ChargingResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ChargingResult_choice, hf_index, ett_camel_ChargingResult,
                                 NULL);

  return offset;
}



static int
dissect_camel_INTEGER_0_255(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t T_rOVolumeIfTariffSwitch_sequence[] = {
  { &hf_camel_rOVolumeSinceLastTariffSwitch, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_0_255 },
  { &hf_camel_rOVolumeTariffSwitchInterval, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_0_255 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_rOVolumeIfTariffSwitch(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_rOVolumeIfTariffSwitch_sequence, hf_index, ett_camel_T_rOVolumeIfTariffSwitch);

  return offset;
}


static const value_string camel_TransferredVolumeRollOver_vals[] = {
  {   0, "rOVolumeIfNoTariffSwitch" },
  {   1, "rOVolumeIfTariffSwitch" },
  { 0, NULL }
};

static const ber_choice_t TransferredVolumeRollOver_choice[] = {
  {   0, &hf_camel_rOVolumeIfNoTariffSwitch, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_0_255 },
  {   1, &hf_camel_rOVolumeIfTariffSwitch, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_T_rOVolumeIfTariffSwitch },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_TransferredVolumeRollOver(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 TransferredVolumeRollOver_choice, hf_index, ett_camel_TransferredVolumeRollOver,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_rOTimeGPRSIfTariffSwitch_sequence[] = {
  { &hf_camel_rOTimeGPRSSinceLastTariffSwitch, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_0_255 },
  { &hf_camel_rOTimeGPRSTariffSwitchInterval, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_0_255 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_rOTimeGPRSIfTariffSwitch(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_rOTimeGPRSIfTariffSwitch_sequence, hf_index, ett_camel_T_rOTimeGPRSIfTariffSwitch);

  return offset;
}


static const value_string camel_ElapsedTimeRollOver_vals[] = {
  {   0, "rOTimeGPRSIfNoTariffSwitch" },
  {   1, "rOTimeGPRSIfTariffSwitch" },
  { 0, NULL }
};

static const ber_choice_t ElapsedTimeRollOver_choice[] = {
  {   0, &hf_camel_rOTimeGPRSIfNoTariffSwitch, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_0_255 },
  {   1, &hf_camel_rOTimeGPRSIfTariffSwitch, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_T_rOTimeGPRSIfTariffSwitch },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_ElapsedTimeRollOver(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ElapsedTimeRollOver_choice, hf_index, ett_camel_ElapsedTimeRollOver,
                                 NULL);

  return offset;
}


static const value_string camel_ChargingRollOver_vals[] = {
  {   0, "transferredVolumeRollOver" },
  {   1, "elapsedTimeRollOver" },
  { 0, NULL }
};

static const ber_choice_t ChargingRollOver_choice[] = {
  {   0, &hf_camel_transferredVolumeRollOver, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_TransferredVolumeRollOver },
  {   1, &hf_camel_elapsedTimeRollOver, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_ElapsedTimeRollOver },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_ChargingRollOver(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ChargingRollOver_choice, hf_index, ett_camel_ChargingRollOver,
                                 NULL);

  return offset;
}


static const value_string camel_ErrorTreatment_vals[] = {
  {   0, "stdErrorAndInfo" },
  {   1, "help" },
  {   2, "repeatPrompt" },
  { 0, NULL }
};


static int
dissect_camel_ErrorTreatment(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t CollectedDigits_sequence[] = {
  { &hf_camel_minimumNbOfDigits, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_1_30 },
  { &hf_camel_maximumNbOfDigits, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_1_30 },
  { &hf_camel_endOfReplyDigit, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_OCTET_STRING_SIZE_1_2 },
  { &hf_camel_cancelDigit   , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_OCTET_STRING_SIZE_1_2 },
  { &hf_camel_startDigit    , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_OCTET_STRING_SIZE_1_2 },
  { &hf_camel_firstDigitTimeOut, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_1_127 },
  { &hf_camel_interDigitTimeOut, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_1_127 },
  { &hf_camel_errorTreatment, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ErrorTreatment },
  { &hf_camel_interruptableAnnInd, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_BOOLEAN },
  { &hf_camel_voiceInformation, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_BOOLEAN },
  { &hf_camel_voiceBack     , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_CollectedDigits(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CollectedDigits_sequence, hf_index, ett_camel_CollectedDigits);

  return offset;
}


static const value_string camel_CollectedInfo_vals[] = {
  {   0, "collectedDigits" },
  { 0, NULL }
};

static const ber_choice_t CollectedInfo_choice[] = {
  {   0, &hf_camel_collectedDigits, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_CollectedDigits },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_CollectedInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CollectedInfo_choice, hf_index, ett_camel_CollectedInfo,
                                 NULL);

  return offset;
}


static const value_string camel_ConnectedNumberTreatmentInd_vals[] = {
  {   0, "noINImpact" },
  {   1, "presentationRestricted" },
  {   2, "presentCalledINNumber" },
  {   3, "presentCallINNumberRestricted" },
  { 0, NULL }
};


static int
dissect_camel_ConnectedNumberTreatmentInd(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string camel_ControlType_vals[] = {
  {   0, "sCPOverloaded" },
  {   1, "manuallyInitiated" },
  { 0, NULL }
};


static int
dissect_camel_ControlType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_camel_ScfID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t CompoundCriteria_sequence[] = {
  { &hf_camel_basicGapCriteria, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_BasicGapCriteria },
  { &hf_camel_scfID         , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ScfID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_CompoundCriteria(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CompoundCriteria_sequence, hf_index, ett_camel_CompoundCriteria);

  return offset;
}



static int
dissect_camel_CorrelationID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_camel_Digits(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_camel_DateAndTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 185 "camel.cnf"


/* 
* date_option = 1 european dd:mm:yyyy
* date_option = 2 american mm:dd:yyyy
*/

/*
* Output should be HH:MM:SS;dd/mm/yyyy
* if european is selected, and HH:MM:SS;mm/dd/yyyy
* otherwise.
*/

  guint8 digit_pair;
  guint8 i = 0, curr_offset; 
  char time[CAMEL_DATE_AND_TIME_LEN];
  char c[CAMEL_DATE_AND_TIME_LEN]; /*temporary container*/

  /* 2 digits per octet, 7 octets total + 5 delimiters */
    
  for (curr_offset = 0; curr_offset < 7 ; curr_offset++)    
  /*Loop to extract date*/
  {
      digit_pair = tvb_get_guint8(tvb, curr_offset);
      
      proto_tree_add_uint(tree,
                          hf_digit,
                          tvb,
                          curr_offset,
                          1,
                          digit_pair & 0x0F);

      proto_tree_add_uint(tree,
                          hf_digit,
                          tvb,
                          curr_offset,
                          1,
                          digit_pair >>4);
			  
      
      c[i] = camel_number_to_char( digit_pair & 0x0F);
      i++;
      c[i] = camel_number_to_char( digit_pair >>4);
      i++;
  }
  
  /* Pretty print date */
  /* XXX - Should we use sprintf here instead of assembling the string by
   * hand? */
  
  time[0] = c[8];
  time[1] = c[9];
  time[2] = ':';
  time[3] = c[10];
  time[4] = c[11];
  time[5] = ':';
  time[6] = c[12];
  time[7] = c[13];
  time[8] = ';';
  if ( EUROPEAN_DATE == date_format) /*european*/
  {
    time[9] = c[6]; /*day*/
    time[10] = c[7];
    time[11] = '/'; 
    time[12] = c[4]; /*month*/
    time[13] = c[5];
  }
  else /*american*/
  {
    time[9] = c[4]; /*month*/
    time[10] = c[5];
    time[11] = '/'; 
    time[12] = c[6]; /*day*/
    time[13] = c[7];
  }
  time[14] = '/';
  time[15] = c[0];
  time[16] = c[1];
  time[17] = c[2];
  time[18] = c[3];

  time[CAMEL_DATE_AND_TIME_LEN - 1] = '\0';
 
/*start = 0, length = 7*/
 
  proto_tree_add_string(tree, 
		      hf_index, 
		      tvb,
		      0, 
		      7, 
		      time);

  return 7; /* 7  octets eaten*/


  return offset;
}


static const ber_sequence_t DestinationRoutingAddress_sequence_of[1] = {
  { &hf_camel_DestinationRoutingAddress_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_camel_CalledPartyNumber },
};

static int
dissect_camel_DestinationRoutingAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      DestinationRoutingAddress_sequence_of, hf_index, ett_camel_DestinationRoutingAddress);

  return offset;
}


static const value_string camel_InitiatorOfServiceChange_vals[] = {
  {   0, "a-side" },
  {   1, "b-side" },
  { 0, NULL }
};


static int
dissect_camel_InitiatorOfServiceChange(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string camel_NatureOfServiceChange_vals[] = {
  {   0, "userInitiated" },
  {   1, "networkInitiated" },
  { 0, NULL }
};


static int
dissect_camel_NatureOfServiceChange(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t T_oServiceChangeSpecificInfo_sequence[] = {
  { &hf_camel_ext_basicServiceCode, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_Ext_BasicServiceCode },
  { &hf_camel_initiatorOfServiceChange, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_InitiatorOfServiceChange },
  { &hf_camel_natureOfServiceChange, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_NatureOfServiceChange },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_oServiceChangeSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_oServiceChangeSpecificInfo_sequence, hf_index, ett_camel_T_oServiceChangeSpecificInfo);

  return offset;
}


static const ber_sequence_t T_tServiceChangeSpecificInfo_sequence[] = {
  { &hf_camel_ext_basicServiceCode, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_Ext_BasicServiceCode },
  { &hf_camel_initiatorOfServiceChange, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_InitiatorOfServiceChange },
  { &hf_camel_natureOfServiceChange, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_NatureOfServiceChange },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_tServiceChangeSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_tServiceChangeSpecificInfo_sequence, hf_index, ett_camel_T_tServiceChangeSpecificInfo);

  return offset;
}


static const ber_sequence_t DpSpecificInfoAlt_sequence[] = {
  { &hf_camel_oServiceChangeSpecificInfo, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_T_oServiceChangeSpecificInfo },
  { &hf_camel_tServiceChangeSpecificInfo, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_T_tServiceChangeSpecificInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_DpSpecificInfoAlt(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DpSpecificInfoAlt_sequence, hf_index, ett_camel_DpSpecificInfoAlt);

  return offset;
}


static const ber_sequence_t T_routeSelectFailureSpecificInfo_sequence[] = {
  { &hf_camel_failureCause  , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_Cause },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_routeSelectFailureSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_routeSelectFailureSpecificInfo_sequence, hf_index, ett_camel_T_routeSelectFailureSpecificInfo);

  return offset;
}


static const ber_sequence_t T_oCalledPartyBusySpecificInfo_sequence[] = {
  { &hf_camel_busyCause     , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_Cause },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_oCalledPartyBusySpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_oCalledPartyBusySpecificInfo_sequence, hf_index, ett_camel_T_oCalledPartyBusySpecificInfo);

  return offset;
}


static const ber_sequence_t T_oNoAnswerSpecificInfo_sequence[] = {
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_oNoAnswerSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_oNoAnswerSpecificInfo_sequence, hf_index, ett_camel_T_oNoAnswerSpecificInfo);

  return offset;
}


static const ber_sequence_t T_oAnswerSpecificInfo_sequence[] = {
  { &hf_camel_destinationAddress, BER_CLASS_CON, 50, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_CalledPartyNumber },
  { &hf_camel_or_Call       , BER_CLASS_CON, 51, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  { &hf_camel_forwardedCall , BER_CLASS_CON, 52, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  { &hf_camel_chargeIndicator, BER_CLASS_CON, 53, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ChargeIndicator },
  { &hf_camel_ext_basicServiceCode, BER_CLASS_CON, 54, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_Ext_BasicServiceCode },
  { &hf_camel_ext_basicServiceCode2, BER_CLASS_CON, 55, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_Ext_BasicServiceCode },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_oAnswerSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_oAnswerSpecificInfo_sequence, hf_index, ett_camel_T_oAnswerSpecificInfo);

  return offset;
}


static const value_string camel_T_omidCallEvents_vals[] = {
  {   3, "dTMFDigitsCompleted" },
  {   4, "dTMFDigitsTimeOut" },
  { 0, NULL }
};

static const ber_choice_t T_omidCallEvents_choice[] = {
  {   3, &hf_camel_dTMFDigitsCompleted, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_camel_Digits },
  {   4, &hf_camel_dTMFDigitsTimeOut, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_camel_Digits },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_omidCallEvents(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_omidCallEvents_choice, hf_index, ett_camel_T_omidCallEvents,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_oMidCallSpecificInfo_sequence[] = {
  { &hf_camel_omidCallEvents, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_T_omidCallEvents },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_oMidCallSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_oMidCallSpecificInfo_sequence, hf_index, ett_camel_T_oMidCallSpecificInfo);

  return offset;
}


static const ber_sequence_t T_oDisconnectSpecificInfo_sequence[] = {
  { &hf_camel_releaseCause  , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_Cause },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_oDisconnectSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_oDisconnectSpecificInfo_sequence, hf_index, ett_camel_T_oDisconnectSpecificInfo);

  return offset;
}


static const ber_sequence_t T_tBusySpecificInfo_sequence[] = {
  { &hf_camel_busyCause     , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_Cause },
  { &hf_camel_callForwarded , BER_CLASS_CON, 50, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  { &hf_camel_routeNotPermitted, BER_CLASS_CON, 51, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  { &hf_camel_forwardingDestinationNumber, BER_CLASS_CON, 52, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_CalledPartyNumber },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_tBusySpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_tBusySpecificInfo_sequence, hf_index, ett_camel_T_tBusySpecificInfo);

  return offset;
}


static const ber_sequence_t T_tNoAnswerSpecificInfo_sequence[] = {
  { &hf_camel_callForwarded , BER_CLASS_CON, 50, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  { &hf_camel_forwardingDestinationNumber, BER_CLASS_CON, 52, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_CalledPartyNumber },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_tNoAnswerSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_tNoAnswerSpecificInfo_sequence, hf_index, ett_camel_T_tNoAnswerSpecificInfo);

  return offset;
}


static const ber_sequence_t T_tAnswerSpecificInfo_sequence[] = {
  { &hf_camel_destinationAddress, BER_CLASS_CON, 50, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_CalledPartyNumber },
  { &hf_camel_or_Call       , BER_CLASS_CON, 51, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  { &hf_camel_forwardedCall , BER_CLASS_CON, 52, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  { &hf_camel_chargeIndicator, BER_CLASS_CON, 53, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ChargeIndicator },
  { &hf_camel_ext_basicServiceCode, BER_CLASS_CON, 54, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_Ext_BasicServiceCode },
  { &hf_camel_ext_basicServiceCode2, BER_CLASS_CON, 55, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_Ext_BasicServiceCode },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_tAnswerSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_tAnswerSpecificInfo_sequence, hf_index, ett_camel_T_tAnswerSpecificInfo);

  return offset;
}


static const value_string camel_T_tmidCallEvents_vals[] = {
  {   3, "dTMFDigitsCompleted" },
  {   4, "dTMFDigitsTimeOut" },
  { 0, NULL }
};

static const ber_choice_t T_tmidCallEvents_choice[] = {
  {   3, &hf_camel_dTMFDigitsCompleted, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_camel_Digits },
  {   4, &hf_camel_dTMFDigitsTimeOut, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_camel_Digits },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_tmidCallEvents(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_tmidCallEvents_choice, hf_index, ett_camel_T_tmidCallEvents,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_tMidCallSpecificInfo_sequence[] = {
  { &hf_camel_tmidCallEvents, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_T_tmidCallEvents },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_tMidCallSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_tMidCallSpecificInfo_sequence, hf_index, ett_camel_T_tMidCallSpecificInfo);

  return offset;
}


static const ber_sequence_t T_tDisconnectSpecificInfo_sequence[] = {
  { &hf_camel_releaseCause  , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_Cause },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_tDisconnectSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_tDisconnectSpecificInfo_sequence, hf_index, ett_camel_T_tDisconnectSpecificInfo);

  return offset;
}


static const ber_sequence_t T_oTermSeizedSpecificInfo_sequence[] = {
  { &hf_camel_locationInformation, BER_CLASS_CON, 50, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ms_LocationInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_oTermSeizedSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_oTermSeizedSpecificInfo_sequence, hf_index, ett_camel_T_oTermSeizedSpecificInfo);

  return offset;
}


static const ber_sequence_t T_callAcceptedSpecificInfo_sequence[] = {
  { &hf_camel_locationInformation, BER_CLASS_CON, 50, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ms_LocationInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_callAcceptedSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_callAcceptedSpecificInfo_sequence, hf_index, ett_camel_T_callAcceptedSpecificInfo);

  return offset;
}


static const ber_sequence_t T_oAbandonSpecificInfo_sequence[] = {
  { &hf_camel_routeNotPermitted, BER_CLASS_CON, 50, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_oAbandonSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_oAbandonSpecificInfo_sequence, hf_index, ett_camel_T_oAbandonSpecificInfo);

  return offset;
}


static const ber_sequence_t MetDPCriterionAlt_sequence[] = {
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_MetDPCriterionAlt(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MetDPCriterionAlt_sequence, hf_index, ett_camel_MetDPCriterionAlt);

  return offset;
}


static const value_string camel_MetDPCriterion_vals[] = {
  {   0, "enteringCellGlobalId" },
  {   1, "leavingCellGlobalId" },
  {   2, "enteringServiceAreaId" },
  {   3, "leavingServiceAreaId" },
  {   4, "enteringLocationAreaId" },
  {   5, "leavingLocationAreaId" },
  {   6, "inter-SystemHandOverToUMTS" },
  {   7, "inter-SystemHandOverToGSM" },
  {   8, "inter-PLMNHandOver" },
  {   9, "inter-MSCHandOver" },
  {  10, "metDPCriterionAlt" },
  { 0, NULL }
};

static const ber_choice_t MetDPCriterion_choice[] = {
  {   0, &hf_camel_enteringCellGlobalId, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gsm_map_CellGlobalIdOrServiceAreaIdFixedLength },
  {   1, &hf_camel_leavingCellGlobalId, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gsm_map_CellGlobalIdOrServiceAreaIdFixedLength },
  {   2, &hf_camel_enteringServiceAreaId, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_gsm_map_CellGlobalIdOrServiceAreaIdFixedLength },
  {   3, &hf_camel_leavingServiceAreaId, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_gsm_map_CellGlobalIdOrServiceAreaIdFixedLength },
  {   4, &hf_camel_enteringLocationAreaId, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_gsm_map_LAIFixedLength },
  {   5, &hf_camel_leavingLocationAreaId, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_gsm_map_LAIFixedLength },
  {   6, &hf_camel_inter_SystemHandOverToUMTS, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  {   7, &hf_camel_inter_SystemHandOverToGSM, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  {   8, &hf_camel_inter_PLMNHandOver, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  {   9, &hf_camel_inter_MSCHandOver, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  {  10, &hf_camel_metDPCriterionAlt, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_camel_MetDPCriterionAlt },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_MetDPCriterion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 MetDPCriterion_choice, hf_index, ett_camel_MetDPCriterion,
                                 NULL);

  return offset;
}


static const ber_sequence_t MetDPCriteriaList_sequence_of[1] = {
  { &hf_camel_MetDPCriteriaList_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_MetDPCriterion },
};

static int
dissect_camel_MetDPCriteriaList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      MetDPCriteriaList_sequence_of, hf_index, ett_camel_MetDPCriteriaList);

  return offset;
}


static const ber_sequence_t T_oChangeOfPositionSpecificInfo_sequence[] = {
  { &hf_camel_locationInformation, BER_CLASS_CON, 50, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ms_LocationInformation },
  { &hf_camel_metDPCriteriaList, BER_CLASS_CON, 51, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_MetDPCriteriaList },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_oChangeOfPositionSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_oChangeOfPositionSpecificInfo_sequence, hf_index, ett_camel_T_oChangeOfPositionSpecificInfo);

  return offset;
}


static const ber_sequence_t T_tChangeOfPositionSpecificInfo_sequence[] = {
  { &hf_camel_locationInformation, BER_CLASS_CON, 50, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ms_LocationInformation },
  { &hf_camel_metDPCriteriaList, BER_CLASS_CON, 51, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_MetDPCriteriaList },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_tChangeOfPositionSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_tChangeOfPositionSpecificInfo_sequence, hf_index, ett_camel_T_tChangeOfPositionSpecificInfo);

  return offset;
}


static const value_string camel_EventSpecificInformationBCSM_vals[] = {
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
  {  13, "oTermSeizedSpecificInfo" },
  {  20, "callAcceptedSpecificInfo" },
  {  21, "oAbandonSpecificInfo" },
  {  50, "oChangeOfPositionSpecificInfo" },
  {  51, "tChangeOfPositionSpecificInfo" },
  {  52, "dpSpecificInfoAlt" },
  { 0, NULL }
};

static const ber_choice_t EventSpecificInformationBCSM_choice[] = {
  {   2, &hf_camel_routeSelectFailureSpecificInfo, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_camel_T_routeSelectFailureSpecificInfo },
  {   3, &hf_camel_oCalledPartyBusySpecificInfo, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_camel_T_oCalledPartyBusySpecificInfo },
  {   4, &hf_camel_oNoAnswerSpecificInfo, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_camel_T_oNoAnswerSpecificInfo },
  {   5, &hf_camel_oAnswerSpecificInfo, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_camel_T_oAnswerSpecificInfo },
  {   6, &hf_camel_oMidCallSpecificInfo, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_camel_T_oMidCallSpecificInfo },
  {   7, &hf_camel_oDisconnectSpecificInfo, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_camel_T_oDisconnectSpecificInfo },
  {   8, &hf_camel_tBusySpecificInfo, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_camel_T_tBusySpecificInfo },
  {   9, &hf_camel_tNoAnswerSpecificInfo, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_camel_T_tNoAnswerSpecificInfo },
  {  10, &hf_camel_tAnswerSpecificInfo, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_camel_T_tAnswerSpecificInfo },
  {  11, &hf_camel_tMidCallSpecificInfo, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_camel_T_tMidCallSpecificInfo },
  {  12, &hf_camel_tDisconnectSpecificInfo, BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_camel_T_tDisconnectSpecificInfo },
  {  13, &hf_camel_oTermSeizedSpecificInfo, BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_camel_T_oTermSeizedSpecificInfo },
  {  20, &hf_camel_callAcceptedSpecificInfo, BER_CLASS_CON, 20, BER_FLAGS_IMPLTAG, dissect_camel_T_callAcceptedSpecificInfo },
  {  21, &hf_camel_oAbandonSpecificInfo, BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_camel_T_oAbandonSpecificInfo },
  {  50, &hf_camel_oChangeOfPositionSpecificInfo, BER_CLASS_CON, 50, BER_FLAGS_IMPLTAG, dissect_camel_T_oChangeOfPositionSpecificInfo },
  {  51, &hf_camel_tChangeOfPositionSpecificInfo, BER_CLASS_CON, 51, BER_FLAGS_IMPLTAG, dissect_camel_T_tChangeOfPositionSpecificInfo },
  {  52, &hf_camel_dpSpecificInfoAlt, BER_CLASS_CON, 52, BER_FLAGS_IMPLTAG, dissect_camel_DpSpecificInfoAlt },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_EventSpecificInformationBCSM(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 EventSpecificInformationBCSM_choice, hf_index, ett_camel_EventSpecificInformationBCSM,
                                 NULL);

  return offset;
}


static const value_string camel_MO_SMSCause_vals[] = {
  {   0, "systemFailure" },
  {   1, "unexpectedDataValue" },
  {   2, "facilityNotSupported" },
  {   3, "sM-DeliveryFailure" },
  {   4, "releaseFromRadioInterface" },
  { 0, NULL }
};


static int
dissect_camel_MO_SMSCause(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t T_o_smsFailureSpecificInfo_sequence[] = {
  { &hf_camel_smsfailureCause, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_MO_SMSCause },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_o_smsFailureSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_o_smsFailureSpecificInfo_sequence, hf_index, ett_camel_T_o_smsFailureSpecificInfo);

  return offset;
}



static int
dissect_camel_INTEGER_0(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t T_o_smsSubmittedSpecificInfo_sequence[] = {
  { &hf_camel_foo           , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_camel_INTEGER_0 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_o_smsSubmittedSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_o_smsSubmittedSpecificInfo_sequence, hf_index, ett_camel_T_o_smsSubmittedSpecificInfo);

  return offset;
}



static int
dissect_camel_MT_SMSCause(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t T_t_smsFailureSpecificInfo_sequence[] = {
  { &hf_camel_failureMTSMSCause, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_MT_SMSCause },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_t_smsFailureSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_t_smsFailureSpecificInfo_sequence, hf_index, ett_camel_T_t_smsFailureSpecificInfo);

  return offset;
}


static const ber_sequence_t T_t_smsDeliverySpecificInfo_sequence[] = {
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_t_smsDeliverySpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_t_smsDeliverySpecificInfo_sequence, hf_index, ett_camel_T_t_smsDeliverySpecificInfo);

  return offset;
}


static const value_string camel_EventSpecificInformationSMS_vals[] = {
  {   0, "o-smsFailureSpecificInfo" },
  {   1, "o-smsSubmittedSpecificInfo" },
  {   2, "t-smsFailureSpecificInfo" },
  {   3, "t-smsDeliverySpecificInfo" },
  { 0, NULL }
};

static const ber_choice_t EventSpecificInformationSMS_choice[] = {
  {   0, &hf_camel_o_smsFailureSpecificInfo, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_T_o_smsFailureSpecificInfo },
  {   1, &hf_camel_o_smsSubmittedSpecificInfo, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_T_o_smsSubmittedSpecificInfo },
  {   2, &hf_camel_t_smsFailureSpecificInfo, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_camel_T_t_smsFailureSpecificInfo },
  {   3, &hf_camel_t_smsDeliverySpecificInfo, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_camel_T_t_smsDeliverySpecificInfo },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_EventSpecificInformationSMS(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 EventSpecificInformationSMS_choice, hf_index, ett_camel_EventSpecificInformationSMS,
                                 NULL);

  return offset;
}


static const value_string camel_EventTypeSMS_vals[] = {
  {   1, "sms-CollectedInfo" },
  {   2, "o-smsFailure" },
  {   3, "o-smsSubmission" },
  {  11, "sms-DeliveryRequested" },
  {  12, "t-smsFailure" },
  {  13, "t-smsDelivery" },
  { 0, NULL }
};


static int
dissect_camel_EventTypeSMS(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_camel_FCIBillingChargingCharacteristics(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_camel_CAMEL_FCIBillingChargingCharacteristics(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_camel_FCIGPRSBillingChargingCharacteristics(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_camel_CAMEL_FCIGPRSBillingChargingCharacteristics(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_camel_FCISMSBillingChargingCharacteristics(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_camel_CAMEL_FCISMSBillingChargingCharacteristics(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t ForwardServiceInteractionInd_sequence[] = {
  { &hf_camel_conferenceTreatmentIndicator, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_OCTET_STRING_SIZE_1 },
  { &hf_camel_callDiversionTreatmentIndicator, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_OCTET_STRING_SIZE_1 },
  { &hf_camel_callingPartyRestrictionIndicator, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_OCTET_STRING_SIZE_1 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_ForwardServiceInteractionInd(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ForwardServiceInteractionInd_sequence, hf_index, ett_camel_ForwardServiceInteractionInd);

  return offset;
}


static const value_string camel_GapCriteria_vals[] = {
  {   0, "basicGapCriteria" },
  {   1, "compoundGapCriteria" },
  { 0, NULL }
};

static const ber_choice_t GapCriteria_choice[] = {
  {   0, &hf_camel_basicGapCriteria, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_camel_BasicGapCriteria },
  {   1, &hf_camel_compoundGapCriteria, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_camel_CompoundCriteria },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_GapCriteria(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 GapCriteria_choice, hf_index, ett_camel_GapCriteria,
                                 NULL);

  return offset;
}



static int
dissect_camel_Duration(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_camel_Interval(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t GapIndicators_sequence[] = {
  { &hf_camel_duration1     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_Duration },
  { &hf_camel_gapInterval   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_Interval },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_GapIndicators(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GapIndicators_sequence, hf_index, ett_camel_GapIndicators);

  return offset;
}



static int
dissect_camel_Integer4(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_camel_IA5String_SIZE_cAPSpecificBoundSetminMessageContentLength_cAPSpecificBoundSetmaxMessageContentLength(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_camel_OCTET_STRING_SIZE_cAPSpecificBoundSetminAttributesLength_cAPSpecificBoundSetmaxAttributesLength(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t T_text_sequence[] = {
  { &hf_camel_messageContent, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_IA5String_SIZE_cAPSpecificBoundSetminMessageContentLength_cAPSpecificBoundSetmaxMessageContentLength },
  { &hf_camel_attributes    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_OCTET_STRING_SIZE_cAPSpecificBoundSetminAttributesLength_cAPSpecificBoundSetmaxAttributesLength },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_text(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_text_sequence, hf_index, ett_camel_T_text);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_cAPSpecificBoundSetnumOfMessageIDs_OF_Integer4_sequence_of[1] = {
  { &hf_camel_elementaryMessageIDs_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_camel_Integer4 },
};

static int
dissect_camel_SEQUENCE_SIZE_1_cAPSpecificBoundSetnumOfMessageIDs_OF_Integer4(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_cAPSpecificBoundSetnumOfMessageIDs_OF_Integer4_sequence_of, hf_index, ett_camel_SEQUENCE_SIZE_1_cAPSpecificBoundSetnumOfMessageIDs_OF_Integer4);

  return offset;
}



static int
dissect_camel_OCTET_STRING_SIZE_2(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_camel_OCTET_STRING_SIZE_4(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string camel_VariablePart_vals[] = {
  {   0, "integer" },
  {   1, "number" },
  {   2, "time" },
  {   3, "date" },
  {   4, "price" },
  { 0, NULL }
};

static const ber_choice_t VariablePart_choice[] = {
  {   0, &hf_camel_integer       , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_Integer4 },
  {   1, &hf_camel_number        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_Digits },
  {   2, &hf_camel_time          , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_camel_OCTET_STRING_SIZE_2 },
  {   3, &hf_camel_date          , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_camel_OCTET_STRING_SIZE_4 },
  {   4, &hf_camel_price         , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_camel_OCTET_STRING_SIZE_4 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_VariablePart(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 VariablePart_choice, hf_index, ett_camel_VariablePart,
                                 NULL);

  return offset;
}


static const ber_sequence_t VariablePartsArray_sequence_of[1] = {
  { &hf_camel_VariablePartsArray_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_VariablePart },
};

static int
dissect_camel_VariablePartsArray(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      VariablePartsArray_sequence_of, hf_index, ett_camel_VariablePartsArray);

  return offset;
}


static const ber_sequence_t T_variableMessage_sequence[] = {
  { &hf_camel_elementaryMessageID, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_Integer4 },
  { &hf_camel_variableParts , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_VariablePartsArray },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_variableMessage(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_variableMessage_sequence, hf_index, ett_camel_T_variableMessage);

  return offset;
}


static const value_string camel_MessageID_vals[] = {
  {   0, "elementaryMessageID" },
  {   1, "text" },
  {  29, "elementaryMessageIDs" },
  {  30, "variableMessage" },
  { 0, NULL }
};

static const ber_choice_t MessageID_choice[] = {
  {   0, &hf_camel_elementaryMessageID, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_Integer4 },
  {   1, &hf_camel_text          , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_T_text },
  {  29, &hf_camel_elementaryMessageIDs, BER_CLASS_CON, 29, BER_FLAGS_IMPLTAG, dissect_camel_SEQUENCE_SIZE_1_cAPSpecificBoundSetnumOfMessageIDs_OF_Integer4 },
  {  30, &hf_camel_variableMessage, BER_CLASS_CON, 30, BER_FLAGS_IMPLTAG, dissect_camel_T_variableMessage },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_MessageID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 MessageID_choice, hf_index, ett_camel_MessageID,
                                 NULL);

  return offset;
}



static int
dissect_camel_INTEGER_0_32767(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t InbandInfo_sequence[] = {
  { &hf_camel_messageID     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_MessageID },
  { &hf_camel_numberOfRepetitions, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_1_127 },
  { &hf_camel_duration2     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_0_32767 },
  { &hf_camel_interval      , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_0_32767 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_InbandInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InbandInfo_sequence, hf_index, ett_camel_InbandInfo);

  return offset;
}


static const ber_sequence_t Tone_sequence[] = {
  { &hf_camel_toneID        , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_Integer4 },
  { &hf_camel_duration3     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_Integer4 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_Tone(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Tone_sequence, hf_index, ett_camel_Tone);

  return offset;
}


static const value_string camel_InformationToSend_vals[] = {
  {   0, "inbandInfo" },
  {   1, "tone" },
  { 0, NULL }
};

static const ber_choice_t InformationToSend_choice[] = {
  {   0, &hf_camel_inbandInfo    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_InbandInfo },
  {   1, &hf_camel_tone          , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_Tone },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_InformationToSend(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 InformationToSend_choice, hf_index, ett_camel_InformationToSend,
                                 NULL);

  return offset;
}


static const value_string camel_GapTreatment_vals[] = {
  {   0, "informationToSend" },
  {   1, "releaseCause" },
  { 0, NULL }
};

static const ber_choice_t GapTreatment_choice[] = {
  {   0, &hf_camel_informationToSend, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_InformationToSend },
  {   1, &hf_camel_releaseCause  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_Cause },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_GapTreatment(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 GapTreatment_choice, hf_index, ett_camel_GapTreatment,
                                 NULL);

  return offset;
}



static int
dissect_camel_GenericNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t GenericNumbers_set_of[1] = {
  { &hf_camel_GenericNumbers_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_camel_GenericNumber },
};

static int
dissect_camel_GenericNumbers(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 GenericNumbers_set_of, hf_index, ett_camel_GenericNumbers);

  return offset;
}


static const value_string camel_GPRS_QoS_vals[] = {
  {   0, "short-QoS-format" },
  {   1, "long-QoS-format" },
  { 0, NULL }
};

static const ber_choice_t GPRS_QoS_choice[] = {
  {   0, &hf_camel_short_QoS_format, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gsm_map_ms_QoS_Subscribed },
  {   1, &hf_camel_long_QoS_format, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gsm_map_ms_Ext_QoS_Subscribed },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_GPRS_QoS(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 GPRS_QoS_choice, hf_index, ett_camel_GPRS_QoS,
                                 NULL);

  return offset;
}


static const ber_sequence_t GPRS_QoS_Extension_sequence[] = {
  { &hf_camel_supplement_to_long_QoS_format, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gsm_map_ms_Ext2_QoS_Subscribed },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_GPRS_QoS_Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GPRS_QoS_Extension_sequence, hf_index, ett_camel_GPRS_QoS_Extension);

  return offset;
}



static int
dissect_camel_GPRSCause(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string camel_GPRSEventType_vals[] = {
  {   1, "attach" },
  {   2, "attachChangeOfPosition" },
  {   3, "detached" },
  {  11, "pdp-ContextEstablishment" },
  {  12, "pdp-ContextEstablishmentAcknowledgement" },
  {  13, "disconnect" },
  {  14, "pdp-ContextChangeOfPosition" },
  { 0, NULL }
};


static int
dissect_camel_GPRSEventType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t GPRSEvent_sequence[] = {
  { &hf_camel_gPRSEventType , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_GPRSEventType },
  { &hf_camel_monitorMode   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_MonitorMode },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_GPRSEvent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GPRSEvent_sequence, hf_index, ett_camel_GPRSEvent);

  return offset;
}



static int
dissect_camel_CellGlobalIdOrServiceAreaIdOrLAI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 467 "camel.cnf"
	proto_item *item;
	proto_tree *subtree;
	int start_offset;

 start_offset = offset;
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);


 item = get_ber_last_created_item();
 subtree = proto_item_add_subtree(item, ett_camel_pdptypenumber);

 if (tvb_reported_length_remaining(tvb,start_offset) == 7){
	dissect_gsm_map_CellGlobalIdOrServiceAreaIdFixedLength(TRUE, tvb, start_offset, actx, subtree, hf_camel_cellGlobalIdOrServiceAreaIdFixedLength);
 }else{
	dissect_gsm_map_LAIFixedLength(TRUE, tvb, start_offset, actx, subtree, hf_camel_locationAreaId);
 }			


  return offset;
}



static int
dissect_camel_ExtensionSetextensionId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t PrivateExtension_sequence[] = {
  { &hf_camel_extId         , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_camel_ExtensionSetextensionId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_PrivateExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PrivateExtension_sequence, hf_index, ett_camel_PrivateExtension);

  return offset;
}


static const ber_sequence_t PrivateExtensionList_sequence_of[1] = {
  { &hf_camel_PrivateExtensionList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_camel_PrivateExtension },
};

static int
dissect_camel_PrivateExtensionList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      PrivateExtensionList_sequence_of, hf_index, ett_camel_PrivateExtensionList);

  return offset;
}


static const ber_sequence_t PCS_Extensions_sequence[] = {
  { &hf_camel_foo           , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_camel_INTEGER_0 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_PCS_Extensions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PCS_Extensions_sequence, hf_index, ett_camel_PCS_Extensions);

  return offset;
}


static const ber_sequence_t ExtensionContainer_sequence[] = {
  { &hf_camel_privateExtensionList, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_PrivateExtensionList },
  { &hf_camel_pcs_Extensions, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_PCS_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_ExtensionContainer(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ExtensionContainer_sequence, hf_index, ett_camel_ExtensionContainer);

  return offset;
}


static const ber_sequence_t LocationInformationGPRS_sequence[] = {
  { &hf_camel_cellGlobalIdOrServiceAreaIdOrLAI, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_CellGlobalIdOrServiceAreaIdOrLAI },
  { &hf_camel_routeingAreaIdentity, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ms_RAIdentity },
  { &hf_camel_geographicalInformation, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ms_GeographicalInformation },
  { &hf_camel_sgsn_Number   , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ISDN_AddressString },
  { &hf_camel_selectedLSAIdentity, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ms_LSAIdentity },
  { &hf_camel_extensionContainer, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ExtensionContainer },
  { &hf_camel_saiPresent    , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_LocationInformationGPRS(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   LocationInformationGPRS_sequence, hf_index, ett_camel_LocationInformationGPRS);

  return offset;
}


static const ber_sequence_t T_attachChangeOfPositionSpecificInformation_sequence[] = {
  { &hf_camel_locationInformationGPRS, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_LocationInformationGPRS },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_attachChangeOfPositionSpecificInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_attachChangeOfPositionSpecificInformation_sequence, hf_index, ett_camel_T_attachChangeOfPositionSpecificInformation);

  return offset;
}



static int
dissect_camel_PDPTypeOrganization(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 390 "camel.cnf"

 tvbuff_t	*parameter_tvb;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


 if (!parameter_tvb)
	return offset;
 PDPTypeOrganization  = (tvb_get_guint8(parameter_tvb,0) &0x0f);	


  return offset;
}



static int
dissect_camel_PDPTypeNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 405 "camel.cnf"

 tvbuff_t	*parameter_tvb;
 proto_item *item;
 proto_tree *subtree;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


 if (!parameter_tvb)
	return offset;
 PDPTypeNumber = tvb_get_guint8(parameter_tvb,0);	
 item = get_ber_last_created_item();
 subtree = proto_item_add_subtree(item, ett_camel_pdptypenumber);
 switch (PDPTypeOrganization){
 case 0: /* ETSI */
	proto_tree_add_item(tree, hf_camel_PDPTypeNumber_etsi, parameter_tvb, 0, 1, FALSE);
	break;
 case 1: /* IETF */
	proto_tree_add_item(tree, hf_camel_PDPTypeNumber_ietf, parameter_tvb, 0, 1, FALSE);
	break;
 default:
	break;
 }


  return offset;
}



static int
dissect_camel_PDPAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 434 "camel.cnf"

 tvbuff_t	*parameter_tvb;
 proto_item *item;
 proto_tree *subtree;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


 if (!parameter_tvb)
	return offset;
 item = get_ber_last_created_item();
 subtree = proto_item_add_subtree(item, ett_camel_pdptypenumber);
 switch (PDPTypeOrganization){
 case 0: /* ETSI */
	break;
 case 1: /* IETF */
	switch(PDPTypeNumber){
	case 0x21: /* IPv4 */
		proto_tree_add_item(tree, hf_camel_PDPAddress_IPv4, parameter_tvb, 0, tvb_length(parameter_tvb), FALSE);
		break;
	case 0x57: /* IPv6 */
		proto_tree_add_item(tree, hf_camel_PDPAddress_IPv6, parameter_tvb, 0, tvb_length(parameter_tvb), FALSE);
		break;
	default:
		break;
	}
 default:
	break;

 }


  return offset;
}


static const ber_sequence_t PDPType_sequence[] = {
  { &hf_camel_pDPTypeOrganization, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_PDPTypeOrganization },
  { &hf_camel_pDPTypeNumber , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_PDPTypeNumber },
  { &hf_camel_pDPAddress    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_PDPAddress },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_PDPType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PDPType_sequence, hf_index, ett_camel_PDPType);

  return offset;
}


static const ber_sequence_t QualityOfService_sequence[] = {
  { &hf_camel_requested_QoS , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_GPRS_QoS },
  { &hf_camel_subscribed_QoS, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_GPRS_QoS },
  { &hf_camel_negotiated_QoS, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_GPRS_QoS },
  { &hf_camel_requested_QoS_Extension, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_GPRS_QoS_Extension },
  { &hf_camel_subscribed_QoS_Extension, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_GPRS_QoS_Extension },
  { &hf_camel_negotiated_QoS_Extension, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_GPRS_QoS_Extension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_QualityOfService(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   QualityOfService_sequence, hf_index, ett_camel_QualityOfService);

  return offset;
}



static int
dissect_camel_TimeAndTimezone(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t T_pdp_ContextchangeOfPositionSpecificInformation_sequence[] = {
  { &hf_camel_accessPointName, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_AccessPointName },
  { &hf_camel_chargingID    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ms_GPRSChargingID },
  { &hf_camel_locationInformationGPRS, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_LocationInformationGPRS },
  { &hf_camel_pDPType       , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_PDPType },
  { &hf_camel_qualityOfService, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_QualityOfService },
  { &hf_camel_timeAndTimeZone, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_TimeAndTimezone },
  { &hf_camel_gGSNAddress   , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ms_GSN_Address },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_pdp_ContextchangeOfPositionSpecificInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_pdp_ContextchangeOfPositionSpecificInformation_sequence, hf_index, ett_camel_T_pdp_ContextchangeOfPositionSpecificInformation);

  return offset;
}


static const value_string camel_InitiatingEntity_vals[] = {
  {   0, "mobileStation" },
  {   1, "sgsn" },
  {   2, "hlr" },
  {   3, "ggsn" },
  { 0, NULL }
};


static int
dissect_camel_InitiatingEntity(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t T_detachSpecificInformation_sequence[] = {
  { &hf_camel_inititatingEntity, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_InitiatingEntity },
  { &hf_camel_routeingAreaUpdate, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_detachSpecificInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_detachSpecificInformation_sequence, hf_index, ett_camel_T_detachSpecificInformation);

  return offset;
}


static const ber_sequence_t T_disconnectSpecificInformation_sequence[] = {
  { &hf_camel_inititatingEntity, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_InitiatingEntity },
  { &hf_camel_routeingAreaUpdate, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_disconnectSpecificInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_disconnectSpecificInformation_sequence, hf_index, ett_camel_T_disconnectSpecificInformation);

  return offset;
}


static const value_string camel_PDPInitiationType_vals[] = {
  {   0, "mSInitiated" },
  {   1, "networkInitiated" },
  { 0, NULL }
};


static int
dissect_camel_PDPInitiationType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t T_pDPContextEstablishmentSpecificInformation_sequence[] = {
  { &hf_camel_accessPointName, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_AccessPointName },
  { &hf_camel_pDPType       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_PDPType },
  { &hf_camel_qualityOfService, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_QualityOfService },
  { &hf_camel_locationInformationGPRS, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_LocationInformationGPRS },
  { &hf_camel_timeAndTimeZone, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_TimeAndTimezone },
  { &hf_camel_pDPInitiationType, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_PDPInitiationType },
  { &hf_camel_secondaryPDPContext, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_pDPContextEstablishmentSpecificInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_pDPContextEstablishmentSpecificInformation_sequence, hf_index, ett_camel_T_pDPContextEstablishmentSpecificInformation);

  return offset;
}


static const ber_sequence_t T_pDPContextEstablishmentAcknowledgementSpecificInformation_sequence[] = {
  { &hf_camel_accessPointName, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_AccessPointName },
  { &hf_camel_chargingID    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ms_GPRSChargingID },
  { &hf_camel_pDPType       , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_PDPType },
  { &hf_camel_qualityOfService, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_QualityOfService },
  { &hf_camel_locationInformationGPRS, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_LocationInformationGPRS },
  { &hf_camel_timeAndTimeZone, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_TimeAndTimezone },
  { &hf_camel_gGSNAddress   , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ms_GSN_Address },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_pDPContextEstablishmentAcknowledgementSpecificInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_pDPContextEstablishmentAcknowledgementSpecificInformation_sequence, hf_index, ett_camel_T_pDPContextEstablishmentAcknowledgementSpecificInformation);

  return offset;
}


static const value_string camel_GPRSEventSpecificInformation_vals[] = {
  {   0, "attachChangeOfPositionSpecificInformation" },
  {   1, "pdp-ContextchangeOfPositionSpecificInformation" },
  {   2, "detachSpecificInformation" },
  {   3, "disconnectSpecificInformation" },
  {   4, "pDPContextEstablishmentSpecificInformation" },
  {   5, "pDPContextEstablishmentAcknowledgementSpecificInformation" },
  { 0, NULL }
};

static const ber_choice_t GPRSEventSpecificInformation_choice[] = {
  {   0, &hf_camel_attachChangeOfPositionSpecificInformation, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_T_attachChangeOfPositionSpecificInformation },
  {   1, &hf_camel_pdp_ContextchangeOfPositionSpecificInformation, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_T_pdp_ContextchangeOfPositionSpecificInformation },
  {   2, &hf_camel_detachSpecificInformation, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_camel_T_detachSpecificInformation },
  {   3, &hf_camel_disconnectSpecificInformation, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_camel_T_disconnectSpecificInformation },
  {   4, &hf_camel_pDPContextEstablishmentSpecificInformation, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_camel_T_pDPContextEstablishmentSpecificInformation },
  {   5, &hf_camel_pDPContextEstablishmentAcknowledgementSpecificInformation, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_camel_T_pDPContextEstablishmentAcknowledgementSpecificInformation },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_GPRSEventSpecificInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 GPRSEventSpecificInformation_choice, hf_index, ett_camel_GPRSEventSpecificInformation,
                                 NULL);

  return offset;
}



static int
dissect_camel_MSNetworkCapability(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 351 "camel.cnf"

 tvbuff_t	*parameter_tvb;
 proto_item *item;
 proto_tree *subtree;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


 if (!parameter_tvb)
	return offset;
 item = get_ber_last_created_item();
 subtree = proto_item_add_subtree(item, ett_camel_MSNetworkCapability);
 de_gmm_ms_net_cap(parameter_tvb, subtree, 0, tvb_length_remaining(parameter_tvb,0), NULL, 0);


  return offset;
}



static int
dissect_camel_MSRadioAccessCapability(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 370 "camel.cnf"

 tvbuff_t	*parameter_tvb;
 proto_item *item;
 proto_tree *subtree;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


 if (!parameter_tvb)
	return offset;
 item = get_ber_last_created_item();
 subtree = proto_item_add_subtree(item, ett_camel_MSRadioAccessCapability);
 de_gmm_ms_radio_acc_cap(parameter_tvb, subtree, 0, tvb_length_remaining(parameter_tvb,0), NULL, 0);


  return offset;
}


static const ber_sequence_t GPRSMSClass_sequence[] = {
  { &hf_camel_mSNetworkCapability, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_MSNetworkCapability },
  { &hf_camel_mSRadioAccessCapability, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_MSRadioAccessCapability },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_GPRSMSClass(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GPRSMSClass_sequence, hf_index, ett_camel_GPRSMSClass);

  return offset;
}



static int
dissect_camel_IPRoutingAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_camel_CalledPartyNumber(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_camel_IPSSPCapabilities(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string camel_LegOrCallSegment_vals[] = {
  {   0, "callSegmentID" },
  {   1, "legID" },
  { 0, NULL }
};

static const ber_choice_t LegOrCallSegment_choice[] = {
  {   0, &hf_camel_callSegmentID , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_CallSegmentID },
  {   1, &hf_camel_legID         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_LegID },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_LegOrCallSegment(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 LegOrCallSegment_choice, hf_index, ett_camel_LegOrCallSegment,
                                 NULL);

  return offset;
}



static int
dissect_camel_LowLayerCompatibility(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_camel_NAOliInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_camel_OCSIApplicable(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_camel_OriginalCalledPartyID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 320 "camel.cnf"

 tvbuff_t	*parameter_tvb;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


 if (!parameter_tvb)
	return offset;
 dissect_isup_original_called_number_parameter(parameter_tvb, tree, NULL);


  return offset;
}



static int
dissect_camel_RedirectingPartyID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 336 "camel.cnf"

 tvbuff_t	*parameter_tvb;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


 if (!parameter_tvb)
	return offset;
 dissect_isup_redirecting_number_parameter(parameter_tvb, tree, NULL);


  return offset;
}


static const value_string camel_RequestedInformationType_vals[] = {
  {   0, "callAttemptElapsedTime" },
  {   1, "callStopTime" },
  {   2, "callConnectedElapsedTime" },
  {  30, "releaseCause" },
  { 0, NULL }
};


static int
dissect_camel_RequestedInformationType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string camel_RequestedInformationValue_vals[] = {
  {   0, "callAttemptElapsedTimeValue" },
  {   1, "callStopTimeValue" },
  {   2, "callConnectedElapsedTimeValue" },
  {  30, "releaseCauseValue" },
  { 0, NULL }
};

static const ber_choice_t RequestedInformationValue_choice[] = {
  {   0, &hf_camel_callAttemptElapsedTimeValue, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_0_255 },
  {   1, &hf_camel_callStopTimeValue, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_DateAndTime },
  {   2, &hf_camel_callConnectedElapsedTimeValue, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_camel_Integer4 },
  {  30, &hf_camel_releaseCauseValue, BER_CLASS_CON, 30, BER_FLAGS_IMPLTAG, dissect_camel_Cause },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_RequestedInformationValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RequestedInformationValue_choice, hf_index, ett_camel_RequestedInformationValue,
                                 NULL);

  return offset;
}


static const ber_sequence_t RequestedInformation_sequence[] = {
  { &hf_camel_requestedInformationType, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_RequestedInformationType },
  { &hf_camel_requestedInformationValue, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_RequestedInformationValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_RequestedInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RequestedInformation_sequence, hf_index, ett_camel_RequestedInformation);

  return offset;
}


static const ber_sequence_t RequestedInformationList_sequence_of[1] = {
  { &hf_camel_RequestedInformationList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_camel_RequestedInformation },
};

static int
dissect_camel_RequestedInformationList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      RequestedInformationList_sequence_of, hf_index, ett_camel_RequestedInformationList);

  return offset;
}


static const ber_sequence_t RequestedInformationTypeList_sequence_of[1] = {
  { &hf_camel_RequestedInformationTypeList_item, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_camel_RequestedInformationType },
};

static int
dissect_camel_RequestedInformationTypeList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      RequestedInformationTypeList_sequence_of, hf_index, ett_camel_RequestedInformationTypeList);

  return offset;
}



static int
dissect_camel_RPCause(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 171 "camel.cnf"

       tvbuff_t *camel_tvb;
       guint8 Cause_value;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &camel_tvb);


       if (camel_tvb)
           dissect_RP_cause_ie(camel_tvb, 0, tvb_length_remaining(camel_tvb,0), tree, hf_camel_RP_Cause, &Cause_value);

       return offset;


  return offset;
}



static int
dissect_camel_SCIBillingChargingCharacteristics(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_camel_SCIGPRSBillingChargingCharacteristics(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string camel_BothwayThroughConnectionInd_vals[] = {
  {   0, "bothwayPathRequired" },
  {   1, "bothwayPathNotRequired" },
  { 0, NULL }
};


static int
dissect_camel_BothwayThroughConnectionInd(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t ServiceInteractionIndicatorsTwo_sequence[] = {
  { &hf_camel_forwardServiceInteractionInd, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ForwardServiceInteractionInd },
  { &hf_camel_backwardServiceInteractionInd, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_BackwardServiceInteractionInd },
  { &hf_camel_bothwayThroughConnectionInd, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_BothwayThroughConnectionInd },
  { &hf_camel_connectedNumberTreatmentInd, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ConnectedNumberTreatmentInd },
  { &hf_camel_nonCUGCall    , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  { &hf_camel_holdTreatmentIndicator, BER_CLASS_CON, 50, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_OCTET_STRING_SIZE_1 },
  { &hf_camel_cwTreatmentIndicator, BER_CLASS_CON, 51, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_OCTET_STRING_SIZE_1 },
  { &hf_camel_ectTreatmentIndicator, BER_CLASS_CON, 52, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_OCTET_STRING_SIZE_1 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_ServiceInteractionIndicatorsTwo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ServiceInteractionIndicatorsTwo_sequence, hf_index, ett_camel_ServiceInteractionIndicatorsTwo);

  return offset;
}



static int
dissect_camel_SGSNCapabilities(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_camel_AddressString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_camel_SMS_AddressString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_camel_AddressString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t SMSEvent_sequence[] = {
  { &hf_camel_eventTypeSMS  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_EventTypeSMS },
  { &hf_camel_monitorMode   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_MonitorMode },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_SMSEvent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SMSEvent_sequence, hf_index, ett_camel_SMSEvent);

  return offset;
}


static const value_string camel_TimerID_vals[] = {
  {   0, "tssf" },
  { 0, NULL }
};


static int
dissect_camel_TimerID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_camel_TimerValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_camel_Integer4(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_camel_TPDataCodingScheme(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_camel_TPProtocolIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_camel_TPShortMessageSpecificInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_camel_TPValidityPeriod(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string camel_UnavailableNetworkResource_vals[] = {
  {   0, "unavailableResources" },
  {   1, "componentFailure" },
  {   2, "basicCallProcessingException" },
  {   3, "resourceStatusFailure" },
  {   4, "endUserFailure" },
  { 0, NULL }
};


static int
dissect_camel_UnavailableNetworkResource(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string camel_SpecializedResourceReportArg_vals[] = {
  {  50, "allAnnouncementsComplete" },
  {  51, "firstAnnouncementStarted" },
  { 0, NULL }
};

static const ber_choice_t SpecializedResourceReportArg_choice[] = {
  {  50, &hf_camel_allAnnouncementsComplete, BER_CLASS_CON, 50, BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  {  51, &hf_camel_firstAnnouncementStarted, BER_CLASS_CON, 51, BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_SpecializedResourceReportArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SpecializedResourceReportArg_choice, hf_index, ett_camel_SpecializedResourceReportArg,
                                 NULL);

  return offset;
}



static int
dissect_camel_CallReferenceNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_camel_SuppressionOfAnnouncement(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string camel_NotReachableReason_vals[] = {
  {   0, "msPurged" },
  {   1, "imsiDetached" },
  {   2, "restrictedArea" },
  {   3, "notRegistred" },
  { 0, NULL }
};


static int
dissect_camel_NotReachableReason(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_camel_CallingPartysCategory(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_camel_RedirectionInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 303 "camel.cnf"

 tvbuff_t	*parameter_tvb;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


 if (!parameter_tvb)
	return offset;

 dissect_isup_redirection_information_parameter(parameter_tvb, tree, NULL);


  return offset;
}



static int
dissect_camel_HighLayerCompatibility(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string camel_T_messageType_vals[] = {
  {   0, "request" },
  {   1, "notification" },
  { 0, NULL }
};


static int
dissect_camel_T_messageType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t MiscCallInfo_sequence[] = {
  { &hf_camel_messageType   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_T_messageType },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_MiscCallInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MiscCallInfo_sequence, hf_index, ett_camel_MiscCallInfo);

  return offset;
}



static int
dissect_camel_CallresultoctetPDU(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 121 "camel.cnf"
tvbuff_t	*parameter_tvb;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

 if (!parameter_tvb)
	return offset;
 dissect_camel_CAMEL_CallResult(implicit_tag, parameter_tvb, 0, actx, tree, -1);
 


  return offset;
}


static const ber_sequence_t ApplyChargingReportArg_sequence[] = {
  { &hf_camel_callresultOctet, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_CAMEL_CallResult },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_ApplyChargingReportArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ApplyChargingReportArg_sequence, hf_index, ett_camel_ApplyChargingReportArg);

  return offset;
}


static const value_string camel_CancelArg_vals[] = {
  {   0, "callInvokeID" },
  {   1, "allRequests" },
  {   2, "callSegmentToCancel" },
  { 0, NULL }
};

static const ber_choice_t CancelArg_choice[] = {
  {   0, &hf_camel_callInvokeID  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_InvokeID },
  {   1, &hf_camel_allRequests   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  {   2, &hf_camel_callSegmentToCancel, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_camel_CallSegmentToCancel },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_CancelArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CancelArg_choice, hf_index, ett_camel_CancelArg,
                                 NULL);

  return offset;
}


static const ber_sequence_t CollectInformationArg_sequence[] = {
  { &hf_camel_extensions    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ExtensionsArray },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_CollectInformationArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CollectInformationArg_sequence, hf_index, ett_camel_CollectInformationArg);

  return offset;
}



static int
dissect_camel_FurnishChargingInformationArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_camel_CAMEL_FCIBillingChargingCharacteristics(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_camel_Q850Cause(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 153 "camel.cnf"

       tvbuff_t *camel_tvb;
       guint8 Cause_value;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &camel_tvb);


       if (camel_tvb)
           dissect_q931_cause_ie(camel_tvb, 0, tvb_length_remaining(camel_tvb,0), tree, hf_camel_cause_indicator, &Cause_value);


       return offset;


  return offset;
}



static int
dissect_camel_ReleaseCallArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_camel_Q850Cause(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string camel_ReceivedInformationArg_vals[] = {
  {   0, "digitsResponse" },
  { 0, NULL }
};

static const ber_choice_t ReceivedInformationArg_choice[] = {
  {   0, &hf_camel_digitsResponse, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_Digits },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_ReceivedInformationArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ReceivedInformationArg_choice, hf_index, ett_camel_ReceivedInformationArg,
                                 NULL);

  return offset;
}



static int
dissect_camel_FurnishChargingInformationSMSArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t ConnectGPRSArg_sequence[] = {
  { &hf_camel_accessPointName, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_AccessPointName },
  { &hf_camel_pdpID         , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_PDPId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_ConnectGPRSArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ConnectGPRSArg_sequence, hf_index, ett_camel_ConnectGPRSArg);

  return offset;
}


static const ber_sequence_t EntityReleasedGPRSArg_sequence[] = {
  { &hf_camel_gPRSCause     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_GPRSCause },
  { &hf_camel_pDPID         , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_PDPId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_EntityReleasedGPRSArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EntityReleasedGPRSArg_sequence, hf_index, ett_camel_EntityReleasedGPRSArg);

  return offset;
}


static const ber_sequence_t ReleaseGPRSArg_sequence[] = {
  { &hf_camel_gprsCause     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_GPRSCause },
  { &hf_camel_pDPID         , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_PDPId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_ReleaseGPRSArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReleaseGPRSArg_sequence, hf_index, ett_camel_ReleaseGPRSArg);

  return offset;
}


static const ber_sequence_t GPRSEventArray_sequence_of[1] = {
  { &hf_camel_GPRSEventArray_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_camel_GPRSEvent },
};

static int
dissect_camel_GPRSEventArray(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      GPRSEventArray_sequence_of, hf_index, ett_camel_GPRSEventArray);

  return offset;
}


static const ber_sequence_t RequestReportGPRSEventArg_sequence[] = {
  { &hf_camel_gPRSEvent     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_GPRSEventArray },
  { &hf_camel_pDPID         , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_PDPId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_RequestReportGPRSEventArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RequestReportGPRSEventArg_sequence, hf_index, ett_camel_RequestReportGPRSEventArg);

  return offset;
}


static const ber_sequence_t SendChargingInformationGPRSArg_sequence[] = {
  { &hf_camel_sCIGPRSBillingChargingCharacteristics, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_SCIGPRSBillingChargingCharacteristics },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_SendChargingInformationGPRSArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SendChargingInformationGPRSArg_sequence, hf_index, ett_camel_SendChargingInformationGPRSArg);

  return offset;
}


static const value_string camel_SubscriberState_vals[] = {
  {   0, "assumedIdle" },
  {   1, "camelBusy" },
  {   2, "netDetNotReachable" },
  {   3, "notProvidedFromVLR" },
  { 0, NULL }
};

static const ber_choice_t SubscriberState_choice[] = {
  {   0, &hf_camel_assumedIdle   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  {   1, &hf_camel_camelBusy     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  {   2, &hf_camel_netDetNotReachable, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_camel_NotReachableReason },
  {   3, &hf_camel_notProvidedFromVLR, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_SubscriberState(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SubscriberState_choice, hf_index, ett_camel_SubscriberState,
                                 NULL);

  return offset;
}


static const asn_namedbit SupportedCamelPhases_bits[] = {
  {  0, &hf_camel_SupportedCamelPhases_phase1, -1, -1, "phase1", NULL },
  {  1, &hf_camel_SupportedCamelPhases_phase2, -1, -1, "phase2", NULL },
  {  2, &hf_camel_SupportedCamelPhases_phase3, -1, -1, "phase3", NULL },
  {  3, &hf_camel_SupportedCamelPhases_phase4, -1, -1, "phase4", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_camel_SupportedCamelPhases(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    SupportedCamelPhases_bits, hf_index, ett_camel_SupportedCamelPhases,
                                    NULL);

  return offset;
}


static const asn_namedbit OfferedCamel4Functionalities_bits[] = {
  {  0, &hf_camel_OfferedCamel4Functionalities_initiateCallAttempt, -1, -1, "initiateCallAttempt", NULL },
  {  1, &hf_camel_OfferedCamel4Functionalities_splitLeg, -1, -1, "splitLeg", NULL },
  {  2, &hf_camel_OfferedCamel4Functionalities_moveLeg, -1, -1, "moveLeg", NULL },
  {  3, &hf_camel_OfferedCamel4Functionalities_disconnectLeg, -1, -1, "disconnectLeg", NULL },
  {  4, &hf_camel_OfferedCamel4Functionalities_entityReleased, -1, -1, "entityReleased", NULL },
  {  5, &hf_camel_OfferedCamel4Functionalities_dfc_WithArgument, -1, -1, "dfc-WithArgument", NULL },
  {  6, &hf_camel_OfferedCamel4Functionalities_playTone, -1, -1, "playTone", NULL },
  {  7, &hf_camel_OfferedCamel4Functionalities_dtmf_MidCall, -1, -1, "dtmf-MidCall", NULL },
  {  8, &hf_camel_OfferedCamel4Functionalities_chargingIndicator, -1, -1, "chargingIndicator", NULL },
  {  9, &hf_camel_OfferedCamel4Functionalities_alertingDP, -1, -1, "alertingDP", NULL },
  { 10, &hf_camel_OfferedCamel4Functionalities_locationAtAlerting, -1, -1, "locationAtAlerting", NULL },
  { 11, &hf_camel_OfferedCamel4Functionalities_changeOfPositionDP, -1, -1, "changeOfPositionDP", NULL },
  { 12, &hf_camel_OfferedCamel4Functionalities_or_Interactions, -1, -1, "or-Interactions", NULL },
  { 13, &hf_camel_OfferedCamel4Functionalities_warningToneEnhancements, -1, -1, "warningToneEnhancements", NULL },
  { 14, &hf_camel_OfferedCamel4Functionalities_cf_Enhancements, -1, -1, "cf-Enhancements", NULL },
  { 15, &hf_camel_OfferedCamel4Functionalities_subscribedEnhancedDialledServices, -1, -1, "subscribedEnhancedDialledServices", NULL },
  { 16, &hf_camel_OfferedCamel4Functionalities_servingNetworkEnhancedDialledServices, -1, -1, "servingNetworkEnhancedDialledServices", NULL },
  { 17, &hf_camel_OfferedCamel4Functionalities_criteriaForChangeOfPositionDP, -1, -1, "criteriaForChangeOfPositionDP", NULL },
  { 18, &hf_camel_OfferedCamel4Functionalities_serviceChangeDP, -1, -1, "serviceChangeDP", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_camel_OfferedCamel4Functionalities(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    OfferedCamel4Functionalities_bits, hf_index, ett_camel_OfferedCamel4Functionalities,
                                    NULL);

  return offset;
}


static const ber_sequence_t InitialDPArgExtension_sequence[] = {
  { &hf_camel_gmscAddress   , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ISDN_AddressString },
  { &hf_camel_forwardingDestinationNumber, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_CalledPartyNumber },
  { &hf_camel_ms_Classmark2 , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ms_MS_Classmark2 },
  { &hf_camel_iMEI          , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_IMEI },
  { &hf_camel_supportedCamelPhases, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_SupportedCamelPhases },
  { &hf_camel_offeredCamel4Functionalities, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_OfferedCamel4Functionalities },
  { &hf_camel_bearerCapability2, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_BearerCapability },
  { &hf_camel_ext_basicServiceCode2, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_Ext_BasicServiceCode },
  { &hf_camel_highLayerCompatibility2, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_HighLayerCompatibility },
  { &hf_camel_lowLayerCompatibility, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_LowLayerCompatibility },
  { &hf_camel_lowLayerCompatibility2, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_LowLayerCompatibility },
  { &hf_camel_enhancedDialledServicesAllowed, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  { &hf_camel_uu_Data       , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ch_UU_Data },
  { &hf_camel_collectInformationAllowed, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_InitialDPArgExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InitialDPArgExtension_sequence, hf_index, ett_camel_InitialDPArgExtension);

  return offset;
}


static const ber_sequence_t InitiateCallAttemptArg_sequence[] = {
  { &hf_camel_destinationRoutingAddress, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_DestinationRoutingAddress },
  { &hf_camel_extensions    , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ExtensionsArray },
  { &hf_camel_legToBeCreated, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_LegID },
  { &hf_camel_newCallSegment, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_CallSegmentID },
  { &hf_camel_callingPartyNumber, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_CallingPartyNumber },
  { &hf_camel_callReferenceNumber, BER_CLASS_CON, 51, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_CallReferenceNumber },
  { &hf_camel_gsmSCFAddress , BER_CLASS_CON, 52, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ISDN_AddressString },
  { &hf_camel_suppress_T_CSI, BER_CLASS_CON, 53, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_InitiateCallAttemptArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InitiateCallAttemptArg_sequence, hf_index, ett_camel_InitiateCallAttemptArg);

  return offset;
}


static const ber_sequence_t InitiateCallAttemptRes_sequence[] = {
  { &hf_camel_supportedCamelPhases, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_SupportedCamelPhases },
  { &hf_camel_offeredCamel4Functionalities, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_OfferedCamel4Functionalities },
  { &hf_camel_extensions    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ExtensionsArray },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_InitiateCallAttemptRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InitiateCallAttemptRes_sequence, hf_index, ett_camel_InitiateCallAttemptRes);

  return offset;
}


static const ber_sequence_t MoveLegArg_sequence[] = {
  { &hf_camel_legIDToMove   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_LegID },
  { &hf_camel_extensions    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ExtensionsArray },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_MoveLegArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MoveLegArg_sequence, hf_index, ett_camel_MoveLegArg);

  return offset;
}


static const ber_sequence_t PlayToneArg_sequence[] = {
  { &hf_camel_legOrCallSegment, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_LegOrCallSegment },
  { &hf_camel_bursts        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_Burst },
  { &hf_camel_extensions    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ExtensionsArray },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_PlayToneArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PlayToneArg_sequence, hf_index, ett_camel_PlayToneArg);

  return offset;
}


static const ber_sequence_t EventReportGPRSArg_sequence[] = {
  { &hf_camel_gPRSEventType , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_GPRSEventType },
  { &hf_camel_miscGPRSInfo  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_MiscCallInfo },
  { &hf_camel_gPRSEventSpecificInformation, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_GPRSEventSpecificInformation },
  { &hf_camel_pDPID         , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_PDPId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_EventReportGPRSArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EventReportGPRSArg_sequence, hf_index, ett_camel_EventReportGPRSArg);

  return offset;
}


static const ber_sequence_t ApplyChargingArg_sequence[] = {
  { &hf_camel_aChBillingChargingCharacteristics, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_AChBillingChargingCharacteristics },
  { &hf_camel_partyToCharge1, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_SendingSideID },
  { &hf_camel_extensions    , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ExtensionsArray },
  { &hf_camel_aChChargingAddress, BER_CLASS_CON, 50, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_AChChargingAddress },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_ApplyChargingArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ApplyChargingArg_sequence, hf_index, ett_camel_ApplyChargingArg);

  return offset;
}


static const ber_sequence_t AssistRequestInstructionsArg_sequence[] = {
  { &hf_camel_correlationID , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_CorrelationID },
  { &hf_camel_iPSSPCapabilities, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_camel_IPSSPCapabilities },
  { &hf_camel_extensions    , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ExtensionsArray },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_AssistRequestInstructionsArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AssistRequestInstructionsArg_sequence, hf_index, ett_camel_AssistRequestInstructionsArg);

  return offset;
}


static const ber_sequence_t CallInformationRequestArg_sequence[] = {
  { &hf_camel_requestedInformationTypeList, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_RequestedInformationTypeList },
  { &hf_camel_extensions    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ExtensionsArray },
  { &hf_camel_legID3        , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_SendingSideID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_CallInformationRequestArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CallInformationRequestArg_sequence, hf_index, ett_camel_CallInformationRequestArg);

  return offset;
}


static const ber_sequence_t ConnectArg_sequence[] = {
  { &hf_camel_destinationRoutingAddress, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_DestinationRoutingAddress },
  { &hf_camel_alertingPattern, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_AlertingPattern },
  { &hf_camel_originalCalledPartyID, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_OriginalCalledPartyID },
  { &hf_camel_extensions    , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ExtensionsArray },
  { &hf_camel_carrier       , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_Carrier },
  { &hf_camel_callingPartysCategory, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_CallingPartysCategory },
  { &hf_camel_redirectingPartyID, BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_RedirectingPartyID },
  { &hf_camel_redirectionInformation, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_RedirectionInformation },
  { &hf_camel_genericNumbers, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_GenericNumbers },
  { &hf_camel_serviceInteractionIndicatorsTwo, BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ServiceInteractionIndicatorsTwo },
  { &hf_camel_chargeNumber  , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ChargeNumber },
  { &hf_camel_legToBeConnected, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_LegID },
  { &hf_camel_cug_Interlock , BER_CLASS_CON, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ms_CUG_Interlock },
  { &hf_camel_cug_OutgoingAccess, BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  { &hf_camel_suppressionOfAnnouncement, BER_CLASS_CON, 55, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_SuppressionOfAnnouncement },
  { &hf_camel_oCSIApplicable, BER_CLASS_CON, 56, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_OCSIApplicable },
  { &hf_camel_naOliInfo     , BER_CLASS_CON, 57, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_NAOliInfo },
  { &hf_camel_bor_InterrogationRequested, BER_CLASS_CON, 58, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  { &hf_camel_suppress_N_CSI, BER_CLASS_CON, 59, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_ConnectArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ConnectArg_sequence, hf_index, ett_camel_ConnectArg);

  return offset;
}


static const value_string camel_T_resourceAddress_vals[] = {
  {   0, "ipRoutingAddress" },
  {   3, "none" },
  { 0, NULL }
};

static const ber_choice_t T_resourceAddress_choice[] = {
  {   0, &hf_camel_ipRoutingAddress, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_IPRoutingAddress },
  {   3, &hf_camel_none          , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_T_resourceAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_resourceAddress_choice, hf_index, ett_camel_T_resourceAddress,
                                 NULL);

  return offset;
}


static const ber_sequence_t ConnectToResourceArg_sequence[] = {
  { &hf_camel_resourceAddress, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_T_resourceAddress },
  { &hf_camel_extensions    , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ExtensionsArray },
  { &hf_camel_serviceInteractionIndicatorsTwo, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ServiceInteractionIndicatorsTwo },
  { &hf_camel_callSegmentID , BER_CLASS_CON, 50, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_CallSegmentID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_ConnectToResourceArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ConnectToResourceArg_sequence, hf_index, ett_camel_ConnectToResourceArg);

  return offset;
}


static const ber_sequence_t ContinueWithArgumentArgExtension_sequence[] = {
  { &hf_camel_suppress_D_CSI, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  { &hf_camel_suppress_N_CSI, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  { &hf_camel_suppressOutgoingCallBarring, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  { &hf_camel_legOrCallSegment, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_LegOrCallSegment },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_ContinueWithArgumentArgExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ContinueWithArgumentArgExtension_sequence, hf_index, ett_camel_ContinueWithArgumentArgExtension);

  return offset;
}


static const ber_sequence_t ContinueWithArgumentArg_sequence[] = {
  { &hf_camel_alertingPattern, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_AlertingPattern },
  { &hf_camel_extensions    , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ExtensionsArray },
  { &hf_camel_serviceInteractionIndicatorsTwo, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ServiceInteractionIndicatorsTwo },
  { &hf_camel_callingPartysCategory, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_CallingPartysCategory },
  { &hf_camel_genericNumbers, BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_GenericNumbers },
  { &hf_camel_cug_Interlock , BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ms_CUG_Interlock },
  { &hf_camel_cug_OutgoingAccess, BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  { &hf_camel_chargeNumber  , BER_CLASS_CON, 50, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ChargeNumber },
  { &hf_camel_carrier       , BER_CLASS_CON, 52, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_Carrier },
  { &hf_camel_suppressionOfAnnouncement, BER_CLASS_CON, 55, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_SuppressionOfAnnouncement },
  { &hf_camel_naOliInfo     , BER_CLASS_CON, 56, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_NAOliInfo },
  { &hf_camel_bor_InterrogationRequested, BER_CLASS_CON, 57, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  { &hf_camel_suppress_O_CSI, BER_CLASS_CON, 58, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  { &hf_camel_continueWithArgumentArgExtension, BER_CLASS_CON, 59, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ContinueWithArgumentArgExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_ContinueWithArgumentArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ContinueWithArgumentArg_sequence, hf_index, ett_camel_ContinueWithArgumentArg);

  return offset;
}


static const ber_sequence_t DisconnectLegArg_sequence[] = {
  { &hf_camel_legToBeReleased, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_LegID },
  { &hf_camel_releaseCause  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_Cause },
  { &hf_camel_extensions    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ExtensionsArray },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_DisconnectLegArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DisconnectLegArg_sequence, hf_index, ett_camel_DisconnectLegArg);

  return offset;
}


static const value_string camel_EntityReleasedArg_vals[] = {
  {   0, "callSegmentFailure" },
  {   1, "bCSM-Failure" },
  { 0, NULL }
};

static const ber_choice_t EntityReleasedArg_choice[] = {
  {   0, &hf_camel_callSegmentFailure, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_CallSegmentFailure },
  {   1, &hf_camel_bCSM_Failure  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_BCSM_Failure },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_EntityReleasedArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 EntityReleasedArg_choice, hf_index, ett_camel_EntityReleasedArg,
                                 NULL);

  return offset;
}


static const ber_sequence_t DisconnectForwardConnectionWithArgumentArg_sequence[] = {
  { &hf_camel_callSegmentID , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_CallSegmentID },
  { &hf_camel_extensions    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ExtensionsArray },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_DisconnectForwardConnectionWithArgumentArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DisconnectForwardConnectionWithArgumentArg_sequence, hf_index, ett_camel_DisconnectForwardConnectionWithArgumentArg);

  return offset;
}


static const ber_sequence_t EstablishTemporaryConnectionArg_sequence[] = {
  { &hf_camel_assistingSSPIPRoutingAddress, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_AssistingSSPIPRoutingAddress },
  { &hf_camel_correlationID , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_CorrelationID },
  { &hf_camel_scfID         , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ScfID },
  { &hf_camel_extensions    , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ExtensionsArray },
  { &hf_camel_carrier       , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_Carrier },
  { &hf_camel_serviceInteractionIndicatorsTwo, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ServiceInteractionIndicatorsTwo },
  { &hf_camel_callSegmentID , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_CallSegmentID },
  { &hf_camel_naOliInfo     , BER_CLASS_CON, 50, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_NAOliInfo },
  { &hf_camel_chargeNumber  , BER_CLASS_CON, 51, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ChargeNumber },
  { &hf_camel_originalCalledPartyID, BER_CLASS_CON, 52, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_OriginalCalledPartyID },
  { &hf_camel_callingPartyNumber, BER_CLASS_CON, 53, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_CallingPartyNumber },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_EstablishTemporaryConnectionArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EstablishTemporaryConnectionArg_sequence, hf_index, ett_camel_EstablishTemporaryConnectionArg);

  return offset;
}


static const ber_sequence_t EventReportBCSMArg_sequence[] = {
  { &hf_camel_eventTypeBCSM , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_EventTypeBCSM },
  { &hf_camel_eventSpecificInformationBCSM, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_EventSpecificInformationBCSM },
  { &hf_camel_legID4        , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_ReceivingSideID },
  { &hf_camel_miscCallInfo  , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_MiscCallInfo },
  { &hf_camel_extensions    , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ExtensionsArray },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_EventReportBCSMArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EventReportBCSMArg_sequence, hf_index, ett_camel_EventReportBCSMArg);

  return offset;
}


static const ber_sequence_t ResetTimerArg_sequence[] = {
  { &hf_camel_timerID       , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_TimerID },
  { &hf_camel_timervalue    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_TimerValue },
  { &hf_camel_extensions    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ExtensionsArray },
  { &hf_camel_callSegmentID , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_CallSegmentID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_ResetTimerArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ResetTimerArg_sequence, hf_index, ett_camel_ResetTimerArg);

  return offset;
}


static const ber_sequence_t SendChargingInformationArg_sequence[] = {
  { &hf_camel_sCIBillingChargingCharacteristics, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_SCIBillingChargingCharacteristics },
  { &hf_camel_partyToCharge2, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_SendingSideID },
  { &hf_camel_extensions    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ExtensionsArray },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_SendChargingInformationArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SendChargingInformationArg_sequence, hf_index, ett_camel_SendChargingInformationArg);

  return offset;
}


static const ber_sequence_t SplitLegArg_sequence[] = {
  { &hf_camel_legToBeSplit  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_LegID },
  { &hf_camel_newCallSegment, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_CallSegmentID },
  { &hf_camel_extensions    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ExtensionsArray },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_SplitLegArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SplitLegArg_sequence, hf_index, ett_camel_SplitLegArg);

  return offset;
}


static const ber_sequence_t CAPGPRSReferenceNumber_sequence[] = {
  { &hf_camel_destinationReference, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_camel_Integer4 },
  { &hf_camel_originationReference, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_camel_Integer4 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_CAPGPRSReferenceNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CAPGPRSReferenceNumber_sequence, hf_index, ett_camel_CAPGPRSReferenceNumber);

  return offset;
}


static const ber_sequence_t EventReportSMSArg_sequence[] = {
  { &hf_camel_eventTypeSMS  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_EventTypeSMS },
  { &hf_camel_eventSpecificInformationSMS, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_EventSpecificInformationSMS },
  { &hf_camel_miscCallInfo  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_MiscCallInfo },
  { &hf_camel_extensions    , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ExtensionsArray },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_EventReportSMSArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EventReportSMSArg_sequence, hf_index, ett_camel_EventReportSMSArg);

  return offset;
}


static const ber_sequence_t ResetTimerSMSArg_sequence[] = {
  { &hf_camel_timerID       , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_TimerID },
  { &hf_camel_timervalue    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_TimerValue },
  { &hf_camel_extensions    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ExtensionsArray },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_ResetTimerSMSArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ResetTimerSMSArg_sequence, hf_index, ett_camel_ResetTimerSMSArg);

  return offset;
}


static const ber_sequence_t BCSMEventArray_sequence_of[1] = {
  { &hf_camel_BCSMEventArray_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_camel_BCSMEvent },
};

static int
dissect_camel_BCSMEventArray(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      BCSMEventArray_sequence_of, hf_index, ett_camel_BCSMEventArray);

  return offset;
}


static const ber_sequence_t RequestReportBCSMEventArg_sequence[] = {
  { &hf_camel_bcsmEvents    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_BCSMEventArray },
  { &hf_camel_extensions    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ExtensionsArray },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_RequestReportBCSMEventArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RequestReportBCSMEventArg_sequence, hf_index, ett_camel_RequestReportBCSMEventArg);

  return offset;
}


static const ber_sequence_t ConnectSMSArg_sequence[] = {
  { &hf_camel_callingPartysNumber, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_SMS_AddressString },
  { &hf_camel_destinationSubscriberNumber, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_CalledPartyBCDNumber },
  { &hf_camel_sMSCAddress   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ISDN_AddressString },
  { &hf_camel_extensions    , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ExtensionsArray },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_ConnectSMSArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ConnectSMSArg_sequence, hf_index, ett_camel_ConnectSMSArg);

  return offset;
}


static const ber_sequence_t CallInformationReportArg_sequence[] = {
  { &hf_camel_requestedInformationList, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_RequestedInformationList },
  { &hf_camel_extensions    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ExtensionsArray },
  { &hf_camel_legID5        , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_ReceivingSideID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_CallInformationReportArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CallInformationReportArg_sequence, hf_index, ett_camel_CallInformationReportArg);

  return offset;
}


static const ber_sequence_t PlayAnnouncementArg_sequence[] = {
  { &hf_camel_informationToSend, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_InformationToSend },
  { &hf_camel_disconnectFromIPForbidden, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_BOOLEAN },
  { &hf_camel_requestAnnouncementComplete, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_BOOLEAN },
  { &hf_camel_extensions    , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ExtensionsArray },
  { &hf_camel_callSegmentID , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_CallSegmentID },
  { &hf_camel_requestAnnouncementStartedNotification, BER_CLASS_CON, 51, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_PlayAnnouncementArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PlayAnnouncementArg_sequence, hf_index, ett_camel_PlayAnnouncementArg);

  return offset;
}


static const ber_sequence_t PromptAndCollectUserInformationArg_sequence[] = {
  { &hf_camel_collectedInfo , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_CollectedInfo },
  { &hf_camel_disconnectFromIPForbidden, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_BOOLEAN },
  { &hf_camel_informationToSend, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_InformationToSend },
  { &hf_camel_extensions    , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ExtensionsArray },
  { &hf_camel_callSegmentID , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_CallSegmentID },
  { &hf_camel_requestAnnouncementStartedNotification, BER_CLASS_CON, 51, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_PromptAndCollectUserInformationArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PromptAndCollectUserInformationArg_sequence, hf_index, ett_camel_PromptAndCollectUserInformationArg);

  return offset;
}



static int
dissect_camel_FurnishChargingInformationGPRSArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_camel_FCIGPRSBillingChargingCharacteristics(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t InitialDPGPRSArg_sequence[] = {
  { &hf_camel_serviceKey    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_ServiceKey },
  { &hf_camel_gPRSEventType , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_GPRSEventType },
  { &hf_camel_mSISDN        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_camel_ISDN_AddressString },
  { &hf_camel_iMSI          , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_gsm_map_IMSI },
  { &hf_camel_timeAndTimeZone, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_camel_TimeAndTimezone },
  { &hf_camel_gPRSMSClass   , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_GPRSMSClass },
  { &hf_camel_pDPType       , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_PDPType },
  { &hf_camel_qualityOfService, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_QualityOfService },
  { &hf_camel_accessPointName, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_AccessPointName },
  { &hf_camel_routeingAreaIdentity, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ms_RAIdentity },
  { &hf_camel_chargingID    , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ms_GPRSChargingID },
  { &hf_camel_sGSNCapabilities, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_SGSNCapabilities },
  { &hf_camel_locationInformationGPRS, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_LocationInformationGPRS },
  { &hf_camel_pDPInitiationType, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_PDPInitiationType },
  { &hf_camel_extensions    , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ExtensionsArray },
  { &hf_camel_gGSNAddress   , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ms_GSN_Address },
  { &hf_camel_secondaryPDPContext, BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  { &hf_camel_iMEI          , BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_IMEI },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_InitialDPGPRSArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InitialDPGPRSArg_sequence, hf_index, ett_camel_InitialDPGPRSArg);

  return offset;
}


static const ber_sequence_t CallGapArg_sequence[] = {
  { &hf_camel_gapCriteria   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_GapCriteria },
  { &hf_camel_gapIndicators , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_GapIndicators },
  { &hf_camel_controlType   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ControlType },
  { &hf_camel_gapTreatment  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_GapTreatment },
  { &hf_camel_extensions    , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ExtensionsArray },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_CallGapArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CallGapArg_sequence, hf_index, ett_camel_CallGapArg);

  return offset;
}


static const ber_sequence_t InitialDPArg_sequence[] = {
  { &hf_camel_serviceKey    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_ServiceKey },
  { &hf_camel_calledPartyNumber, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_CalledPartyNumber },
  { &hf_camel_callingPartyNumber, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_CallingPartyNumber },
  { &hf_camel_callingPartysCategory, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_CallingPartysCategory },
  { &hf_camel_cGEncountered , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_CGEncountered },
  { &hf_camel_iPSSPCapabilities, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_IPSSPCapabilities },
  { &hf_camel_locationNumber, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_LocationNumber },
  { &hf_camel_originalCalledPartyID, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_OriginalCalledPartyID },
  { &hf_camel_extensions    , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ExtensionsArray },
  { &hf_camel_highLayerCompatibility, BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_HighLayerCompatibility },
  { &hf_camel_additionalCallingPartyNumber, BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_AdditionalCallingPartyNumber },
  { &hf_camel_bearerCapability, BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_BearerCapability },
  { &hf_camel_eventTypeBCSM , BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_EventTypeBCSM },
  { &hf_camel_redirectingPartyID, BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_RedirectingPartyID },
  { &hf_camel_redirectionInformation, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_RedirectionInformation },
  { &hf_camel_cause         , BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_Cause },
  { &hf_camel_serviceInteractionIndicatorsTwo, BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ServiceInteractionIndicatorsTwo },
  { &hf_camel_carrier       , BER_CLASS_CON, 37, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_Carrier },
  { &hf_camel_cug_Index     , BER_CLASS_CON, 45, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ms_CUG_Index },
  { &hf_camel_cug_Interlock , BER_CLASS_CON, 46, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ms_CUG_Interlock },
  { &hf_camel_cug_OutgoingAccess, BER_CLASS_CON, 47, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  { &hf_camel_iMSI          , BER_CLASS_CON, 50, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_IMSI },
  { &hf_camel_subscriberState, BER_CLASS_CON, 51, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_SubscriberState },
  { &hf_camel_locationInformation, BER_CLASS_CON, 52, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ms_LocationInformation },
  { &hf_camel_ext_basicServiceCode, BER_CLASS_CON, 53, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_Ext_BasicServiceCode },
  { &hf_camel_callReferenceNumber, BER_CLASS_CON, 54, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_CallReferenceNumber },
  { &hf_camel_mscAddress    , BER_CLASS_CON, 55, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ISDN_AddressString },
  { &hf_camel_calledPartyBCDNumber, BER_CLASS_CON, 56, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_CalledPartyBCDNumber },
  { &hf_camel_timeAndTimezone, BER_CLASS_CON, 57, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_TimeAndTimezone },
  { &hf_camel_gsm_ForwardingPending, BER_CLASS_CON, 58, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_NULL },
  { &hf_camel_initialDPArgExtension, BER_CLASS_CON, 59, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_InitialDPArgExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_InitialDPArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InitialDPArg_sequence, hf_index, ett_camel_InitialDPArg);

  return offset;
}


static const ber_sequence_t InitialDPSMSArg_sequence[] = {
  { &hf_camel_serviceKey    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_ServiceKey },
  { &hf_camel_destinationSubscriberNumber, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_CalledPartyBCDNumber },
  { &hf_camel_callingPartyNumberas, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_SMS_AddressString },
  { &hf_camel_eventTypeSMS  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_EventTypeSMS },
  { &hf_camel_iMSI          , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_IMSI },
  { &hf_camel_locationInformationMSC, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ms_LocationInformation },
  { &hf_camel_locationInformationGPRS, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_LocationInformationGPRS },
  { &hf_camel_sMSCAddress   , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ISDN_AddressString },
  { &hf_camel_timeAndTimezone, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_TimeAndTimezone },
  { &hf_camel_tPShortMessageSpecificInfo, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_TPShortMessageSpecificInfo },
  { &hf_camel_tPProtocolIdentifier, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_TPProtocolIdentifier },
  { &hf_camel_tPDataCodingScheme, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_TPDataCodingScheme },
  { &hf_camel_tPValidityPeriod, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_TPValidityPeriod },
  { &hf_camel_extensions    , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ExtensionsArray },
  { &hf_camel_smsReferenceNumber, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_CallReferenceNumber },
  { &hf_camel_mscAddress    , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ISDN_AddressString },
  { &hf_camel_sgsnNumber    , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ISDN_AddressString },
  { &hf_camel_ms_Classmark2 , BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ms_MS_Classmark2 },
  { &hf_camel_gPRSMSClass   , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_GPRSMSClass },
  { &hf_camel_iMEI          , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_IMEI },
  { &hf_camel_calledPartyNumberSMS, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ISDN_AddressString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_InitialDPSMSArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InitialDPSMSArg_sequence, hf_index, ett_camel_InitialDPSMSArg);

  return offset;
}



static int
dissect_camel_ReleaseSMSArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_camel_RPCause(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t SMSEventArray_sequence_of[1] = {
  { &hf_camel_SMSEventArray_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_camel_SMSEvent },
};

static int
dissect_camel_SMSEventArray(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SMSEventArray_sequence_of, hf_index, ett_camel_SMSEventArray);

  return offset;
}


static const ber_sequence_t RequestReportSMSEventArg_sequence[] = {
  { &hf_camel_sMSEvents     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_SMSEventArray },
  { &hf_camel_extensions    , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_ExtensionsArray },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_RequestReportSMSEventArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RequestReportSMSEventArg_sequence, hf_index, ett_camel_RequestReportSMSEventArg);

  return offset;
}


static const ber_sequence_t ApplyChargingGPRSArg_sequence[] = {
  { &hf_camel_chargingCharacteristics, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_ChargingCharacteristics },
  { &hf_camel_tariffSwitchInterval, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_INTEGER_1_86400 },
  { &hf_camel_pDPID         , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_PDPId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_ApplyChargingGPRSArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ApplyChargingGPRSArg_sequence, hf_index, ett_camel_ApplyChargingGPRSArg);

  return offset;
}


static const ber_sequence_t ApplyChargingReportGPRSArg_sequence[] = {
  { &hf_camel_chargingResult, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_ChargingResult },
  { &hf_camel_qualityOfService, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_QualityOfService },
  { &hf_camel_active        , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_BOOLEAN },
  { &hf_camel_pDPID         , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_PDPId },
  { &hf_camel_chargingRollOver, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_camel_ChargingRollOver },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_ApplyChargingReportGPRSArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ApplyChargingReportGPRSArg_sequence, hf_index, ett_camel_ApplyChargingReportGPRSArg);

  return offset;
}


static const ber_sequence_t CancelGPRSArg_sequence[] = {
  { &hf_camel_pDPID         , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_PDPId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_CancelGPRSArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CancelGPRSArg_sequence, hf_index, ett_camel_CancelGPRSArg);

  return offset;
}


static const ber_sequence_t ContinueGPRSArg_sequence[] = {
  { &hf_camel_pDPID         , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_PDPId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_ContinueGPRSArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ContinueGPRSArg_sequence, hf_index, ett_camel_ContinueGPRSArg);

  return offset;
}


static const ber_sequence_t ResetTimerGPRSArg_sequence[] = {
  { &hf_camel_timerID       , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_TimerID },
  { &hf_camel_timervalue    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_TimerValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_ResetTimerGPRSArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ResetTimerGPRSArg_sequence, hf_index, ett_camel_ResetTimerGPRSArg);

  return offset;
}


static const value_string camel_T_cancelproblem_vals[] = {
  {   0, "unknownOperation" },
  {   1, "tooLate" },
  {   2, "operationNotCancellable" },
  { 0, NULL }
};


static int
dissect_camel_T_cancelproblem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t CancelFailedPARAM_sequence[] = {
  { &hf_camel_cancelproblem , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_camel_T_cancelproblem },
  { &hf_camel_operation     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camel_InvokeID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_camel_CancelFailedPARAM(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CancelFailedPARAM_sequence, hf_index, ett_camel_CancelFailedPARAM);

  return offset;
}


static const value_string camel_RequestedInfoErrorPARAM_vals[] = {
  {   1, "unknownRequestedInfo" },
  {   2, "requestedInfoNotAvailable" },
  { 0, NULL }
};


static int
dissect_camel_RequestedInfoErrorPARAM(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_camel_SystemFailurePARAM(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_camel_UnavailableNetworkResource(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string camel_TaskRefusedPARAM_vals[] = {
  {   0, "generic" },
  {   1, "unobtainable" },
  {   2, "congestion" },
  { 0, NULL }
};


static int
dissect_camel_TaskRefusedPARAM(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}

/*--- PDUs ---*/

static void dissect_Component_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_camel_Component(FALSE, tvb, 0, &asn1_ctx, tree, hf_camel_Component_PDU);
}


/*--- End of included file: packet-camel-fn.c ---*/
#line 236 "packet-camel-template.c"

const value_string camel_opr_code_strings[] = {

  {0,	"InitialDP"},
  {16, "AssistRequestInstructions"},
  {17, "EstablishTemporaryConnection"},
  {18, "DisconnectForwardConnection"},
  {19, "ConnectToResource"},
  {20, "Connect"},
  {22, "ReleaseCall"},
  {23, "RequestReportBCSMEvent"},
  {24, "EventReportBCSM"},
  {27, "CollectInformation"},
  {31, "Continue"},
  {32, "InitiateCallAttempt"},
  {33, "ResetTimer"},
  {34, "FurnishChargingInformation"},
  {35, "ApplyCharging"},
  {36, "ApplyChargingReport"},
  {41, "CallGap"},
  {44, "CallInformationReport"},
  {45, "CallInformationRequest"},
  {46, "SendChargingInformation"},
  {47, "PlayAnnouncement"},
  {48, "PromptAndCollectUserInformation"},
  {49, "SpecializedResourceReport"},
  {53, "Cancel"},
  {55, "ActivityTest"},
  {56, "ContinueWithArgument"},
  {60, "InitialDPSMS"},
  {61, "FurnishChargingInformationSMS"},
  {62, "ConnectSMS"},
  {63, "RequestReportSMSEvent"},
  {64, "EventReportSMS"},
  {65, "ContinueSMS"},
  {66, "ReleaseSMS"},
  {67, "ResetTimerSMS"},
  {70, "ActivityTestGPRS"},
  {71, "ApplyChargingGPRS"},
  {72, "ApplyChargingReportGPRS"},
  {73, "CancelGPRS"},
  {74, "ConnectGPRS"},
  {75, "ContinueGPRS"},
  {76, "EntityReleasedGPRS"},
  {77, "FurnishChargingInformationGPRS"},
  {78, "InitialDPGPRS"},
  {79, "ReleaseGPRS"},
  {80, "EventReportGPRS"},
  {81, "RequestReportGPRSEvent"},
  {82, "ResetTimerGPRS"},
  {83, "SendChargingInformationGPRS"},
  {86,	"DFCWithArgument"},
  {88,	"ContinueWithArgument"},
  {90,	"DisconnectLeg"},
  {93,	"MoveLeg"},
  {95,	"SplitLeg"},
  {96,	"EntityReleased"},
  {97,	"PlayTone"},
  {0, NULL}
};

static const value_string camel_err_code_string_vals[] = {
  { 0,  "Canceled"},
  { 1,  "CancelFailed"},
  { 3,  "ETCFailed"},
  { 4,  "ImproperCallerResponse"},
  { 6,  "MissingCustomerRecord"},
  { 7,  "MissingParameter"},
  { 8,  "ParameterOutOfRange"},
  { 10, "RequestedInfoError"},
  { 11, "SystemFailure"},
  { 12, "TaskRefused"},
  { 13, "UnavailableResource"},
  { 14, "UnexpectedComponentSequence"},
  { 15, "UnexpectedDataValue"},
  { 16, "UnexpectedParameter"},
  { 17, "UnknownLegID"},
  { 50, "UnknownPDPID"},
  { 51, "UnknownCSID"},
  { 0, NULL}
};

static char camel_number_to_char(int number)
{
   if (number < 10)
   return (char) (number + 48 ); /* this is ASCII specific */
   else
   return (char) (number + 55 );
}

/*
 * 24.011 8.2.5.4
 */   
static guint8
dissect_RP_cause_ie(tvbuff_t *tvb, guint32 offset, _U_ guint len,
		    proto_tree *tree, int hf_cause_value, guint8 *cause_value)
{
  guint8	oct;
  guint32	curr_offset;
  static char a_bigbuf[1024];
  
  curr_offset = offset;
  oct = tvb_get_guint8(tvb, curr_offset);

  *cause_value = oct & 0x7f; 
  
  other_decode_bitfield_value(a_bigbuf, oct, 0x7f, 8);
  proto_tree_add_uint_format(tree, hf_cause_value,
			     tvb, curr_offset, 1, *cause_value,
			     "%s : %s",
			     a_bigbuf,
			     val_to_str(*cause_value, camel_RP_Cause_values, 
					"Unknown Cause (%u), treated as (41) \"Temporary failure\" for MO-SMS or (111) \"Protocol error,unspecified\" for MT-SMS"));
  curr_offset++;
  
  if ((oct & 0x80)) {
    oct = tvb_get_guint8(tvb, curr_offset);
    proto_tree_add_uint_format(tree, hf_cause_value,
			       tvb, curr_offset, 1, oct,
			       "Diagnostic : %u", oct);
    curr_offset++;
  }
  return(curr_offset - offset);
}


static int dissect_invokeData(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx) {
  proto_item *cause;
  gint8 bug_class;
  gboolean bug_pc, bug_ind_field;
  gint32 bug_tag;
  guint32 bug_len1;

  switch(opcode){
  case 0: /*InitialDP*/
    offset=dissect_camel_InitialDPArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 16: /*AssistRequestInstructions*/
    offset=dissect_camel_AssistRequestInstructionsArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 17: /*EstablishTemporaryConnection*/
    offset=dissect_camel_EstablishTemporaryConnectionArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 18: /*DisconnectForwardConnections*/
    proto_tree_add_text(tree, tvb, offset, -1, "Disconnect Forward Connection");
    break;
  case 19: /*ConnectToResource*/
    offset=dissect_camel_ConnectToResourceArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 20: /*Connect*/
    offset=dissect_camel_ConnectArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 22: /*releaseCall*/
    offset=dissect_camel_ReleaseCallArg(FALSE, tvb, offset, actx, tree, hf_camel_cause);
    break;
  case 23: /*RequestReportBCSMEvent*/
    offset=dissect_camel_RequestReportBCSMEventArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 24: /*EventReportBCSM*/
    offset=dissect_camel_EventReportBCSMArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 27: /*CollectInformation*/
    offset=dissect_camel_CollectInformationArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 31: /*Continue*/
    /* Continue: no arguments - do nothing */
    break;
  case 32: /*initiateCallAttempt*/
    offset=dissect_camel_InitiateCallAttemptArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 33: /*ResetTimer*/
    offset=dissect_camel_ResetTimerArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 34: /*FurnishChargingInformation*/
    /* offset=dissect_camel_FurnishChargingInformationArg(TRUE, tvb, offset, tree, -1); */
    offset = get_ber_identifier(tvb, offset, &bug_class, &bug_pc, &bug_tag);
    offset = get_ber_length(tree, tvb, offset, &bug_len1, &bug_ind_field);
    offset=dissect_camel_CAMEL_FCIBillingChargingCharacteristics(TRUE, tvb, offset, actx, tree, -1);
    break;
  case 35: /*ApplyCharging*/
    offset=dissect_camel_ApplyChargingArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 36: /*ApplyChargingReport*/
    /* offset=dissect_camel_ApplyChargingReportArg(TRUE, tvb, offset, tree, -1); */
    offset = get_ber_identifier(tvb, offset, &bug_class, &bug_pc, &bug_tag);
    offset = get_ber_length(tree, tvb, offset, &bug_len1, &bug_ind_field);
    offset=dissect_camel_CAMEL_CallResult(TRUE, tvb, offset, actx, tree, -1);
    break;
  case 41: /*CallGap*/
    offset=dissect_camel_CallGapArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 44: /*CallInformationReport*/
    offset=dissect_camel_CallInformationReportArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 45: /*CallInformationRequest*/
    offset=dissect_camel_CallInformationRequestArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 46: /*SendChargingInformation*/
    offset=dissect_camel_SendChargingInformationArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 47: /*PlayAnnouncement*/
    offset=dissect_camel_PlayAnnouncementArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 48: /*PromptAndCollectUserInformation*/
    offset=dissect_camel_PromptAndCollectUserInformationArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 49: /*SpecializedResourceReport*/
    offset=dissect_camel_SpecializedResourceReportArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 53: /*Cancel*/
    offset=dissect_camel_CancelArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 56: /*ContinueWithArgument*/
    offset=dissect_camel_ContinueWithArgumentArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 60: /*InitialDPSMS*/
    offset=dissect_camel_InitialDPSMSArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 61: /*FurnishChargingInformationSMS*/
    /* offset=dissect_camel_FurnishChargingInformationSMSArg(FALSE, tvb, offset, tree, -1); */
    offset = get_ber_identifier(tvb, offset, &bug_class, &bug_pc, &bug_tag);
    offset = get_ber_length(tree, tvb, offset, &bug_len1, &bug_ind_field);
    offset=dissect_camel_CAMEL_FCISMSBillingChargingCharacteristics(TRUE, tvb, offset, actx, tree, -1);
    break;
  case 62: /*ConnectSMS*/
    offset=dissect_camel_ConnectSMSArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 63: /*RequestReportSMSEvent*/
    offset=dissect_camel_RequestReportSMSEventArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 64: /*EventReportSMS*/
    offset=dissect_camel_EventReportSMSArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 65: /*ContinueSMS*/
    /* ContinueSMS: no arguments - do nothing */
    break;
  case 66: /*ReleaseSMS*/
    offset=dissect_camel_ReleaseSMSArg(FALSE, tvb, offset, actx, tree, hf_camel_RP_Cause);
    break;
  case 67: /*ResetTimerSMS*/
    offset=dissect_camel_ResetTimerSMSArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 71: /*ApplyChargingGPRS*/
    offset=dissect_camel_ApplyChargingGPRSArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 72: /*ApplyChargingReportGPRS*/
    offset=dissect_camel_ApplyChargingReportGPRSArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 73: /*CancelGPRS*/
    offset=dissect_camel_CancelGPRSArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 74: /*ConnectGPRS*/
    offset=dissect_camel_ConnectGPRSArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 75: /*ContinueGPRS*/
    offset=dissect_camel_ContinueGPRSArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 76: /*EntityReleasedGPRS*/
    offset=dissect_camel_EntityReleasedGPRSArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 77: /*FurnishChargingInformationGPRS*/
    /* offset=dissect_camel_FurnishChargingInformationGPRSArg(FALSE, tvb, offset, tree, -1); */
    offset = get_ber_identifier(tvb, offset, &bug_class, &bug_pc, &bug_tag);
    offset = get_ber_length(tree, tvb, offset, &bug_len1, &bug_ind_field);
    offset=dissect_camel_CAMEL_FCIGPRSBillingChargingCharacteristics(TRUE, tvb, offset, actx, tree, -1);
    break;
  case 78: /*InitialDPGPRS*/
    offset=dissect_camel_InitialDPGPRSArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 79: /*ReleaseGPRS*/
    offset=dissect_camel_ReleaseGPRSArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 80: /*EventReportGPRS*/
    offset=dissect_camel_EventReportGPRSArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 81: /*RequestReportGPRSEvent*/
    offset=dissect_camel_RequestReportGPRSEventArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 82: /*ResetTimerGPRS*/
    offset=dissect_camel_ResetTimerGPRSArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 83: /*SendChargingInformationGPRS*/
    offset=dissect_camel_SendChargingInformationGPRSArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 86: /*DFCWithArgument*/
    offset= dissect_camel_DisconnectForwardConnectionWithArgumentArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 88: /*ContinueWithArgument*/
	  /* XXX Same as opcode 56 ??? */
    offset= dissect_camel_ContinueWithArgumentArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 90: /*DisconnectLeg*/
    offset= dissect_camel_DisconnectLegArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 93: /*MoveLeg*/
    offset= dissect_camel_MoveLegArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 95: /*SplitLeg*/
    offset= dissect_camel_SplitLegArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 96: /*EntityReleased*/
    offset= dissect_camel_EntityReleasedArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 97: /*PlayTone*/
    offset= dissect_camel_PlayToneArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  default:
    cause=proto_tree_add_text(tree, tvb, offset, -1, "Unknown invokeData blob");
    proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
    expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "Unknown invokeData %d",opcode);
    /* todo call the asn.1 dissector */
  }
  return offset;
}


static int dissect_returnResultData(proto_tree *tree, tvbuff_t *tvb, int offset,asn1_ctx_t *actx) {
  proto_item *cause;

  switch(opcode){
  case 32: /*initiateCallAttempt*/
    offset=dissect_camel_InitiateCallAttemptRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 48: /*PromptAndCollectUserInformation*/
    offset=dissect_camel_ReceivedInformationArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 55: /*ActivityTest*/
    /* ActivityTest: no arguments - do nothing */
    break;
  case 70: /*ActivityTestGPRS*/
    /* ActivityTestGPRS: no arguments - do nothing */
    break;
  default:
    cause=proto_tree_add_text(tree, tvb, offset, -1, "Unknown returnResultData blob");
    proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
    expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "Unknown returnResultData %d",opcode);
  }
  return offset;
}

static int dissect_returnErrorData(proto_tree *tree, tvbuff_t *tvb, int offset,asn1_ctx_t *actx) {
  proto_item *cause;

  switch(errorCode) {
  case 1: /*CancelFailed*/
    offset=dissect_camel_CancelFailedPARAM(TRUE, tvb, offset, actx, tree, -1);
    break;
  case 10: /*RequestedInfoError*/
    offset=dissect_camel_RequestedInfoErrorPARAM(TRUE, tvb, offset, actx, tree, -1);
    break;
  case 11: /*SystemFailure*/
   offset=dissect_camel_SystemFailurePARAM(TRUE, tvb, offset, actx, tree, -1);
    break;
  case 12: /*TaskRefused*/
   offset=dissect_camel_TaskRefusedPARAM(TRUE, tvb, offset, actx, tree, -1);
    break;
  default:
    cause=proto_tree_add_text(tree, tvb, offset, -1, "Unknown returnErrorData blob");
    proto_item_set_expert_flags(cause, PI_MALFORMED, PI_WARN);
    expert_add_info_format(actx->pinfo, cause, PI_MALFORMED, PI_WARN, "Unknown returnErrorData %d",errorCode);
  }
  return offset;
}

static guint8 camel_pdu_type = 0;
static guint8 camel_pdu_size = 0;

static void dissect_camelext_CAPGPRSReferenceNumber(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree) {
  proto_item    *item=NULL;
  proto_tree    *tree=NULL;
  proto_item    *camel_item=NULL;
  proto_tree    *camel_tree=NULL;
  asn1_ctx_t	asn1_ctx;

  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);


  if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Camel");
  }

  /* create display subtree for the protocol */
  if(parent_tree){
    camel_item = proto_tree_add_item(parent_tree, proto_camel, tvb, 0, -1, FALSE);
    camel_tree = proto_item_add_subtree(camel_item, ett_camel);
  }
  /* create display subtree for the protocol */
  if(camel_tree){
    item = proto_tree_add_text(camel_tree, tvb, 0, -1, "GPRS Reference Number");
    tree = proto_item_add_subtree(item, ett_camel_CAPGPRSReferenceNumber);
  }
  dissect_camel_CAPGPRSReferenceNumber(FALSE, tvb, 0, &asn1_ctx, tree, -1);
}

static int
dissect_camel_camelPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_,proto_tree *tree, int hf_index) {

  char *version_ptr;
  struct tcap_private_t * p_private_tcap;

  opcode = 0;
  application_context_version = 0;
  if (actx->pinfo->private_data != NULL){
    p_private_tcap=actx->pinfo->private_data; 
    
    if (p_private_tcap->acv==TRUE ){
      version_ptr = strrchr(p_private_tcap->oid,'.');
      if (version_ptr)
	application_context_version = atoi(version_ptr+1);
    }
    gp_camelsrt_info->tcap_context=p_private_tcap->context; 
    if (p_private_tcap->context)
      gp_camelsrt_info->tcap_session_id

	= ( (struct tcaphash_context_t *) (p_private_tcap->context))->session_id;
  }

  camel_pdu_type = tvb_get_guint8(tvb, offset)&0x0f;
  /* Get the length and add 2 */
  camel_pdu_size = tvb_get_guint8(tvb, offset+1)+2;

  if (check_col(actx->pinfo->cinfo, COL_INFO)){
    /* Populate the info column with PDU type*/
    col_set_str(actx->pinfo->cinfo, COL_INFO, val_to_str(camel_pdu_type, camel_Component_vals, "Unknown Camel (%u)"));
    col_append_fstr(actx->pinfo->cinfo, COL_INFO, " ");
  }

  offset = dissect_camel_Component(FALSE, tvb, 0, actx, tree, hf_index);

  return offset;
}

static void
dissect_camel(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
  proto_item    *item=NULL;
  proto_tree    *tree=NULL;
  proto_item  *stat_item=NULL;
  proto_tree  *stat_tree=NULL;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

  if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "Camel");
  }

  /* create display subtree for the protocol */
  if(parent_tree){
     item = proto_tree_add_item(parent_tree, proto_camel, tvb, 0, -1, FALSE);
     tree = proto_item_add_subtree(item, ett_camel);
  }
  /* camelsrt reset counter, and initialise global pointer
     to store service response time related data */
  gp_camelsrt_info=camelsrt_razinfo();
  dissect_camel_camelPDU(FALSE, tvb, 0, &asn1_ctx , tree, -1);
  
  /* If a Tcap context is associated to this transaction */
  if (gcamel_HandleSRT &&
      gp_camelsrt_info->tcap_context ) {
    if (gcamel_DisplaySRT && tree) {
      stat_item = proto_tree_add_text(tree, tvb, 0, 0, "Stat");
      stat_tree = proto_item_add_subtree(stat_item, ett_camel_stat);
    }
    camelsrt_call_matching(tvb, pinfo, stat_tree, gp_camelsrt_info);
    tap_queue_packet(camel_tap, pinfo, gp_camelsrt_info);
  }
}

/*--- proto_reg_handoff_camel ---------------------------------------*/
static void range_delete_callback(guint32 ssn)
{
  if (ssn) {
    delete_itu_tcap_subdissector(ssn, camel_handle);
  }
}

static void range_add_callback(guint32 ssn)
{
  if (ssn) {
    add_itu_tcap_subdissector(ssn, camel_handle);
  }
}

void proto_reg_handoff_camel(void) {

  static int camel_prefs_initialized = FALSE;
  if (!camel_prefs_initialized) {
    camel_prefs_initialized = TRUE;
    camel_handle = create_dissector_handle(dissect_camel, proto_camel);

    register_ber_oid_dissector_handle("0.4.0.0.1.0.50.0",camel_handle, proto_camel, "itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network|umts-Network(1) applicationContext(0) cap-gsmssf-to-gsmscf(50) version1(0)" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.50.1",camel_handle, proto_camel, "itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network|umts-Network(1) applicationContext(0) cap-gsmssf-to-gsmscf(50) version2(1)" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.51.1",camel_handle, proto_camel, "itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network|umts-Network(1) applicationContext(0) cap-assist-handoff-gsmssf-to-gsmscf(51) version2(1)" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.52.1",camel_handle, proto_camel, "itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network|umts-Network(1) applicationContext(0) cap-gsmSRF-to-gsmscf(52) version2(1)" );
    register_ber_oid_dissector_handle("0.4.0.0.1.21.3.50",camel_handle, proto_camel, "itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) cAP3OE(21) ac(3) id-ac-CAP-gprsSSF-gsmSCF-AC(50)" );
    register_ber_oid_dissector_handle("0.4.0.0.1.21.3.61",camel_handle, proto_camel, "itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) cAP3OE(21) ac(3) id-ac-cap3-sms-AC(61)" );

    register_ber_oid_dissector("0.4.0.0.1.1.5.2", dissect_camelext_CAPGPRSReferenceNumber, proto_camel, "itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) abstractSyntax(1) cap-GPRS-ReferenceNumber(5) version3(2)");
  } else {
    range_foreach(ssn_range, range_delete_callback);
  }

  g_free(ssn_range);
  ssn_range = range_copy(global_ssn_range);

  range_foreach(ssn_range, range_add_callback);
  
}

void proto_register_camel(void) {
  module_t *camel_module;
  /* List of fields */
  static hf_register_info hf[] = {
  { &hf_camel_cause_indicator, /* Currently not enabled */
    { "Cause indicator",  "camel.cause_indicator",
      FT_UINT8, BASE_DEC, VALS(q850_cause_code_vals), 0x7f,
      "", HFILL }},
  { &hf_camel_addr_extension,
     { "Extension", "camel.addr_extension",
        FT_BOOLEAN, 8, TFS(&camel_extension_value), 0x80,
        "Extension", HFILL }},
    { &hf_camel_addr_natureOfAddressIndicator,
      { "Nature of address", "camel.addr_nature_of_addr",
        FT_UINT8, BASE_HEX, VALS(camel_nature_of_addr_indicator_values), 0x70,
        "Nature of address", HFILL }},
    { &hf_camel_addr_numberingPlanInd,
      { "Numbering plan indicator", "camel.addr_numbering_plan",
        FT_UINT8, BASE_HEX, VALS(camel_number_plan_values), 0x0f,
        "Numbering plan indicator", HFILL }},
  { &hf_camel_addr_digits,
      { "Address digits", "camel.address_digits",
        FT_STRING, BASE_NONE, NULL, 0,
        "Address digits", HFILL }},
   { &hf_digit,
      { "Digit Value",  "camel.digit_value",
      FT_UINT8, BASE_DEC, VALS(digit_value), 0, "Digit Value", HFILL }},
   { &hf_camel_PDPTypeNumber_etsi,
      { "ETSI defined PDP Type Value",  "camel.PDPTypeNumber_etsi",
      FT_UINT8, BASE_HEX, VALS(gsm_map_etsi_defined_pdp_vals), 0,
	  "ETSI defined PDP Type Value", HFILL }},
   { &hf_camel_PDPTypeNumber_ietf,
      { "IETF defined PDP Type Value",  "camel.PDPTypeNumber_ietf",
      FT_UINT8, BASE_HEX, VALS(gsm_map_ietf_defined_pdp_vals), 0,
	  "IETF defined PDP Type Value", HFILL }},
   { &hf_camel_PDPAddress_IPv4,
      { "PDPAddress IPv4",  "camel.PDPAddress_IPv4",
	  FT_IPv4, BASE_NONE, NULL, 0,
	  "IPAddress IPv4", HFILL }},
   { &hf_camel_PDPAddress_IPv6,
      { "PDPAddress IPv6",  "camel.PDPAddress_IPv6",
	  FT_IPv6, BASE_NONE, NULL, 0,
	  "IPAddress IPv6", HFILL }},
   { &hf_camel_cellGlobalIdOrServiceAreaIdFixedLength,
      { "CellGlobalIdOrServiceAreaIdFixedLength", "camel.CellGlobalIdOrServiceAreaIdFixedLength",
        FT_BYTES, BASE_HEX, NULL, 0,
        "LocationInformationGPRS/CellGlobalIdOrServiceAreaIdOrLAI", HFILL }},
  { &hf_camel_RP_Cause,
      { "RP Cause",  "camel.RP_Cause",
      FT_UINT8, BASE_DEC, NULL, 0,
	"RP Cause Value", HFILL }},

  /* Camel Service Response Time */
    { &hf_camelsrt_SessionId,
      { "Session Id",
        "camel.srt.session_id",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "", HFILL }
    },
    { &hf_camelsrt_RequestNumber,
      { "Request Number",
        "camel.srt.request_number",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        "", HFILL }
    },
    { &hf_camelsrt_Duplicate,
      { "Request Duplicate",
        "camel.srt.duplicate",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "", HFILL }
    },
    { &hf_camelsrt_RequestFrame,
      { "Requested Frame",
        "camel.srt.reqframe",
        FT_FRAMENUM, BASE_NONE, NULL, 0x0,
        "SRT Request Frame", HFILL }
    },
    { &hf_camelsrt_ResponseFrame,
      { "Response Frame",
        "camel.srt.rspframe",
        FT_FRAMENUM, BASE_NONE, NULL, 0x0,
        "SRT Response Frame", HFILL }
    },
    { &hf_camelsrt_DeltaTime,
      { "Service Response Time",
        "camel.srt.deltatime",
        FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
        "DeltaTime between Request and Response", HFILL }
    },
    { &hf_camelsrt_SessionTime,
      { "Session duration",
        "camel.srt.sessiontime",
        FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
        "Duration of the TCAP session", HFILL }
    },
    { &hf_camelsrt_DeltaTime31,
      { "Service Response Time",
        "camel.srt.deltatime31",
        FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
        "DeltaTime between InitialDP and Continue", HFILL }
    },
    { &hf_camelsrt_DeltaTime65,
      { "Service Response Time",
        "camel.srt.deltatime65",
        FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
        "DeltaTime between InitialDPSMS and ContinueSMS", HFILL }
    },
    { &hf_camelsrt_DeltaTime75,
      { "Service Response Time",
        "camel.srt.deltatime75",
        FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
        "DeltaTime between InitialDPGPRS and ContinueGPRS", HFILL }
    },
    { &hf_camelsrt_DeltaTime35,
      { "Service Response Time",
        "camel.srt.deltatime35",
        FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
        "DeltaTime between ApplyCharginReport and ApplyCharging", HFILL }
    },
    { &hf_camelsrt_DeltaTime22,
      { "Service Response Time",
        "camel.srt.deltatime22",
        FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
        "DeltaTime between EventReport(Disconnect) and Release Call", HFILL }
    },
  { &hf_camelsrt_DeltaTime80,
      { "Service Response Time",
        "camel.srt.deltatime80",
        FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
        "DeltaTime between EventReportGPRS and ContinueGPRS", HFILL }
    },

#ifdef REMOVED
#endif

/*--- Included file: packet-camel-hfarr.c ---*/
#line 1 "packet-camel-hfarr.c"
    { &hf_camel_Component_PDU,
      { "Component", "camel.Component",
        FT_UINT32, BASE_DEC, VALS(camel_Component_vals), 0,
        "camel.Component", HFILL }},
    { &hf_camel_invoke,
      { "invoke", "camel.invoke",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.Invoke", HFILL }},
    { &hf_camel_returnResultLast,
      { "returnResultLast", "camel.returnResultLast",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.ReturnResult", HFILL }},
    { &hf_camel_returnError,
      { "returnError", "camel.returnError",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.ReturnError", HFILL }},
    { &hf_camel_reject,
      { "reject", "camel.reject",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.Reject", HFILL }},
    { &hf_camel_invokeID,
      { "invokeID", "camel.invokeID",
        FT_INT32, BASE_DEC, NULL, 0,
        "camel.InvokeIdType", HFILL }},
    { &hf_camel_linkedID,
      { "linkedID", "camel.linkedID",
        FT_INT32, BASE_DEC, NULL, 0,
        "camel.InvokeIdType", HFILL }},
    { &hf_camel_opCode,
      { "opCode", "camel.opCode",
        FT_UINT32, BASE_DEC, VALS(camel_OPERATION_vals), 0,
        "camel.OPERATION", HFILL }},
    { &hf_camel_invokeparameter,
      { "invokeparameter", "camel.invokeparameter",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.InvokeParameter", HFILL }},
    { &hf_camel_resultretres,
      { "resultretres", "camel.resultretres",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_resultretres", HFILL }},
    { &hf_camel_returnparameter,
      { "returnparameter", "camel.returnparameter",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.ReturnResultParameter", HFILL }},
    { &hf_camel_errorCode,
      { "errorCode", "camel.errorCode",
        FT_UINT32, BASE_DEC, VALS(camel_ERROR_vals), 0,
        "camel.ERROR", HFILL }},
    { &hf_camel_parameter,
      { "parameter", "camel.parameter",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.ReturnErrorParameter", HFILL }},
    { &hf_camel_invokeIDRej,
      { "invokeIDRej", "camel.invokeIDRej",
        FT_UINT32, BASE_DEC, VALS(camel_T_invokeIDRej_vals), 0,
        "camel.T_invokeIDRej", HFILL }},
    { &hf_camel_derivable,
      { "derivable", "camel.derivable",
        FT_INT32, BASE_DEC, NULL, 0,
        "camel.InvokeIdType", HFILL }},
    { &hf_camel_not_derivable,
      { "not-derivable", "camel.not_derivable",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.NULL", HFILL }},
    { &hf_camel_problem,
      { "problem", "camel.problem",
        FT_UINT32, BASE_DEC, VALS(camel_T_problem_vals), 0,
        "camel.T_problem", HFILL }},
    { &hf_camel_generalProblem,
      { "generalProblem", "camel.generalProblem",
        FT_INT32, BASE_DEC, VALS(camel_GeneralProblem_vals), 0,
        "camel.GeneralProblem", HFILL }},
    { &hf_camel_invokeProblem,
      { "invokeProblem", "camel.invokeProblem",
        FT_INT32, BASE_DEC, VALS(camel_InvokeProblem_vals), 0,
        "camel.InvokeProblem", HFILL }},
    { &hf_camel_returnResultProblem,
      { "returnResultProblem", "camel.returnResultProblem",
        FT_INT32, BASE_DEC, VALS(camel_ReturnResultProblem_vals), 0,
        "camel.ReturnResultProblem", HFILL }},
    { &hf_camel_returnErrorProblem,
      { "returnErrorProblem", "camel.returnErrorProblem",
        FT_INT32, BASE_DEC, VALS(camel_ReturnErrorProblem_vals), 0,
        "camel.ReturnErrorProblem", HFILL }},
    { &hf_camel_localValue,
      { "localValue", "camel.localValue",
        FT_INT32, BASE_DEC, VALS(camel_CAMELOperationLocalvalue_vals), 0,
        "camel.OperationLocalvalue", HFILL }},
    { &hf_camel_globalValue,
      { "globalValue", "camel.globalValue",
        FT_OID, BASE_NONE, NULL, 0,
        "camel.OBJECT_IDENTIFIER", HFILL }},
    { &hf_camel_localErrorValue,
      { "localErrorValue", "camel.localErrorValue",
        FT_INT32, BASE_DEC, VALS(camel_CAMELLocalErrorcode_vals), 0,
        "camel.LocalErrorcode", HFILL }},
    { &hf_camel_globalErrorValue,
      { "globalErrorValue", "camel.globalErrorValue",
        FT_OID, BASE_NONE, NULL, 0,
        "camel.OBJECT_IDENTIFIER", HFILL }},
    { &hf_camel_actimeDurationCharging,
      { "actimeDurationCharging", "camel.actimeDurationCharging",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_actimeDurationCharging", HFILL }},
    { &hf_camel_maxCallPeriodDuration,
      { "maxCallPeriodDuration", "camel.maxCallPeriodDuration",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_1_864000", HFILL }},
    { &hf_camel_releaseIfdurationExceeded,
      { "releaseIfdurationExceeded", "camel.releaseIfdurationExceeded",
        FT_BOOLEAN, 8, NULL, 0,
        "camel.BOOLEAN", HFILL }},
    { &hf_camel_tariffSwitchInterval,
      { "tariffSwitchInterval", "camel.tariffSwitchInterval",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_1_86400", HFILL }},
    { &hf_camel_actone,
      { "actone", "camel.actone",
        FT_BOOLEAN, 8, NULL, 0,
        "camel.BOOLEAN", HFILL }},
    { &hf_camel_extensions,
      { "extensions", "camel.extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.ExtensionsArray", HFILL }},
    { &hf_camel_legID,
      { "legID", "camel.legID",
        FT_UINT32, BASE_DEC, VALS(camel_LegID_vals), 0,
        "camel.LegID", HFILL }},
    { &hf_camel_srfConnection,
      { "srfConnection", "camel.srfConnection",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.CallSegmentID", HFILL }},
    { &hf_camel_aOCInitial,
      { "aOCInitial", "camel.aOCInitial",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.CAI_Gsm0224", HFILL }},
    { &hf_camel_aOCSubsequent,
      { "aOCSubsequent", "camel.aOCSubsequent",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.AOCSubsequent", HFILL }},
    { &hf_camel_cAI_GSM0224,
      { "cAI-GSM0224", "camel.cAI_GSM0224",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.CAI_Gsm0224", HFILL }},
    { &hf_camel_istone,
      { "istone", "camel.istone",
        FT_BOOLEAN, 8, NULL, 0,
        "camel.BOOLEAN", HFILL }},
    { &hf_camel_burstList,
      { "burstList", "camel.burstList",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.BurstList", HFILL }},
    { &hf_camel_conferenceTreatmentIndicator,
      { "conferenceTreatmentIndicator", "camel.conferenceTreatmentIndicator",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.OCTET_STRING_SIZE_1", HFILL }},
    { &hf_camel_callCompletionTreatmentIndicator,
      { "callCompletionTreatmentIndicator", "camel.callCompletionTreatmentIndicator",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.OCTET_STRING_SIZE_1", HFILL }},
    { &hf_camel_calledAddressValue,
      { "calledAddressValue", "camel.calledAddressValue",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.Digits", HFILL }},
    { &hf_camel_gapOnService,
      { "gapOnService", "camel.gapOnService",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.GapOnService", HFILL }},
    { &hf_camel_calledAddressAndService,
      { "calledAddressAndService", "camel.calledAddressAndService",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_calledAddressAndService", HFILL }},
    { &hf_camel_serviceKey,
      { "serviceKey", "camel.serviceKey",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.ServiceKey", HFILL }},
    { &hf_camel_callingAddressAndService,
      { "callingAddressAndService", "camel.callingAddressAndService",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_callingAddressAndService", HFILL }},
    { &hf_camel_callingAddressValue,
      { "callingAddressValue", "camel.callingAddressValue",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.Digits", HFILL }},
    { &hf_camel_eventTypeBCSM,
      { "eventTypeBCSM", "camel.eventTypeBCSM",
        FT_UINT32, BASE_DEC, VALS(camel_EventTypeBCSM_vals), 0,
        "camel.EventTypeBCSM", HFILL }},
    { &hf_camel_monitorMode,
      { "monitorMode", "camel.monitorMode",
        FT_UINT32, BASE_DEC, VALS(camel_MonitorMode_vals), 0,
        "camel.MonitorMode", HFILL }},
    { &hf_camel_legID6,
      { "legID6", "camel.legID6",
        FT_UINT32, BASE_DEC, VALS(camel_LegID_vals), 0,
        "camel.LegID", HFILL }},
    { &hf_camel_dpSpecificCriteria,
      { "dpSpecificCriteria", "camel.dpSpecificCriteria",
        FT_UINT32, BASE_DEC, VALS(camel_DpSpecificCriteria_vals), 0,
        "camel.DpSpecificCriteria", HFILL }},
    { &hf_camel_automaticRearm,
      { "automaticRearm", "camel.automaticRearm",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.NULL", HFILL }},
    { &hf_camel_cause,
      { "cause", "camel.cause",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.Cause", HFILL }},
    { &hf_camel_bearerCap,
      { "bearerCap", "camel.bearerCap",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.BearerCap", HFILL }},
    { &hf_camel_numberOfBursts,
      { "numberOfBursts", "camel.numberOfBursts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_1_3", HFILL }},
    { &hf_camel_burstInterval,
      { "burstInterval", "camel.burstInterval",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_1_1200", HFILL }},
    { &hf_camel_numberOfTonesInBurst,
      { "numberOfTonesInBurst", "camel.numberOfTonesInBurst",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_1_3", HFILL }},
    { &hf_camel_toneDuration,
      { "toneDuration", "camel.toneDuration",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_1_20", HFILL }},
    { &hf_camel_toneInterval,
      { "toneInterval", "camel.toneInterval",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_1_20", HFILL }},
    { &hf_camel_warningPeriod,
      { "warningPeriod", "camel.warningPeriod",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_1_1200", HFILL }},
    { &hf_camel_bursts,
      { "bursts", "camel.bursts",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.Burst", HFILL }},
    { &hf_camel_e1,
      { "e1", "camel.e1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_0_8191", HFILL }},
    { &hf_camel_e2,
      { "e2", "camel.e2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_0_8191", HFILL }},
    { &hf_camel_e3,
      { "e3", "camel.e3",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_0_8191", HFILL }},
    { &hf_camel_e4,
      { "e4", "camel.e4",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_0_8191", HFILL }},
    { &hf_camel_e5,
      { "e5", "camel.e5",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_0_8191", HFILL }},
    { &hf_camel_e6,
      { "e6", "camel.e6",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_0_8191", HFILL }},
    { &hf_camel_e7,
      { "e7", "camel.e7",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_0_8191", HFILL }},
    { &hf_camel_callSegmentID,
      { "callSegmentID", "camel.callSegmentID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.CallSegmentID", HFILL }},
    { &hf_camel_callInvokeID,
      { "callInvokeID", "camel.callInvokeID",
        FT_INT32, BASE_DEC, NULL, 0,
        "camel.InvokeID", HFILL }},
    { &hf_camel_timeDurationCharging,
      { "timeDurationCharging", "camel.timeDurationCharging",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_timeDurationCharging", HFILL }},
    { &hf_camel_audibleIndicator,
      { "audibleIndicator", "camel.audibleIndicator",
        FT_UINT32, BASE_DEC, VALS(camel_AudibleIndicator_vals), 0,
        "camel.AudibleIndicator", HFILL }},
    { &hf_camel_timeDurationChargingResult,
      { "timeDurationChargingResult", "camel.timeDurationChargingResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.TimeDurationChargingResult", HFILL }},
    { &hf_camel_void,
      { "void", "camel.void",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.NULL", HFILL }},
    { &hf_camel_partyToCharge,
      { "partyToCharge", "camel.partyToCharge",
        FT_UINT32, BASE_DEC, VALS(camel_ReceivingSideID_vals), 0,
        "camel.ReceivingSideID", HFILL }},
    { &hf_camel_timeInformation,
      { "timeInformation", "camel.timeInformation",
        FT_UINT32, BASE_DEC, VALS(camel_TimeInformation_vals), 0,
        "camel.TimeInformation", HFILL }},
    { &hf_camel_legActive,
      { "legActive", "camel.legActive",
        FT_BOOLEAN, 8, NULL, 0,
        "camel.BOOLEAN", HFILL }},
    { &hf_camel_callLegReleasedAtTcpExpiry,
      { "callLegReleasedAtTcpExpiry", "camel.callLegReleasedAtTcpExpiry",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.NULL", HFILL }},
    { &hf_camel_aChChargingAddress,
      { "aChChargingAddress", "camel.aChChargingAddress",
        FT_UINT32, BASE_DEC, VALS(camel_AChChargingAddress_vals), 0,
        "camel.AChChargingAddress", HFILL }},
    { &hf_camel_fCIBCCCAMELsequence1,
      { "fCIBCCCAMELsequence1", "camel.fCIBCCCAMELsequence1",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_fCIBCCCAMELsequence1", HFILL }},
    { &hf_camel_freeFormatData,
      { "freeFormatData", "camel.freeFormatData",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.FreeFormatData", HFILL }},
    { &hf_camel_partyToCharge4,
      { "partyToCharge4", "camel.partyToCharge4",
        FT_UINT32, BASE_DEC, VALS(camel_SendingSideID_vals), 0,
        "camel.SendingSideID", HFILL }},
    { &hf_camel_appendFreeFormatData,
      { "appendFreeFormatData", "camel.appendFreeFormatData",
        FT_UINT32, BASE_DEC, VALS(camel_AppendFreeFormatData_vals), 0,
        "camel.AppendFreeFormatData", HFILL }},
    { &hf_camel_fCIBCCCAMELsequence2,
      { "fCIBCCCAMELsequence2", "camel.fCIBCCCAMELsequence2",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_fCIBCCCAMELsequence2", HFILL }},
    { &hf_camel_pDPID,
      { "pDPID", "camel.pDPID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.PDPId", HFILL }},
    { &hf_camel_fCIBCCCAMELsequence3,
      { "fCIBCCCAMELsequence3", "camel.fCIBCCCAMELsequence3",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_fCIBCCCAMELsequence3", HFILL }},
    { &hf_camel_aOCBeforeAnswer,
      { "aOCBeforeAnswer", "camel.aOCBeforeAnswer",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.AOCBeforeAnswer", HFILL }},
    { &hf_camel_aOCAfterAnswer,
      { "aOCAfterAnswer", "camel.aOCAfterAnswer",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.AOCSubsequent", HFILL }},
    { &hf_camel_aOC_extension,
      { "aOC-extension", "camel.aOC_extension",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.CAMEL_SCIBillingChargingCharacteristicsAlt", HFILL }},
    { &hf_camel_aOCGPRS,
      { "aOCGPRS", "camel.aOCGPRS",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.AOCGprs", HFILL }},
    { &hf_camel_ChangeOfPositionControlInfo_item,
      { "Item", "camel.ChangeOfPositionControlInfo_item",
        FT_UINT32, BASE_DEC, VALS(camel_ChangeOfLocation_vals), 0,
        "camel.ChangeOfLocation", HFILL }},
    { &hf_camel_cellGlobalId,
      { "cellGlobalId", "camel.cellGlobalId",
        FT_BYTES, BASE_HEX, NULL, 0,
        "gsm_map.CellGlobalIdOrServiceAreaIdFixedLength", HFILL }},
    { &hf_camel_serviceAreaId,
      { "serviceAreaId", "camel.serviceAreaId",
        FT_BYTES, BASE_HEX, NULL, 0,
        "gsm_map.CellGlobalIdOrServiceAreaIdFixedLength", HFILL }},
    { &hf_camel_locationAreaId,
      { "locationAreaId", "camel.locationAreaId",
        FT_BYTES, BASE_HEX, NULL, 0,
        "gsm_map.LAIFixedLength", HFILL }},
    { &hf_camel_inter_SystemHandOver,
      { "inter-SystemHandOver", "camel.inter_SystemHandOver",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.NULL", HFILL }},
    { &hf_camel_inter_PLMNHandOver,
      { "inter-PLMNHandOver", "camel.inter_PLMNHandOver",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.NULL", HFILL }},
    { &hf_camel_inter_MSCHandOver,
      { "inter-MSCHandOver", "camel.inter_MSCHandOver",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.NULL", HFILL }},
    { &hf_camel_changeOfLocationAlt,
      { "changeOfLocationAlt", "camel.changeOfLocationAlt",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.ChangeOfLocationAlt", HFILL }},
    { &hf_camel_maxTransferredVolume,
      { "maxTransferredVolume", "camel.maxTransferredVolume",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_1_4294967295", HFILL }},
    { &hf_camel_maxElapsedTime,
      { "maxElapsedTime", "camel.maxElapsedTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_1_86400", HFILL }},
    { &hf_camel_transferredVolume,
      { "transferredVolume", "camel.transferredVolume",
        FT_UINT32, BASE_DEC, VALS(camel_TransferredVolume_vals), 0,
        "camel.TransferredVolume", HFILL }},
    { &hf_camel_elapsedTime,
      { "elapsedTime", "camel.elapsedTime",
        FT_UINT32, BASE_DEC, VALS(camel_ElapsedTime_vals), 0,
        "camel.ElapsedTime", HFILL }},
    { &hf_camel_transferredVolumeRollOver,
      { "transferredVolumeRollOver", "camel.transferredVolumeRollOver",
        FT_UINT32, BASE_DEC, VALS(camel_TransferredVolumeRollOver_vals), 0,
        "camel.TransferredVolumeRollOver", HFILL }},
    { &hf_camel_elapsedTimeRollOver,
      { "elapsedTimeRollOver", "camel.elapsedTimeRollOver",
        FT_UINT32, BASE_DEC, VALS(camel_ElapsedTimeRollOver_vals), 0,
        "camel.ElapsedTimeRollOver", HFILL }},
    { &hf_camel_minimumNbOfDigits,
      { "minimumNbOfDigits", "camel.minimumNbOfDigits",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_1_30", HFILL }},
    { &hf_camel_maximumNbOfDigits,
      { "maximumNbOfDigits", "camel.maximumNbOfDigits",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_1_30", HFILL }},
    { &hf_camel_endOfReplyDigit,
      { "endOfReplyDigit", "camel.endOfReplyDigit",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.OCTET_STRING_SIZE_1_2", HFILL }},
    { &hf_camel_cancelDigit,
      { "cancelDigit", "camel.cancelDigit",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.OCTET_STRING_SIZE_1_2", HFILL }},
    { &hf_camel_startDigit,
      { "startDigit", "camel.startDigit",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.OCTET_STRING_SIZE_1_2", HFILL }},
    { &hf_camel_firstDigitTimeOut,
      { "firstDigitTimeOut", "camel.firstDigitTimeOut",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_1_127", HFILL }},
    { &hf_camel_interDigitTimeOut,
      { "interDigitTimeOut", "camel.interDigitTimeOut",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_1_127", HFILL }},
    { &hf_camel_errorTreatment,
      { "errorTreatment", "camel.errorTreatment",
        FT_UINT32, BASE_DEC, VALS(camel_ErrorTreatment_vals), 0,
        "camel.ErrorTreatment", HFILL }},
    { &hf_camel_interruptableAnnInd,
      { "interruptableAnnInd", "camel.interruptableAnnInd",
        FT_BOOLEAN, 8, NULL, 0,
        "camel.BOOLEAN", HFILL }},
    { &hf_camel_voiceInformation,
      { "voiceInformation", "camel.voiceInformation",
        FT_BOOLEAN, 8, NULL, 0,
        "camel.BOOLEAN", HFILL }},
    { &hf_camel_voiceBack,
      { "voiceBack", "camel.voiceBack",
        FT_BOOLEAN, 8, NULL, 0,
        "camel.BOOLEAN", HFILL }},
    { &hf_camel_collectedDigits,
      { "collectedDigits", "camel.collectedDigits",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.CollectedDigits", HFILL }},
    { &hf_camel_basicGapCriteria,
      { "basicGapCriteria", "camel.basicGapCriteria",
        FT_UINT32, BASE_DEC, VALS(camel_BasicGapCriteria_vals), 0,
        "camel.BasicGapCriteria", HFILL }},
    { &hf_camel_scfID,
      { "scfID", "camel.scfID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.ScfID", HFILL }},
    { &hf_camel_DestinationRoutingAddress_item,
      { "Item", "camel.DestinationRoutingAddress_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.CalledPartyNumber", HFILL }},
    { &hf_camel_applicationTimer,
      { "applicationTimer", "camel.applicationTimer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.ApplicationTimer", HFILL }},
    { &hf_camel_midCallControlInfo,
      { "midCallControlInfo", "camel.midCallControlInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.MidCallControlInfo", HFILL }},
    { &hf_camel_dpSpecificCriteriaAlt,
      { "dpSpecificCriteriaAlt", "camel.dpSpecificCriteriaAlt",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.DpSpecificCriteriaAlt", HFILL }},
    { &hf_camel_changeOfPositionControlInfo,
      { "changeOfPositionControlInfo", "camel.changeOfPositionControlInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.ChangeOfPositionControlInfo", HFILL }},
    { &hf_camel_numberOfDigits,
      { "numberOfDigits", "camel.numberOfDigits",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.NumberOfDigits", HFILL }},
    { &hf_camel_interDigitTimeout,
      { "interDigitTimeout", "camel.interDigitTimeout",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_1_127", HFILL }},
    { &hf_camel_oServiceChangeSpecificInfo,
      { "oServiceChangeSpecificInfo", "camel.oServiceChangeSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_oServiceChangeSpecificInfo", HFILL }},
    { &hf_camel_ext_basicServiceCode,
      { "ext-basicServiceCode", "camel.ext_basicServiceCode",
        FT_UINT32, BASE_DEC, VALS(gsm_map_Ext_BasicServiceCode_vals), 0,
        "gsm_map.Ext_BasicServiceCode", HFILL }},
    { &hf_camel_initiatorOfServiceChange,
      { "initiatorOfServiceChange", "camel.initiatorOfServiceChange",
        FT_UINT32, BASE_DEC, VALS(camel_InitiatorOfServiceChange_vals), 0,
        "camel.InitiatorOfServiceChange", HFILL }},
    { &hf_camel_natureOfServiceChange,
      { "natureOfServiceChange", "camel.natureOfServiceChange",
        FT_UINT32, BASE_DEC, VALS(camel_NatureOfServiceChange_vals), 0,
        "camel.NatureOfServiceChange", HFILL }},
    { &hf_camel_tServiceChangeSpecificInfo,
      { "tServiceChangeSpecificInfo", "camel.tServiceChangeSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_tServiceChangeSpecificInfo", HFILL }},
    { &hf_camel_timeGPRSIfNoTariffSwitch,
      { "timeGPRSIfNoTariffSwitch", "camel.timeGPRSIfNoTariffSwitch",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_0_86400", HFILL }},
    { &hf_camel_timeGPRSIfTariffSwitch,
      { "timeGPRSIfTariffSwitch", "camel.timeGPRSIfTariffSwitch",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_timeGPRSIfTariffSwitch", HFILL }},
    { &hf_camel_timeGPRSSinceLastTariffSwitch,
      { "timeGPRSSinceLastTariffSwitch", "camel.timeGPRSSinceLastTariffSwitch",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_0_86400", HFILL }},
    { &hf_camel_timeGPRSTariffSwitchInterval,
      { "timeGPRSTariffSwitchInterval", "camel.timeGPRSTariffSwitchInterval",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_0_86400", HFILL }},
    { &hf_camel_rOTimeGPRSIfNoTariffSwitch,
      { "rOTimeGPRSIfNoTariffSwitch", "camel.rOTimeGPRSIfNoTariffSwitch",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_0_255", HFILL }},
    { &hf_camel_rOTimeGPRSIfTariffSwitch,
      { "rOTimeGPRSIfTariffSwitch", "camel.rOTimeGPRSIfTariffSwitch",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_rOTimeGPRSIfTariffSwitch", HFILL }},
    { &hf_camel_rOTimeGPRSSinceLastTariffSwitch,
      { "rOTimeGPRSSinceLastTariffSwitch", "camel.rOTimeGPRSSinceLastTariffSwitch",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_0_255", HFILL }},
    { &hf_camel_rOTimeGPRSTariffSwitchInterval,
      { "rOTimeGPRSTariffSwitchInterval", "camel.rOTimeGPRSTariffSwitchInterval",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_0_255", HFILL }},
    { &hf_camel_routeSelectFailureSpecificInfo,
      { "routeSelectFailureSpecificInfo", "camel.routeSelectFailureSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_routeSelectFailureSpecificInfo", HFILL }},
    { &hf_camel_failureCause,
      { "failureCause", "camel.failureCause",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.Cause", HFILL }},
    { &hf_camel_oCalledPartyBusySpecificInfo,
      { "oCalledPartyBusySpecificInfo", "camel.oCalledPartyBusySpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_oCalledPartyBusySpecificInfo", HFILL }},
    { &hf_camel_busyCause,
      { "busyCause", "camel.busyCause",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.Cause", HFILL }},
    { &hf_camel_oNoAnswerSpecificInfo,
      { "oNoAnswerSpecificInfo", "camel.oNoAnswerSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_oNoAnswerSpecificInfo", HFILL }},
    { &hf_camel_oAnswerSpecificInfo,
      { "oAnswerSpecificInfo", "camel.oAnswerSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_oAnswerSpecificInfo", HFILL }},
    { &hf_camel_destinationAddress,
      { "destinationAddress", "camel.destinationAddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.CalledPartyNumber", HFILL }},
    { &hf_camel_or_Call,
      { "or-Call", "camel.or_Call",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.NULL", HFILL }},
    { &hf_camel_forwardedCall,
      { "forwardedCall", "camel.forwardedCall",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.NULL", HFILL }},
    { &hf_camel_chargeIndicator,
      { "chargeIndicator", "camel.chargeIndicator",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.ChargeIndicator", HFILL }},
    { &hf_camel_ext_basicServiceCode2,
      { "ext-basicServiceCode2", "camel.ext_basicServiceCode2",
        FT_UINT32, BASE_DEC, VALS(gsm_map_Ext_BasicServiceCode_vals), 0,
        "gsm_map.Ext_BasicServiceCode", HFILL }},
    { &hf_camel_oMidCallSpecificInfo,
      { "oMidCallSpecificInfo", "camel.oMidCallSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_oMidCallSpecificInfo", HFILL }},
    { &hf_camel_omidCallEvents,
      { "omidCallEvents", "camel.omidCallEvents",
        FT_UINT32, BASE_DEC, VALS(camel_T_omidCallEvents_vals), 0,
        "camel.T_omidCallEvents", HFILL }},
    { &hf_camel_dTMFDigitsCompleted,
      { "dTMFDigitsCompleted", "camel.dTMFDigitsCompleted",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.Digits", HFILL }},
    { &hf_camel_dTMFDigitsTimeOut,
      { "dTMFDigitsTimeOut", "camel.dTMFDigitsTimeOut",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.Digits", HFILL }},
    { &hf_camel_oDisconnectSpecificInfo,
      { "oDisconnectSpecificInfo", "camel.oDisconnectSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_oDisconnectSpecificInfo", HFILL }},
    { &hf_camel_releaseCause,
      { "releaseCause", "camel.releaseCause",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.Cause", HFILL }},
    { &hf_camel_tBusySpecificInfo,
      { "tBusySpecificInfo", "camel.tBusySpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_tBusySpecificInfo", HFILL }},
    { &hf_camel_callForwarded,
      { "callForwarded", "camel.callForwarded",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.NULL", HFILL }},
    { &hf_camel_routeNotPermitted,
      { "routeNotPermitted", "camel.routeNotPermitted",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.NULL", HFILL }},
    { &hf_camel_forwardingDestinationNumber,
      { "forwardingDestinationNumber", "camel.forwardingDestinationNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.CalledPartyNumber", HFILL }},
    { &hf_camel_tNoAnswerSpecificInfo,
      { "tNoAnswerSpecificInfo", "camel.tNoAnswerSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_tNoAnswerSpecificInfo", HFILL }},
    { &hf_camel_tAnswerSpecificInfo,
      { "tAnswerSpecificInfo", "camel.tAnswerSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_tAnswerSpecificInfo", HFILL }},
    { &hf_camel_tMidCallSpecificInfo,
      { "tMidCallSpecificInfo", "camel.tMidCallSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_tMidCallSpecificInfo", HFILL }},
    { &hf_camel_tmidCallEvents,
      { "tmidCallEvents", "camel.tmidCallEvents",
        FT_UINT32, BASE_DEC, VALS(camel_T_tmidCallEvents_vals), 0,
        "camel.T_tmidCallEvents", HFILL }},
    { &hf_camel_tDisconnectSpecificInfo,
      { "tDisconnectSpecificInfo", "camel.tDisconnectSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_tDisconnectSpecificInfo", HFILL }},
    { &hf_camel_oTermSeizedSpecificInfo,
      { "oTermSeizedSpecificInfo", "camel.oTermSeizedSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_oTermSeizedSpecificInfo", HFILL }},
    { &hf_camel_locationInformation,
      { "locationInformation", "camel.locationInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "gsm_map_ms.LocationInformation", HFILL }},
    { &hf_camel_callAcceptedSpecificInfo,
      { "callAcceptedSpecificInfo", "camel.callAcceptedSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_callAcceptedSpecificInfo", HFILL }},
    { &hf_camel_oAbandonSpecificInfo,
      { "oAbandonSpecificInfo", "camel.oAbandonSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_oAbandonSpecificInfo", HFILL }},
    { &hf_camel_oChangeOfPositionSpecificInfo,
      { "oChangeOfPositionSpecificInfo", "camel.oChangeOfPositionSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_oChangeOfPositionSpecificInfo", HFILL }},
    { &hf_camel_metDPCriteriaList,
      { "metDPCriteriaList", "camel.metDPCriteriaList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.MetDPCriteriaList", HFILL }},
    { &hf_camel_tChangeOfPositionSpecificInfo,
      { "tChangeOfPositionSpecificInfo", "camel.tChangeOfPositionSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_tChangeOfPositionSpecificInfo", HFILL }},
    { &hf_camel_dpSpecificInfoAlt,
      { "dpSpecificInfoAlt", "camel.dpSpecificInfoAlt",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.DpSpecificInfoAlt", HFILL }},
    { &hf_camel_o_smsFailureSpecificInfo,
      { "o-smsFailureSpecificInfo", "camel.o_smsFailureSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_o_smsFailureSpecificInfo", HFILL }},
    { &hf_camel_smsfailureCause,
      { "smsfailureCause", "camel.smsfailureCause",
        FT_UINT32, BASE_DEC, VALS(camel_MO_SMSCause_vals), 0,
        "camel.MO_SMSCause", HFILL }},
    { &hf_camel_o_smsSubmittedSpecificInfo,
      { "o-smsSubmittedSpecificInfo", "camel.o_smsSubmittedSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_o_smsSubmittedSpecificInfo", HFILL }},
    { &hf_camel_foo,
      { "foo", "camel.foo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_0", HFILL }},
    { &hf_camel_t_smsFailureSpecificInfo,
      { "t-smsFailureSpecificInfo", "camel.t_smsFailureSpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_t_smsFailureSpecificInfo", HFILL }},
    { &hf_camel_failureMTSMSCause,
      { "failureMTSMSCause", "camel.failureMTSMSCause",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.MT_SMSCause", HFILL }},
    { &hf_camel_t_smsDeliverySpecificInfo,
      { "t-smsDeliverySpecificInfo", "camel.t_smsDeliverySpecificInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_t_smsDeliverySpecificInfo", HFILL }},
    { &hf_camel_callDiversionTreatmentIndicator,
      { "callDiversionTreatmentIndicator", "camel.callDiversionTreatmentIndicator",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.OCTET_STRING_SIZE_1", HFILL }},
    { &hf_camel_callingPartyRestrictionIndicator,
      { "callingPartyRestrictionIndicator", "camel.callingPartyRestrictionIndicator",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.OCTET_STRING_SIZE_1", HFILL }},
    { &hf_camel_compoundGapCriteria,
      { "compoundGapCriteria", "camel.compoundGapCriteria",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.CompoundCriteria", HFILL }},
    { &hf_camel_duration1,
      { "duration1", "camel.duration1",
        FT_INT32, BASE_DEC, NULL, 0,
        "camel.Duration", HFILL }},
    { &hf_camel_gapInterval,
      { "gapInterval", "camel.gapInterval",
        FT_INT32, BASE_DEC, NULL, 0,
        "camel.Interval", HFILL }},
    { &hf_camel_informationToSend,
      { "informationToSend", "camel.informationToSend",
        FT_UINT32, BASE_DEC, VALS(camel_InformationToSend_vals), 0,
        "camel.InformationToSend", HFILL }},
    { &hf_camel_GenericNumbers_item,
      { "Item", "camel.GenericNumbers_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.GenericNumber", HFILL }},
    { &hf_camel_short_QoS_format,
      { "short-QoS-format", "camel.short_QoS_format",
        FT_BYTES, BASE_HEX, NULL, 0,
        "gsm_map_ms.QoS_Subscribed", HFILL }},
    { &hf_camel_long_QoS_format,
      { "long-QoS-format", "camel.long_QoS_format",
        FT_BYTES, BASE_HEX, NULL, 0,
        "gsm_map_ms.Ext_QoS_Subscribed", HFILL }},
    { &hf_camel_supplement_to_long_QoS_format,
      { "supplement-to-long-QoS-format", "camel.supplement_to_long_QoS_format",
        FT_BYTES, BASE_HEX, NULL, 0,
        "gsm_map_ms.Ext2_QoS_Subscribed", HFILL }},
    { &hf_camel_gPRSEventType,
      { "gPRSEventType", "camel.gPRSEventType",
        FT_UINT32, BASE_DEC, VALS(camel_GPRSEventType_vals), 0,
        "camel.GPRSEventType", HFILL }},
    { &hf_camel_attachChangeOfPositionSpecificInformation,
      { "attachChangeOfPositionSpecificInformation", "camel.attachChangeOfPositionSpecificInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_attachChangeOfPositionSpecificInformation", HFILL }},
    { &hf_camel_locationInformationGPRS,
      { "locationInformationGPRS", "camel.locationInformationGPRS",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.LocationInformationGPRS", HFILL }},
    { &hf_camel_pdp_ContextchangeOfPositionSpecificInformation,
      { "pdp-ContextchangeOfPositionSpecificInformation", "camel.pdp_ContextchangeOfPositionSpecificInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_pdp_ContextchangeOfPositionSpecificInformation", HFILL }},
    { &hf_camel_accessPointName,
      { "accessPointName", "camel.accessPointName",
        FT_STRING, NONE, NULL, 0,
        "camel.AccessPointName", HFILL }},
    { &hf_camel_chargingID,
      { "chargingID", "camel.chargingID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "gsm_map_ms.GPRSChargingID", HFILL }},
    { &hf_camel_pDPType,
      { "pDPType", "camel.pDPType",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.PDPType", HFILL }},
    { &hf_camel_qualityOfService,
      { "qualityOfService", "camel.qualityOfService",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.QualityOfService", HFILL }},
    { &hf_camel_timeAndTimeZone,
      { "timeAndTimeZone", "camel.timeAndTimeZone",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.TimeAndTimezone", HFILL }},
    { &hf_camel_gGSNAddress,
      { "gGSNAddress", "camel.gGSNAddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "gsm_map_ms.GSN_Address", HFILL }},
    { &hf_camel_detachSpecificInformation,
      { "detachSpecificInformation", "camel.detachSpecificInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_detachSpecificInformation", HFILL }},
    { &hf_camel_inititatingEntity,
      { "inititatingEntity", "camel.inititatingEntity",
        FT_UINT32, BASE_DEC, VALS(camel_InitiatingEntity_vals), 0,
        "camel.InitiatingEntity", HFILL }},
    { &hf_camel_routeingAreaUpdate,
      { "routeingAreaUpdate", "camel.routeingAreaUpdate",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.NULL", HFILL }},
    { &hf_camel_disconnectSpecificInformation,
      { "disconnectSpecificInformation", "camel.disconnectSpecificInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_disconnectSpecificInformation", HFILL }},
    { &hf_camel_pDPContextEstablishmentSpecificInformation,
      { "pDPContextEstablishmentSpecificInformation", "camel.pDPContextEstablishmentSpecificInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_pDPContextEstablishmentSpecificInformation", HFILL }},
    { &hf_camel_pDPInitiationType,
      { "pDPInitiationType", "camel.pDPInitiationType",
        FT_UINT32, BASE_DEC, VALS(camel_PDPInitiationType_vals), 0,
        "camel.PDPInitiationType", HFILL }},
    { &hf_camel_secondaryPDPContext,
      { "secondaryPDPContext", "camel.secondaryPDPContext",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.NULL", HFILL }},
    { &hf_camel_pDPContextEstablishmentAcknowledgementSpecificInformation,
      { "pDPContextEstablishmentAcknowledgementSpecificInformation", "camel.pDPContextEstablishmentAcknowledgementSpecificInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_pDPContextEstablishmentAcknowledgementSpecificInformation", HFILL }},
    { &hf_camel_mSNetworkCapability,
      { "mSNetworkCapability", "camel.mSNetworkCapability",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.MSNetworkCapability", HFILL }},
    { &hf_camel_mSRadioAccessCapability,
      { "mSRadioAccessCapability", "camel.mSRadioAccessCapability",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.MSRadioAccessCapability", HFILL }},
    { &hf_camel_messageID,
      { "messageID", "camel.messageID",
        FT_UINT32, BASE_DEC, VALS(camel_MessageID_vals), 0,
        "camel.MessageID", HFILL }},
    { &hf_camel_numberOfRepetitions,
      { "numberOfRepetitions", "camel.numberOfRepetitions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_1_127", HFILL }},
    { &hf_camel_duration2,
      { "duration2", "camel.duration2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_0_32767", HFILL }},
    { &hf_camel_interval,
      { "interval", "camel.interval",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_0_32767", HFILL }},
    { &hf_camel_inbandInfo,
      { "inbandInfo", "camel.inbandInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.InbandInfo", HFILL }},
    { &hf_camel_tone,
      { "tone", "camel.tone",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.Tone", HFILL }},
    { &hf_camel_cellGlobalIdOrServiceAreaIdOrLAI,
      { "cellGlobalIdOrServiceAreaIdOrLAI", "camel.cellGlobalIdOrServiceAreaIdOrLAI",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.CellGlobalIdOrServiceAreaIdOrLAI", HFILL }},
    { &hf_camel_routeingAreaIdentity,
      { "routeingAreaIdentity", "camel.routeingAreaIdentity",
        FT_BYTES, BASE_HEX, NULL, 0,
        "gsm_map_ms.RAIdentity", HFILL }},
    { &hf_camel_geographicalInformation,
      { "geographicalInformation", "camel.geographicalInformation",
        FT_BYTES, BASE_HEX, NULL, 0,
        "gsm_map_ms.GeographicalInformation", HFILL }},
    { &hf_camel_sgsn_Number,
      { "sgsn-Number", "camel.sgsn_Number",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.ISDN_AddressString", HFILL }},
    { &hf_camel_selectedLSAIdentity,
      { "selectedLSAIdentity", "camel.selectedLSAIdentity",
        FT_BYTES, BASE_HEX, NULL, 0,
        "gsm_map_ms.LSAIdentity", HFILL }},
    { &hf_camel_extensionContainer,
      { "extensionContainer", "camel.extensionContainer",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.ExtensionContainer", HFILL }},
    { &hf_camel_saiPresent,
      { "saiPresent", "camel.saiPresent",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.NULL", HFILL }},
    { &hf_camel_elementaryMessageID,
      { "elementaryMessageID", "camel.elementaryMessageID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.Integer4", HFILL }},
    { &hf_camel_text,
      { "text", "camel.text",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_text", HFILL }},
    { &hf_camel_messageContent,
      { "messageContent", "camel.messageContent",
        FT_STRING, BASE_NONE, NULL, 0,
        "camel.IA5String_SIZE_cAPSpecificBoundSetminMessageContentLength_cAPSpecificBoundSetmaxMessageContentLength", HFILL }},
    { &hf_camel_attributes,
      { "attributes", "camel.attributes",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.OCTET_STRING_SIZE_cAPSpecificBoundSetminAttributesLength_cAPSpecificBoundSetmaxAttributesLength", HFILL }},
    { &hf_camel_elementaryMessageIDs,
      { "elementaryMessageIDs", "camel.elementaryMessageIDs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.SEQUENCE_SIZE_1_cAPSpecificBoundSetnumOfMessageIDs_OF_Integer4", HFILL }},
    { &hf_camel_elementaryMessageIDs_item,
      { "Item", "camel.elementaryMessageIDs_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.Integer4", HFILL }},
    { &hf_camel_variableMessage,
      { "variableMessage", "camel.variableMessage",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_variableMessage", HFILL }},
    { &hf_camel_variableParts,
      { "variableParts", "camel.variableParts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.VariablePartsArray", HFILL }},
    { &hf_camel_MetDPCriteriaList_item,
      { "Item", "camel.MetDPCriteriaList_item",
        FT_UINT32, BASE_DEC, VALS(camel_MetDPCriterion_vals), 0,
        "camel.MetDPCriterion", HFILL }},
    { &hf_camel_enteringCellGlobalId,
      { "enteringCellGlobalId", "camel.enteringCellGlobalId",
        FT_BYTES, BASE_HEX, NULL, 0,
        "gsm_map.CellGlobalIdOrServiceAreaIdFixedLength", HFILL }},
    { &hf_camel_leavingCellGlobalId,
      { "leavingCellGlobalId", "camel.leavingCellGlobalId",
        FT_BYTES, BASE_HEX, NULL, 0,
        "gsm_map.CellGlobalIdOrServiceAreaIdFixedLength", HFILL }},
    { &hf_camel_enteringServiceAreaId,
      { "enteringServiceAreaId", "camel.enteringServiceAreaId",
        FT_BYTES, BASE_HEX, NULL, 0,
        "gsm_map.CellGlobalIdOrServiceAreaIdFixedLength", HFILL }},
    { &hf_camel_leavingServiceAreaId,
      { "leavingServiceAreaId", "camel.leavingServiceAreaId",
        FT_BYTES, BASE_HEX, NULL, 0,
        "gsm_map.CellGlobalIdOrServiceAreaIdFixedLength", HFILL }},
    { &hf_camel_enteringLocationAreaId,
      { "enteringLocationAreaId", "camel.enteringLocationAreaId",
        FT_BYTES, BASE_HEX, NULL, 0,
        "gsm_map.LAIFixedLength", HFILL }},
    { &hf_camel_leavingLocationAreaId,
      { "leavingLocationAreaId", "camel.leavingLocationAreaId",
        FT_BYTES, BASE_HEX, NULL, 0,
        "gsm_map.LAIFixedLength", HFILL }},
    { &hf_camel_inter_SystemHandOverToUMTS,
      { "inter-SystemHandOverToUMTS", "camel.inter_SystemHandOverToUMTS",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.NULL", HFILL }},
    { &hf_camel_inter_SystemHandOverToGSM,
      { "inter-SystemHandOverToGSM", "camel.inter_SystemHandOverToGSM",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.NULL", HFILL }},
    { &hf_camel_metDPCriterionAlt,
      { "metDPCriterionAlt", "camel.metDPCriterionAlt",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.MetDPCriterionAlt", HFILL }},
    { &hf_camel_minimumNumberOfDigits,
      { "minimumNumberOfDigits", "camel.minimumNumberOfDigits",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_1_30", HFILL }},
    { &hf_camel_maximumNumberOfDigits,
      { "maximumNumberOfDigits", "camel.maximumNumberOfDigits",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_1_30", HFILL }},
    { &hf_camel_requested_QoS,
      { "requested-QoS", "camel.requested_QoS",
        FT_UINT32, BASE_DEC, VALS(camel_GPRS_QoS_vals), 0,
        "camel.GPRS_QoS", HFILL }},
    { &hf_camel_subscribed_QoS,
      { "subscribed-QoS", "camel.subscribed_QoS",
        FT_UINT32, BASE_DEC, VALS(camel_GPRS_QoS_vals), 0,
        "camel.GPRS_QoS", HFILL }},
    { &hf_camel_negotiated_QoS,
      { "negotiated-QoS", "camel.negotiated_QoS",
        FT_UINT32, BASE_DEC, VALS(camel_GPRS_QoS_vals), 0,
        "camel.GPRS_QoS", HFILL }},
    { &hf_camel_requested_QoS_Extension,
      { "requested-QoS-Extension", "camel.requested_QoS_Extension",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.GPRS_QoS_Extension", HFILL }},
    { &hf_camel_subscribed_QoS_Extension,
      { "subscribed-QoS-Extension", "camel.subscribed_QoS_Extension",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.GPRS_QoS_Extension", HFILL }},
    { &hf_camel_negotiated_QoS_Extension,
      { "negotiated-QoS-Extension", "camel.negotiated_QoS_Extension",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.GPRS_QoS_Extension", HFILL }},
    { &hf_camel_receivingSideID,
      { "receivingSideID", "camel.receivingSideID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.LegType", HFILL }},
    { &hf_camel_RequestedInformationList_item,
      { "Item", "camel.RequestedInformationList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.RequestedInformation", HFILL }},
    { &hf_camel_RequestedInformationTypeList_item,
      { "Item", "camel.RequestedInformationTypeList_item",
        FT_UINT32, BASE_DEC, VALS(camel_RequestedInformationType_vals), 0,
        "camel.RequestedInformationType", HFILL }},
    { &hf_camel_requestedInformationType,
      { "requestedInformationType", "camel.requestedInformationType",
        FT_UINT32, BASE_DEC, VALS(camel_RequestedInformationType_vals), 0,
        "camel.RequestedInformationType", HFILL }},
    { &hf_camel_requestedInformationValue,
      { "requestedInformationValue", "camel.requestedInformationValue",
        FT_UINT32, BASE_DEC, VALS(camel_RequestedInformationValue_vals), 0,
        "camel.RequestedInformationValue", HFILL }},
    { &hf_camel_callAttemptElapsedTimeValue,
      { "callAttemptElapsedTimeValue", "camel.callAttemptElapsedTimeValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_0_255", HFILL }},
    { &hf_camel_callStopTimeValue,
      { "callStopTimeValue", "camel.callStopTimeValue",
        FT_STRING, NONE, NULL, 0,
        "camel.DateAndTime", HFILL }},
    { &hf_camel_callConnectedElapsedTimeValue,
      { "callConnectedElapsedTimeValue", "camel.callConnectedElapsedTimeValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.Integer4", HFILL }},
    { &hf_camel_releaseCauseValue,
      { "releaseCauseValue", "camel.releaseCauseValue",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.Cause", HFILL }},
    { &hf_camel_sendingSideID,
      { "sendingSideID", "camel.sendingSideID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.LegType", HFILL }},
    { &hf_camel_forwardServiceInteractionInd,
      { "forwardServiceInteractionInd", "camel.forwardServiceInteractionInd",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.ForwardServiceInteractionInd", HFILL }},
    { &hf_camel_backwardServiceInteractionInd,
      { "backwardServiceInteractionInd", "camel.backwardServiceInteractionInd",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.BackwardServiceInteractionInd", HFILL }},
    { &hf_camel_bothwayThroughConnectionInd,
      { "bothwayThroughConnectionInd", "camel.bothwayThroughConnectionInd",
        FT_UINT32, BASE_DEC, VALS(camel_BothwayThroughConnectionInd_vals), 0,
        "camel.BothwayThroughConnectionInd", HFILL }},
    { &hf_camel_connectedNumberTreatmentInd,
      { "connectedNumberTreatmentInd", "camel.connectedNumberTreatmentInd",
        FT_UINT32, BASE_DEC, VALS(camel_ConnectedNumberTreatmentInd_vals), 0,
        "camel.ConnectedNumberTreatmentInd", HFILL }},
    { &hf_camel_nonCUGCall,
      { "nonCUGCall", "camel.nonCUGCall",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.NULL", HFILL }},
    { &hf_camel_holdTreatmentIndicator,
      { "holdTreatmentIndicator", "camel.holdTreatmentIndicator",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.OCTET_STRING_SIZE_1", HFILL }},
    { &hf_camel_cwTreatmentIndicator,
      { "cwTreatmentIndicator", "camel.cwTreatmentIndicator",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.OCTET_STRING_SIZE_1", HFILL }},
    { &hf_camel_ectTreatmentIndicator,
      { "ectTreatmentIndicator", "camel.ectTreatmentIndicator",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.OCTET_STRING_SIZE_1", HFILL }},
    { &hf_camel_eventTypeSMS,
      { "eventTypeSMS", "camel.eventTypeSMS",
        FT_UINT32, BASE_DEC, VALS(camel_EventTypeSMS_vals), 0,
        "camel.EventTypeSMS", HFILL }},
    { &hf_camel_timeSinceTariffSwitch,
      { "timeSinceTariffSwitch", "camel.timeSinceTariffSwitch",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_0_864000", HFILL }},
    { &hf_camel_tttariffSwitchInterval,
      { "tttariffSwitchInterval", "camel.tttariffSwitchInterval",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_1_864000", HFILL }},
    { &hf_camel_timeIfNoTariffSwitch,
      { "timeIfNoTariffSwitch", "camel.timeIfNoTariffSwitch",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.TimeIfNoTariffSwitch", HFILL }},
    { &hf_camel_timeIfTariffSwitch,
      { "timeIfTariffSwitch", "camel.timeIfTariffSwitch",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.TimeIfTariffSwitch", HFILL }},
    { &hf_camel_toneID,
      { "toneID", "camel.toneID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.Integer4", HFILL }},
    { &hf_camel_duration3,
      { "duration3", "camel.duration3",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.Integer4", HFILL }},
    { &hf_camel_volumeIfNoTariffSwitch,
      { "volumeIfNoTariffSwitch", "camel.volumeIfNoTariffSwitch",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_0_4294967295", HFILL }},
    { &hf_camel_volumeIfTariffSwitch,
      { "volumeIfTariffSwitch", "camel.volumeIfTariffSwitch",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_volumeIfTariffSwitch", HFILL }},
    { &hf_camel_volumeSinceLastTariffSwitch,
      { "volumeSinceLastTariffSwitch", "camel.volumeSinceLastTariffSwitch",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_0_4294967295", HFILL }},
    { &hf_camel_volumeTariffSwitchInterval,
      { "volumeTariffSwitchInterval", "camel.volumeTariffSwitchInterval",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_0_4294967295", HFILL }},
    { &hf_camel_rOVolumeIfNoTariffSwitch,
      { "rOVolumeIfNoTariffSwitch", "camel.rOVolumeIfNoTariffSwitch",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_0_255", HFILL }},
    { &hf_camel_rOVolumeIfTariffSwitch,
      { "rOVolumeIfTariffSwitch", "camel.rOVolumeIfTariffSwitch",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.T_rOVolumeIfTariffSwitch", HFILL }},
    { &hf_camel_rOVolumeSinceLastTariffSwitch,
      { "rOVolumeSinceLastTariffSwitch", "camel.rOVolumeSinceLastTariffSwitch",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_0_255", HFILL }},
    { &hf_camel_rOVolumeTariffSwitchInterval,
      { "rOVolumeTariffSwitchInterval", "camel.rOVolumeTariffSwitchInterval",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.INTEGER_0_255", HFILL }},
    { &hf_camel_integer,
      { "integer", "camel.integer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.Integer4", HFILL }},
    { &hf_camel_number,
      { "number", "camel.number",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.Digits", HFILL }},
    { &hf_camel_time,
      { "time", "camel.time",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.OCTET_STRING_SIZE_2", HFILL }},
    { &hf_camel_date,
      { "date", "camel.date",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.OCTET_STRING_SIZE_4", HFILL }},
    { &hf_camel_price,
      { "price", "camel.price",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.OCTET_STRING_SIZE_4", HFILL }},
    { &hf_camel_allAnnouncementsComplete,
      { "allAnnouncementsComplete", "camel.allAnnouncementsComplete",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.NULL", HFILL }},
    { &hf_camel_firstAnnouncementStarted,
      { "firstAnnouncementStarted", "camel.firstAnnouncementStarted",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.NULL", HFILL }},
    { &hf_camel_pDPTypeOrganization,
      { "pDPTypeOrganization", "camel.pDPTypeOrganization",
        FT_UINT8, BASE_DEC, VALS(gsm_map_PDP_Type_Organisation_vals), 0x0f,
        "camel.PDPTypeOrganization", HFILL }},
    { &hf_camel_pDPTypeNumber,
      { "pDPTypeNumber", "camel.pDPTypeNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.PDPTypeNumber", HFILL }},
    { &hf_camel_pDPAddress,
      { "pDPAddress", "camel.pDPAddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.PDPAddress", HFILL }},
    { &hf_camel_local,
      { "local", "camel.local",
        FT_INT32, BASE_DEC, NULL, 0,
        "camel.INTEGER", HFILL }},
    { &hf_camel_global,
      { "global", "camel.global",
        FT_OID, BASE_NONE, NULL, 0,
        "camel.OBJECT_IDENTIFIER", HFILL }},
    { &hf_camel_messageType,
      { "messageType", "camel.messageType",
        FT_UINT32, BASE_DEC, VALS(camel_T_messageType_vals), 0,
        "camel.T_messageType", HFILL }},
    { &hf_camel_firstExtensionExtensionType,
      { "firstExtensionExtensionType", "camel.firstExtensionExtensionType",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.NULL", HFILL }},
    { &hf_camel_extId,
      { "extId", "camel.extId",
        FT_OID, BASE_NONE, NULL, 0,
        "camel.ExtensionSetextensionId", HFILL }},
    { &hf_camel_callresultOctet,
      { "callresultOctet", "camel.callresultOctet",
        FT_UINT32, BASE_DEC, VALS(camel_CAMEL_CallResult_vals), 0,
        "camel.CAMEL_CallResult", HFILL }},
    { &hf_camel_allRequests,
      { "allRequests", "camel.allRequests",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.NULL", HFILL }},
    { &hf_camel_callSegmentToCancel,
      { "callSegmentToCancel", "camel.callSegmentToCancel",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.CallSegmentToCancel", HFILL }},
    { &hf_camel_digitsResponse,
      { "digitsResponse", "camel.digitsResponse",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.Digits", HFILL }},
    { &hf_camel_pdpID,
      { "pdpID", "camel.pdpID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.PDPId", HFILL }},
    { &hf_camel_gPRSCause,
      { "gPRSCause", "camel.gPRSCause",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.GPRSCause", HFILL }},
    { &hf_camel_gprsCause,
      { "gprsCause", "camel.gprsCause",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.GPRSCause", HFILL }},
    { &hf_camel_gPRSEvent,
      { "gPRSEvent", "camel.gPRSEvent",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.GPRSEventArray", HFILL }},
    { &hf_camel_GPRSEventArray_item,
      { "Item", "camel.GPRSEventArray_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.GPRSEvent", HFILL }},
    { &hf_camel_sCIGPRSBillingChargingCharacteristics,
      { "sCIGPRSBillingChargingCharacteristics", "camel.sCIGPRSBillingChargingCharacteristics",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.SCIGPRSBillingChargingCharacteristics", HFILL }},
    { &hf_camel_assumedIdle,
      { "assumedIdle", "camel.assumedIdle",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.NULL", HFILL }},
    { &hf_camel_camelBusy,
      { "camelBusy", "camel.camelBusy",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.NULL", HFILL }},
    { &hf_camel_netDetNotReachable,
      { "netDetNotReachable", "camel.netDetNotReachable",
        FT_UINT32, BASE_DEC, VALS(camel_NotReachableReason_vals), 0,
        "camel.NotReachableReason", HFILL }},
    { &hf_camel_notProvidedFromVLR,
      { "notProvidedFromVLR", "camel.notProvidedFromVLR",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.NULL", HFILL }},
    { &hf_camel_PrivateExtensionList_item,
      { "Item", "camel.PrivateExtensionList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.PrivateExtension", HFILL }},
    { &hf_camel_VariablePartsArray_item,
      { "Item", "camel.VariablePartsArray_item",
        FT_UINT32, BASE_DEC, VALS(camel_VariablePart_vals), 0,
        "camel.VariablePart", HFILL }},
    { &hf_camel_gmscAddress,
      { "gmscAddress", "camel.gmscAddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.ISDN_AddressString", HFILL }},
    { &hf_camel_ms_Classmark2,
      { "ms-Classmark2", "camel.ms_Classmark2",
        FT_BYTES, BASE_HEX, NULL, 0,
        "gsm_map_ms.MS_Classmark2", HFILL }},
    { &hf_camel_iMEI,
      { "iMEI", "camel.iMEI",
        FT_BYTES, BASE_HEX, NULL, 0,
        "gsm_map.IMEI", HFILL }},
    { &hf_camel_supportedCamelPhases,
      { "supportedCamelPhases", "camel.supportedCamelPhases",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.SupportedCamelPhases", HFILL }},
    { &hf_camel_offeredCamel4Functionalities,
      { "offeredCamel4Functionalities", "camel.offeredCamel4Functionalities",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.OfferedCamel4Functionalities", HFILL }},
    { &hf_camel_bearerCapability2,
      { "bearerCapability2", "camel.bearerCapability2",
        FT_UINT32, BASE_DEC, VALS(camel_BearerCapability_vals), 0,
        "camel.BearerCapability", HFILL }},
    { &hf_camel_highLayerCompatibility2,
      { "highLayerCompatibility2", "camel.highLayerCompatibility2",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.HighLayerCompatibility", HFILL }},
    { &hf_camel_lowLayerCompatibility,
      { "lowLayerCompatibility", "camel.lowLayerCompatibility",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.LowLayerCompatibility", HFILL }},
    { &hf_camel_lowLayerCompatibility2,
      { "lowLayerCompatibility2", "camel.lowLayerCompatibility2",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.LowLayerCompatibility", HFILL }},
    { &hf_camel_enhancedDialledServicesAllowed,
      { "enhancedDialledServicesAllowed", "camel.enhancedDialledServicesAllowed",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.NULL", HFILL }},
    { &hf_camel_uu_Data,
      { "uu-Data", "camel.uu_Data",
        FT_NONE, BASE_NONE, NULL, 0,
        "gsm_map_ch.UU_Data", HFILL }},
    { &hf_camel_collectInformationAllowed,
      { "collectInformationAllowed", "camel.collectInformationAllowed",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.NULL", HFILL }},
    { &hf_camel_destinationRoutingAddress,
      { "destinationRoutingAddress", "camel.destinationRoutingAddress",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.DestinationRoutingAddress", HFILL }},
    { &hf_camel_legToBeCreated,
      { "legToBeCreated", "camel.legToBeCreated",
        FT_UINT32, BASE_DEC, VALS(camel_LegID_vals), 0,
        "camel.LegID", HFILL }},
    { &hf_camel_newCallSegment,
      { "newCallSegment", "camel.newCallSegment",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.CallSegmentID", HFILL }},
    { &hf_camel_callingPartyNumber,
      { "callingPartyNumber", "camel.callingPartyNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.CallingPartyNumber", HFILL }},
    { &hf_camel_callReferenceNumber,
      { "callReferenceNumber", "camel.callReferenceNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.CallReferenceNumber", HFILL }},
    { &hf_camel_gsmSCFAddress,
      { "gsmSCFAddress", "camel.gsmSCFAddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.ISDN_AddressString", HFILL }},
    { &hf_camel_suppress_T_CSI,
      { "suppress-T-CSI", "camel.suppress_T_CSI",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.NULL", HFILL }},
    { &hf_camel_legIDToMove,
      { "legIDToMove", "camel.legIDToMove",
        FT_UINT32, BASE_DEC, VALS(camel_LegID_vals), 0,
        "camel.LegID", HFILL }},
    { &hf_camel_legOrCallSegment,
      { "legOrCallSegment", "camel.legOrCallSegment",
        FT_UINT32, BASE_DEC, VALS(camel_LegOrCallSegment_vals), 0,
        "camel.LegOrCallSegment", HFILL }},
    { &hf_camel_miscGPRSInfo,
      { "miscGPRSInfo", "camel.miscGPRSInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.MiscCallInfo", HFILL }},
    { &hf_camel_gPRSEventSpecificInformation,
      { "gPRSEventSpecificInformation", "camel.gPRSEventSpecificInformation",
        FT_UINT32, BASE_DEC, VALS(camel_GPRSEventSpecificInformation_vals), 0,
        "camel.GPRSEventSpecificInformation", HFILL }},
    { &hf_camel_type,
      { "type", "camel.type",
        FT_UINT32, BASE_DEC, VALS(camel_Code_vals), 0,
        "camel.SupportedExtensionsid", HFILL }},
    { &hf_camel_criticality,
      { "criticality", "camel.criticality",
        FT_UINT32, BASE_DEC, VALS(camel_CriticalityType_vals), 0,
        "camel.CriticalityType", HFILL }},
    { &hf_camel_value,
      { "value", "camel.value",
        FT_UINT32, BASE_DEC, VALS(camel_SupportedExtensionsExtensionType_vals), 0,
        "camel.SupportedExtensionsExtensionType", HFILL }},
    { &hf_camel_aChBillingChargingCharacteristics,
      { "aChBillingChargingCharacteristics", "camel.aChBillingChargingCharacteristics",
        FT_UINT32, BASE_DEC, VALS(camel_AChBillingChargingCharacteristics_vals), 0,
        "camel.AChBillingChargingCharacteristics", HFILL }},
    { &hf_camel_partyToCharge1,
      { "partyToCharge1", "camel.partyToCharge1",
        FT_UINT32, BASE_DEC, VALS(camel_SendingSideID_vals), 0,
        "camel.SendingSideID", HFILL }},
    { &hf_camel_ExtensionsArray_item,
      { "Item", "camel.ExtensionsArray_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.ExtensionField", HFILL }},
    { &hf_camel_correlationID,
      { "correlationID", "camel.correlationID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.CorrelationID", HFILL }},
    { &hf_camel_iPSSPCapabilities,
      { "iPSSPCapabilities", "camel.iPSSPCapabilities",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.IPSSPCapabilities", HFILL }},
    { &hf_camel_requestedInformationTypeList,
      { "requestedInformationTypeList", "camel.requestedInformationTypeList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.RequestedInformationTypeList", HFILL }},
    { &hf_camel_legID3,
      { "legID3", "camel.legID3",
        FT_UINT32, BASE_DEC, VALS(camel_SendingSideID_vals), 0,
        "camel.SendingSideID", HFILL }},
    { &hf_camel_alertingPattern,
      { "alertingPattern", "camel.alertingPattern",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.AlertingPattern", HFILL }},
    { &hf_camel_originalCalledPartyID,
      { "originalCalledPartyID", "camel.originalCalledPartyID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.OriginalCalledPartyID", HFILL }},
    { &hf_camel_carrier,
      { "carrier", "camel.carrier",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.Carrier", HFILL }},
    { &hf_camel_callingPartysCategory,
      { "callingPartysCategory", "camel.callingPartysCategory",
        FT_UINT16, BASE_DEC, VALS(isup_calling_partys_category_value), 0,
        "camel.CallingPartysCategory", HFILL }},
    { &hf_camel_redirectingPartyID,
      { "redirectingPartyID", "camel.redirectingPartyID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.RedirectingPartyID", HFILL }},
    { &hf_camel_redirectionInformation,
      { "redirectionInformation", "camel.redirectionInformation",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.RedirectionInformation", HFILL }},
    { &hf_camel_genericNumbers,
      { "genericNumbers", "camel.genericNumbers",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.GenericNumbers", HFILL }},
    { &hf_camel_serviceInteractionIndicatorsTwo,
      { "serviceInteractionIndicatorsTwo", "camel.serviceInteractionIndicatorsTwo",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.ServiceInteractionIndicatorsTwo", HFILL }},
    { &hf_camel_chargeNumber,
      { "chargeNumber", "camel.chargeNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.ChargeNumber", HFILL }},
    { &hf_camel_legToBeConnected,
      { "legToBeConnected", "camel.legToBeConnected",
        FT_UINT32, BASE_DEC, VALS(camel_LegID_vals), 0,
        "camel.LegID", HFILL }},
    { &hf_camel_cug_Interlock,
      { "cug-Interlock", "camel.cug_Interlock",
        FT_BYTES, BASE_HEX, NULL, 0,
        "gsm_map_ms.CUG_Interlock", HFILL }},
    { &hf_camel_cug_OutgoingAccess,
      { "cug-OutgoingAccess", "camel.cug_OutgoingAccess",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.NULL", HFILL }},
    { &hf_camel_suppressionOfAnnouncement,
      { "suppressionOfAnnouncement", "camel.suppressionOfAnnouncement",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.SuppressionOfAnnouncement", HFILL }},
    { &hf_camel_oCSIApplicable,
      { "oCSIApplicable", "camel.oCSIApplicable",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.OCSIApplicable", HFILL }},
    { &hf_camel_naOliInfo,
      { "naOliInfo", "camel.naOliInfo",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.NAOliInfo", HFILL }},
    { &hf_camel_bor_InterrogationRequested,
      { "bor-InterrogationRequested", "camel.bor_InterrogationRequested",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.NULL", HFILL }},
    { &hf_camel_suppress_N_CSI,
      { "suppress-N-CSI", "camel.suppress_N_CSI",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.NULL", HFILL }},
    { &hf_camel_resourceAddress,
      { "resourceAddress", "camel.resourceAddress",
        FT_UINT32, BASE_DEC, VALS(camel_T_resourceAddress_vals), 0,
        "camel.T_resourceAddress", HFILL }},
    { &hf_camel_ipRoutingAddress,
      { "ipRoutingAddress", "camel.ipRoutingAddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.IPRoutingAddress", HFILL }},
    { &hf_camel_none,
      { "none", "camel.none",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.NULL", HFILL }},
    { &hf_camel_suppress_O_CSI,
      { "suppress-O-CSI", "camel.suppress_O_CSI",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.NULL", HFILL }},
    { &hf_camel_continueWithArgumentArgExtension,
      { "continueWithArgumentArgExtension", "camel.continueWithArgumentArgExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.ContinueWithArgumentArgExtension", HFILL }},
    { &hf_camel_suppress_D_CSI,
      { "suppress-D-CSI", "camel.suppress_D_CSI",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.NULL", HFILL }},
    { &hf_camel_suppressOutgoingCallBarring,
      { "suppressOutgoingCallBarring", "camel.suppressOutgoingCallBarring",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.NULL", HFILL }},
    { &hf_camel_legToBeReleased,
      { "legToBeReleased", "camel.legToBeReleased",
        FT_UINT32, BASE_DEC, VALS(camel_LegID_vals), 0,
        "camel.LegID", HFILL }},
    { &hf_camel_callSegmentFailure,
      { "callSegmentFailure", "camel.callSegmentFailure",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.CallSegmentFailure", HFILL }},
    { &hf_camel_bCSM_Failure,
      { "bCSM-Failure", "camel.bCSM_Failure",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.BCSM_Failure", HFILL }},
    { &hf_camel_assistingSSPIPRoutingAddress,
      { "assistingSSPIPRoutingAddress", "camel.assistingSSPIPRoutingAddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.AssistingSSPIPRoutingAddress", HFILL }},
    { &hf_camel_eventSpecificInformationBCSM,
      { "eventSpecificInformationBCSM", "camel.eventSpecificInformationBCSM",
        FT_UINT32, BASE_DEC, VALS(camel_EventSpecificInformationBCSM_vals), 0,
        "camel.EventSpecificInformationBCSM", HFILL }},
    { &hf_camel_legID4,
      { "legID4", "camel.legID4",
        FT_UINT32, BASE_DEC, VALS(camel_ReceivingSideID_vals), 0,
        "camel.ReceivingSideID", HFILL }},
    { &hf_camel_miscCallInfo,
      { "miscCallInfo", "camel.miscCallInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.MiscCallInfo", HFILL }},
    { &hf_camel_timerID,
      { "timerID", "camel.timerID",
        FT_UINT32, BASE_DEC, VALS(camel_TimerID_vals), 0,
        "camel.TimerID", HFILL }},
    { &hf_camel_timervalue,
      { "timervalue", "camel.timervalue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.TimerValue", HFILL }},
    { &hf_camel_sCIBillingChargingCharacteristics,
      { "sCIBillingChargingCharacteristics", "camel.sCIBillingChargingCharacteristics",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.SCIBillingChargingCharacteristics", HFILL }},
    { &hf_camel_partyToCharge2,
      { "partyToCharge2", "camel.partyToCharge2",
        FT_UINT32, BASE_DEC, VALS(camel_SendingSideID_vals), 0,
        "camel.SendingSideID", HFILL }},
    { &hf_camel_legToBeSplit,
      { "legToBeSplit", "camel.legToBeSplit",
        FT_UINT32, BASE_DEC, VALS(camel_LegID_vals), 0,
        "camel.LegID", HFILL }},
    { &hf_camel_destinationReference,
      { "destinationReference", "camel.destinationReference",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.Integer4", HFILL }},
    { &hf_camel_originationReference,
      { "originationReference", "camel.originationReference",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.Integer4", HFILL }},
    { &hf_camel_eventSpecificInformationSMS,
      { "eventSpecificInformationSMS", "camel.eventSpecificInformationSMS",
        FT_UINT32, BASE_DEC, VALS(camel_EventSpecificInformationSMS_vals), 0,
        "camel.EventSpecificInformationSMS", HFILL }},
    { &hf_camel_bcsmEvents,
      { "bcsmEvents", "camel.bcsmEvents",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.BCSMEventArray", HFILL }},
    { &hf_camel_BCSMEventArray_item,
      { "Item", "camel.BCSMEventArray_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.BCSMEvent", HFILL }},
    { &hf_camel_callingPartysNumber,
      { "callingPartysNumber", "camel.callingPartysNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.SMS_AddressString", HFILL }},
    { &hf_camel_destinationSubscriberNumber,
      { "destinationSubscriberNumber", "camel.destinationSubscriberNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.CalledPartyBCDNumber", HFILL }},
    { &hf_camel_sMSCAddress,
      { "sMSCAddress", "camel.sMSCAddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.ISDN_AddressString", HFILL }},
    { &hf_camel_requestedInformationList,
      { "requestedInformationList", "camel.requestedInformationList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.RequestedInformationList", HFILL }},
    { &hf_camel_legID5,
      { "legID5", "camel.legID5",
        FT_UINT32, BASE_DEC, VALS(camel_ReceivingSideID_vals), 0,
        "camel.ReceivingSideID", HFILL }},
    { &hf_camel_disconnectFromIPForbidden,
      { "disconnectFromIPForbidden", "camel.disconnectFromIPForbidden",
        FT_BOOLEAN, 8, NULL, 0,
        "camel.BOOLEAN", HFILL }},
    { &hf_camel_requestAnnouncementComplete,
      { "requestAnnouncementComplete", "camel.requestAnnouncementComplete",
        FT_BOOLEAN, 8, NULL, 0,
        "camel.BOOLEAN", HFILL }},
    { &hf_camel_requestAnnouncementStartedNotification,
      { "requestAnnouncementStartedNotification", "camel.requestAnnouncementStartedNotification",
        FT_BOOLEAN, 8, NULL, 0,
        "camel.BOOLEAN", HFILL }},
    { &hf_camel_collectedInfo,
      { "collectedInfo", "camel.collectedInfo",
        FT_UINT32, BASE_DEC, VALS(camel_CollectedInfo_vals), 0,
        "camel.CollectedInfo", HFILL }},
    { &hf_camel_mSISDN,
      { "mSISDN", "camel.mSISDN",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.ISDN_AddressString", HFILL }},
    { &hf_camel_iMSI,
      { "iMSI", "camel.iMSI",
        FT_BYTES, BASE_HEX, NULL, 0,
        "gsm_map.IMSI", HFILL }},
    { &hf_camel_gPRSMSClass,
      { "gPRSMSClass", "camel.gPRSMSClass",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.GPRSMSClass", HFILL }},
    { &hf_camel_sGSNCapabilities,
      { "sGSNCapabilities", "camel.sGSNCapabilities",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.SGSNCapabilities", HFILL }},
    { &hf_camel_gapCriteria,
      { "gapCriteria", "camel.gapCriteria",
        FT_UINT32, BASE_DEC, VALS(camel_GapCriteria_vals), 0,
        "camel.GapCriteria", HFILL }},
    { &hf_camel_gapIndicators,
      { "gapIndicators", "camel.gapIndicators",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.GapIndicators", HFILL }},
    { &hf_camel_controlType,
      { "controlType", "camel.controlType",
        FT_UINT32, BASE_DEC, VALS(camel_ControlType_vals), 0,
        "camel.ControlType", HFILL }},
    { &hf_camel_gapTreatment,
      { "gapTreatment", "camel.gapTreatment",
        FT_UINT32, BASE_DEC, VALS(camel_GapTreatment_vals), 0,
        "camel.GapTreatment", HFILL }},
    { &hf_camel_calledPartyNumber,
      { "calledPartyNumber", "camel.calledPartyNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.CalledPartyNumber", HFILL }},
    { &hf_camel_cGEncountered,
      { "cGEncountered", "camel.cGEncountered",
        FT_UINT32, BASE_DEC, VALS(camel_CGEncountered_vals), 0,
        "camel.CGEncountered", HFILL }},
    { &hf_camel_locationNumber,
      { "locationNumber", "camel.locationNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.LocationNumber", HFILL }},
    { &hf_camel_highLayerCompatibility,
      { "highLayerCompatibility", "camel.highLayerCompatibility",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.HighLayerCompatibility", HFILL }},
    { &hf_camel_additionalCallingPartyNumber,
      { "additionalCallingPartyNumber", "camel.additionalCallingPartyNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.AdditionalCallingPartyNumber", HFILL }},
    { &hf_camel_bearerCapability,
      { "bearerCapability", "camel.bearerCapability",
        FT_UINT32, BASE_DEC, VALS(camel_BearerCapability_vals), 0,
        "camel.BearerCapability", HFILL }},
    { &hf_camel_cug_Index,
      { "cug-Index", "camel.cug_Index",
        FT_UINT32, BASE_DEC, NULL, 0,
        "gsm_map_ms.CUG_Index", HFILL }},
    { &hf_camel_subscriberState,
      { "subscriberState", "camel.subscriberState",
        FT_UINT32, BASE_DEC, VALS(gsm_map_ms_SubscriberState_vals), 0,
        "camel.SubscriberState", HFILL }},
    { &hf_camel_mscAddress,
      { "mscAddress", "camel.mscAddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.ISDN_AddressString", HFILL }},
    { &hf_camel_calledPartyBCDNumber,
      { "calledPartyBCDNumber", "camel.calledPartyBCDNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.CalledPartyBCDNumber", HFILL }},
    { &hf_camel_timeAndTimezone,
      { "timeAndTimezone", "camel.timeAndTimezone",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.TimeAndTimezone", HFILL }},
    { &hf_camel_gsm_ForwardingPending,
      { "gsm-ForwardingPending", "camel.gsm_ForwardingPending",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.NULL", HFILL }},
    { &hf_camel_initialDPArgExtension,
      { "initialDPArgExtension", "camel.initialDPArgExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.InitialDPArgExtension", HFILL }},
    { &hf_camel_callingPartyNumberas,
      { "callingPartyNumberas", "camel.callingPartyNumberas",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.SMS_AddressString", HFILL }},
    { &hf_camel_locationInformationMSC,
      { "locationInformationMSC", "camel.locationInformationMSC",
        FT_NONE, BASE_NONE, NULL, 0,
        "gsm_map_ms.LocationInformation", HFILL }},
    { &hf_camel_tPShortMessageSpecificInfo,
      { "tPShortMessageSpecificInfo", "camel.tPShortMessageSpecificInfo",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.TPShortMessageSpecificInfo", HFILL }},
    { &hf_camel_tPProtocolIdentifier,
      { "tPProtocolIdentifier", "camel.tPProtocolIdentifier",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.TPProtocolIdentifier", HFILL }},
    { &hf_camel_tPDataCodingScheme,
      { "tPDataCodingScheme", "camel.tPDataCodingScheme",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.TPDataCodingScheme", HFILL }},
    { &hf_camel_tPValidityPeriod,
      { "tPValidityPeriod", "camel.tPValidityPeriod",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.TPValidityPeriod", HFILL }},
    { &hf_camel_smsReferenceNumber,
      { "smsReferenceNumber", "camel.smsReferenceNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.CallReferenceNumber", HFILL }},
    { &hf_camel_sgsnNumber,
      { "sgsnNumber", "camel.sgsnNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.ISDN_AddressString", HFILL }},
    { &hf_camel_calledPartyNumberSMS,
      { "calledPartyNumberSMS", "camel.calledPartyNumberSMS",
        FT_BYTES, BASE_HEX, NULL, 0,
        "camel.ISDN_AddressString", HFILL }},
    { &hf_camel_sMSEvents,
      { "sMSEvents", "camel.sMSEvents",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.SMSEventArray", HFILL }},
    { &hf_camel_SMSEventArray_item,
      { "Item", "camel.SMSEventArray_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.SMSEvent", HFILL }},
    { &hf_camel_privateExtensionList,
      { "privateExtensionList", "camel.privateExtensionList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "camel.PrivateExtensionList", HFILL }},
    { &hf_camel_pcs_Extensions,
      { "pcs-Extensions", "camel.pcs_Extensions",
        FT_NONE, BASE_NONE, NULL, 0,
        "camel.PCS_Extensions", HFILL }},
    { &hf_camel_chargingCharacteristics,
      { "chargingCharacteristics", "camel.chargingCharacteristics",
        FT_UINT32, BASE_DEC, VALS(camel_ChargingCharacteristics_vals), 0,
        "camel.ChargingCharacteristics", HFILL }},
    { &hf_camel_chargingResult,
      { "chargingResult", "camel.chargingResult",
        FT_UINT32, BASE_DEC, VALS(camel_ChargingResult_vals), 0,
        "camel.ChargingResult", HFILL }},
    { &hf_camel_active,
      { "active", "camel.active",
        FT_BOOLEAN, 8, NULL, 0,
        "camel.BOOLEAN", HFILL }},
    { &hf_camel_chargingRollOver,
      { "chargingRollOver", "camel.chargingRollOver",
        FT_UINT32, BASE_DEC, VALS(camel_ChargingRollOver_vals), 0,
        "camel.ChargingRollOver", HFILL }},
    { &hf_camel_cancelproblem,
      { "cancelproblem", "camel.cancelproblem",
        FT_UINT32, BASE_DEC, VALS(camel_T_cancelproblem_vals), 0,
        "camel.T_cancelproblem", HFILL }},
    { &hf_camel_operation,
      { "operation", "camel.operation",
        FT_INT32, BASE_DEC, NULL, 0,
        "camel.InvokeID", HFILL }},
    { &hf_camel_SupportedCamelPhases_phase1,
      { "phase1", "camel.phase1",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_camel_SupportedCamelPhases_phase2,
      { "phase2", "camel.phase2",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_camel_SupportedCamelPhases_phase3,
      { "phase3", "camel.phase3",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_camel_SupportedCamelPhases_phase4,
      { "phase4", "camel.phase4",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_camel_OfferedCamel4Functionalities_initiateCallAttempt,
      { "initiateCallAttempt", "camel.initiateCallAttempt",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_camel_OfferedCamel4Functionalities_splitLeg,
      { "splitLeg", "camel.splitLeg",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_camel_OfferedCamel4Functionalities_moveLeg,
      { "moveLeg", "camel.moveLeg",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_camel_OfferedCamel4Functionalities_disconnectLeg,
      { "disconnectLeg", "camel.disconnectLeg",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_camel_OfferedCamel4Functionalities_entityReleased,
      { "entityReleased", "camel.entityReleased",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_camel_OfferedCamel4Functionalities_dfc_WithArgument,
      { "dfc-WithArgument", "camel.dfc-WithArgument",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_camel_OfferedCamel4Functionalities_playTone,
      { "playTone", "camel.playTone",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_camel_OfferedCamel4Functionalities_dtmf_MidCall,
      { "dtmf-MidCall", "camel.dtmf-MidCall",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_camel_OfferedCamel4Functionalities_chargingIndicator,
      { "chargingIndicator", "camel.chargingIndicator",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_camel_OfferedCamel4Functionalities_alertingDP,
      { "alertingDP", "camel.alertingDP",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_camel_OfferedCamel4Functionalities_locationAtAlerting,
      { "locationAtAlerting", "camel.locationAtAlerting",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_camel_OfferedCamel4Functionalities_changeOfPositionDP,
      { "changeOfPositionDP", "camel.changeOfPositionDP",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_camel_OfferedCamel4Functionalities_or_Interactions,
      { "or-Interactions", "camel.or-Interactions",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_camel_OfferedCamel4Functionalities_warningToneEnhancements,
      { "warningToneEnhancements", "camel.warningToneEnhancements",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_camel_OfferedCamel4Functionalities_cf_Enhancements,
      { "cf-Enhancements", "camel.cf-Enhancements",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_camel_OfferedCamel4Functionalities_subscribedEnhancedDialledServices,
      { "subscribedEnhancedDialledServices", "camel.subscribedEnhancedDialledServices",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_camel_OfferedCamel4Functionalities_servingNetworkEnhancedDialledServices,
      { "servingNetworkEnhancedDialledServices", "camel.servingNetworkEnhancedDialledServices",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_camel_OfferedCamel4Functionalities_criteriaForChangeOfPositionDP,
      { "criteriaForChangeOfPositionDP", "camel.criteriaForChangeOfPositionDP",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_camel_OfferedCamel4Functionalities_serviceChangeDP,
      { "serviceChangeDP", "camel.serviceChangeDP",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},

/*--- End of included file: packet-camel-hfarr.c ---*/
#line 880 "packet-camel-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_camel,
    &ett_camelisup_parameter,
    &ett_camel_isdn_address_string,
    &ett_camel_MSRadioAccessCapability,
    &ett_camel_MSNetworkCapability,
    &ett_camel_AccessPointName,
    &ett_camel_pdptypenumber,
    &ett_camel_stat,


/*--- Included file: packet-camel-ettarr.c ---*/
#line 1 "packet-camel-ettarr.c"
    &ett_camel_Component,
    &ett_camel_Invoke,
    &ett_camel_ReturnResult,
    &ett_camel_T_resultretres,
    &ett_camel_ReturnError,
    &ett_camel_Reject,
    &ett_camel_T_invokeIDRej,
    &ett_camel_T_problem,
    &ett_camel_OPERATION,
    &ett_camel_ERROR,
    &ett_camel_AChBillingChargingCharacteristics,
    &ett_camel_T_actimeDurationCharging,
    &ett_camel_AChChargingAddress,
    &ett_camel_AOCBeforeAnswer,
    &ett_camel_AOCGprs,
    &ett_camel_AOCSubsequent,
    &ett_camel_AudibleIndicator,
    &ett_camel_BackwardServiceInteractionInd,
    &ett_camel_BasicGapCriteria,
    &ett_camel_T_calledAddressAndService,
    &ett_camel_T_callingAddressAndService,
    &ett_camel_BCSMEvent,
    &ett_camel_BCSM_Failure,
    &ett_camel_BearerCapability,
    &ett_camel_Burst,
    &ett_camel_BurstList,
    &ett_camel_CAI_Gsm0224,
    &ett_camel_CallSegmentFailure,
    &ett_camel_CallSegmentToCancel,
    &ett_camel_CAMEL_AChBillingChargingCharacteristics,
    &ett_camel_T_timeDurationCharging,
    &ett_camel_CAMEL_CallResult,
    &ett_camel_TimeDurationChargingResult,
    &ett_camel_CAMEL_FCIBillingChargingCharacteristics,
    &ett_camel_T_fCIBCCCAMELsequence1,
    &ett_camel_CAMEL_FCIGPRSBillingChargingCharacteristics,
    &ett_camel_T_fCIBCCCAMELsequence2,
    &ett_camel_CAMEL_FCISMSBillingChargingCharacteristics,
    &ett_camel_T_fCIBCCCAMELsequence3,
    &ett_camel_CAMEL_SCIBillingChargingCharacteristics,
    &ett_camel_CAMEL_SCIBillingChargingCharacteristicsAlt,
    &ett_camel_CamelSCIGPRSBillingChargingCharacteristics,
    &ett_camel_ChangeOfPositionControlInfo,
    &ett_camel_ChangeOfLocation,
    &ett_camel_ChangeOfLocationAlt,
    &ett_camel_ChargingCharacteristics,
    &ett_camel_ChargingResult,
    &ett_camel_ChargingRollOver,
    &ett_camel_CollectedDigits,
    &ett_camel_CollectedInfo,
    &ett_camel_CompoundCriteria,
    &ett_camel_DestinationRoutingAddress,
    &ett_camel_DpSpecificCriteria,
    &ett_camel_DpSpecificCriteriaAlt,
    &ett_camel_DpSpecificInfoAlt,
    &ett_camel_T_oServiceChangeSpecificInfo,
    &ett_camel_T_tServiceChangeSpecificInfo,
    &ett_camel_ElapsedTime,
    &ett_camel_T_timeGPRSIfTariffSwitch,
    &ett_camel_ElapsedTimeRollOver,
    &ett_camel_T_rOTimeGPRSIfTariffSwitch,
    &ett_camel_EventSpecificInformationBCSM,
    &ett_camel_T_routeSelectFailureSpecificInfo,
    &ett_camel_T_oCalledPartyBusySpecificInfo,
    &ett_camel_T_oNoAnswerSpecificInfo,
    &ett_camel_T_oAnswerSpecificInfo,
    &ett_camel_T_oMidCallSpecificInfo,
    &ett_camel_T_omidCallEvents,
    &ett_camel_T_oDisconnectSpecificInfo,
    &ett_camel_T_tBusySpecificInfo,
    &ett_camel_T_tNoAnswerSpecificInfo,
    &ett_camel_T_tAnswerSpecificInfo,
    &ett_camel_T_tMidCallSpecificInfo,
    &ett_camel_T_tmidCallEvents,
    &ett_camel_T_tDisconnectSpecificInfo,
    &ett_camel_T_oTermSeizedSpecificInfo,
    &ett_camel_T_callAcceptedSpecificInfo,
    &ett_camel_T_oAbandonSpecificInfo,
    &ett_camel_T_oChangeOfPositionSpecificInfo,
    &ett_camel_T_tChangeOfPositionSpecificInfo,
    &ett_camel_EventSpecificInformationSMS,
    &ett_camel_T_o_smsFailureSpecificInfo,
    &ett_camel_T_o_smsSubmittedSpecificInfo,
    &ett_camel_T_t_smsFailureSpecificInfo,
    &ett_camel_T_t_smsDeliverySpecificInfo,
    &ett_camel_ForwardServiceInteractionInd,
    &ett_camel_GapCriteria,
    &ett_camel_GapIndicators,
    &ett_camel_GapOnService,
    &ett_camel_GapTreatment,
    &ett_camel_GenericNumbers,
    &ett_camel_GPRS_QoS,
    &ett_camel_GPRS_QoS_Extension,
    &ett_camel_GPRSEvent,
    &ett_camel_GPRSEventSpecificInformation,
    &ett_camel_T_attachChangeOfPositionSpecificInformation,
    &ett_camel_T_pdp_ContextchangeOfPositionSpecificInformation,
    &ett_camel_T_detachSpecificInformation,
    &ett_camel_T_disconnectSpecificInformation,
    &ett_camel_T_pDPContextEstablishmentSpecificInformation,
    &ett_camel_T_pDPContextEstablishmentAcknowledgementSpecificInformation,
    &ett_camel_GPRSMSClass,
    &ett_camel_InbandInfo,
    &ett_camel_InformationToSend,
    &ett_camel_LegOrCallSegment,
    &ett_camel_LocationInformationGPRS,
    &ett_camel_MessageID,
    &ett_camel_T_text,
    &ett_camel_SEQUENCE_SIZE_1_cAPSpecificBoundSetnumOfMessageIDs_OF_Integer4,
    &ett_camel_T_variableMessage,
    &ett_camel_MetDPCriteriaList,
    &ett_camel_MetDPCriterion,
    &ett_camel_MetDPCriterionAlt,
    &ett_camel_MidCallControlInfo,
    &ett_camel_QualityOfService,
    &ett_camel_ReceivingSideID,
    &ett_camel_RequestedInformationList,
    &ett_camel_RequestedInformationTypeList,
    &ett_camel_RequestedInformation,
    &ett_camel_RequestedInformationValue,
    &ett_camel_SendingSideID,
    &ett_camel_ServiceInteractionIndicatorsTwo,
    &ett_camel_SMSEvent,
    &ett_camel_TimeIfTariffSwitch,
    &ett_camel_TimeInformation,
    &ett_camel_Tone,
    &ett_camel_TransferredVolume,
    &ett_camel_T_volumeIfTariffSwitch,
    &ett_camel_TransferredVolumeRollOver,
    &ett_camel_T_rOVolumeIfTariffSwitch,
    &ett_camel_VariablePart,
    &ett_camel_SpecializedResourceReportArg,
    &ett_camel_PDPType,
    &ett_camel_Code,
    &ett_camel_PCS_Extensions,
    &ett_camel_MiscCallInfo,
    &ett_camel_SupportedExtensionsExtensionType,
    &ett_camel_PrivateExtension,
    &ett_camel_ApplyChargingReportArg,
    &ett_camel_CancelArg,
    &ett_camel_CollectInformationArg,
    &ett_camel_ReceivedInformationArg,
    &ett_camel_ConnectGPRSArg,
    &ett_camel_EntityReleasedGPRSArg,
    &ett_camel_ReleaseGPRSArg,
    &ett_camel_RequestReportGPRSEventArg,
    &ett_camel_GPRSEventArray,
    &ett_camel_SendChargingInformationGPRSArg,
    &ett_camel_SubscriberState,
    &ett_camel_PrivateExtensionList,
    &ett_camel_LegID,
    &ett_camel_VariablePartsArray,
    &ett_camel_InitialDPArgExtension,
    &ett_camel_InitiateCallAttemptArg,
    &ett_camel_InitiateCallAttemptRes,
    &ett_camel_MoveLegArg,
    &ett_camel_PlayToneArg,
    &ett_camel_SupportedCamelPhases,
    &ett_camel_OfferedCamel4Functionalities,
    &ett_camel_EventReportGPRSArg,
    &ett_camel_ExtensionField,
    &ett_camel_ApplyChargingArg,
    &ett_camel_ExtensionsArray,
    &ett_camel_AssistRequestInstructionsArg,
    &ett_camel_CallInformationRequestArg,
    &ett_camel_ConnectArg,
    &ett_camel_ConnectToResourceArg,
    &ett_camel_T_resourceAddress,
    &ett_camel_ContinueWithArgumentArg,
    &ett_camel_ContinueWithArgumentArgExtension,
    &ett_camel_DisconnectLegArg,
    &ett_camel_EntityReleasedArg,
    &ett_camel_DisconnectForwardConnectionWithArgumentArg,
    &ett_camel_EstablishTemporaryConnectionArg,
    &ett_camel_EventReportBCSMArg,
    &ett_camel_ResetTimerArg,
    &ett_camel_SendChargingInformationArg,
    &ett_camel_SplitLegArg,
    &ett_camel_CAPGPRSReferenceNumber,
    &ett_camel_EventReportSMSArg,
    &ett_camel_ResetTimerSMSArg,
    &ett_camel_RequestReportBCSMEventArg,
    &ett_camel_BCSMEventArray,
    &ett_camel_ConnectSMSArg,
    &ett_camel_CallInformationReportArg,
    &ett_camel_PlayAnnouncementArg,
    &ett_camel_PromptAndCollectUserInformationArg,
    &ett_camel_InitialDPGPRSArg,
    &ett_camel_CallGapArg,
    &ett_camel_InitialDPArg,
    &ett_camel_InitialDPSMSArg,
    &ett_camel_RequestReportSMSEventArg,
    &ett_camel_SMSEventArray,
    &ett_camel_ExtensionContainer,
    &ett_camel_ApplyChargingGPRSArg,
    &ett_camel_ApplyChargingReportGPRSArg,
    &ett_camel_CancelGPRSArg,
    &ett_camel_ContinueGPRSArg,
    &ett_camel_ResetTimerGPRSArg,
    &ett_camel_CancelFailedPARAM,

/*--- End of included file: packet-camel-ettarr.c ---*/
#line 894 "packet-camel-template.c"
  };
  /* Register protocol */
  proto_camel = proto_register_protocol(PNAME, PSNAME, PFNAME);

  register_dissector("camel", dissect_camel, proto_camel);

  proto_register_field_array(proto_camel, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register our configuration options, particularly our ssn:s */
  /* Set default SSNs */
  range_convert_str(&global_ssn_range, "6-9", MAX_SSN);
  ssn_range = range_empty();

  camel_module = prefs_register_protocol(proto_camel, proto_reg_handoff_camel);

  prefs_register_enum_preference(camel_module, "date.format", "Date Format",
                                  "The date format: (DD/MM) or (MM/DD)",
                                  &date_format, date_options, FALSE);
  
  
  prefs_register_range_preference(camel_module, "tcap.ssn",
    "TCAP SSNs",
    "TCAP Subsystem numbers used for Camel",
    &global_ssn_range, MAX_SSN);

  prefs_register_bool_preference(camel_module, "srt",
				 "Service Response Time Analyse",
				 "Activate the analyse for Response Time",
				 &gcamel_HandleSRT);

  prefs_register_bool_preference(camel_module, "persistentsrt",
				 "Persistent stats for SRT",
				 "Statistics for Response Time",
				 &gcamel_PersistentSRT);
  
  /* Routine for statistic */ 
  register_init_routine(&camelsrt_init_routine);
  camel_tap=register_tap(PSNAME);
}

