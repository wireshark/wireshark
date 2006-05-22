/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* .\packet-h450.c                                                            */
/* ../../tools/asn2wrs.py -e -p h450 -c h450.cnf -s packet-h450-template h4501.asn */

/* Input file: packet-h450-template.c */

#line 1 "packet-h450-template.c"
/* packet-h450.c
 * Routines for h450 packet dissection
 * Based on the previous h450 dissector by:
 * 2003  Graeme Reid (graeme.reid@norwoodsystems.com)
 * Copyright 2005, Anders Broman <anders.broman@ericsson.com>
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
 *
 * Credit to Tomas Kukosa for developing the Asn2eth compiler.
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include "packet-h450.h"

#include "packet-ber.h"
#include "packet-per.h"
#include "packet-h225.h"

#define PNAME  "h450"
#define PSNAME "h450"
#define PFNAME "h450"
/* H.450.2 Call Transfer constants */
#define CallTransferIdentify        7
#define CallTransferAbandon         8
#define CallTransferInitiate        9
#define CallTransferSetup           10
#define CallTransferUpdate          13
#define SubaddressTransfer          14
#define CallTransferComplete        12
#define CallTransferActive          11

/* H.450.3 Call Diversion constants */
#define ActivateDiversionQ          15
#define DeactivateDiversionQ        16
#define InterrogateDiversionQ       17
#define CheckRestriction            18
#define CallRerouting               19
#define DivertingLegInformation1    20
#define DivertingLegInformation2    21
#define DivertingLegInformation3    22
#define DivertingLegInformation4    100
#define CfnrDivertedLegFailed       23

/* H.450.4 Call Hold constants */
#define HoldNotific                 101
#define RetrieveNotific             102
#define RemoteHold                  103
#define RemoteRetrieve              104

/* H.450.5 Call Park and Pickup constants */
#define CpRequest                   106
#define CpSetup                     107
#define GroupIndicationOn           108
#define GroupIndicationOff          109
#define Pickrequ                    110
#define Pickup                      111
#define PickExe                     112
#define CpNotify                    113
#define CpickupNotify               114

/* H.450.6 Call Waiting constants */
#define CallWaiting                 105

/* H.450.7 Message Waiting Indication constants */
#define MWIActivate                 80
#define MWIDeactivate               81
#define MWIInterrogate              82 

/* H.450.8 Name Identification constants */
#define NIcallingName               0
#define NIalertingName              1
#define NIconnectedName             2
#define NIbusyName                  3 

/* H.450.9 Call Completion constants */
#define CCBSRequest                 40
#define CCNRRequest                 27
#define CCCancel                    28
#define CCExecPossible              29
#define CCRingout                   31
#define CCSuspend                   32
#define CCResume                    33 

/* H.450.10 Call Offer constants */
#define CallOfferRequest            34
#define RemoteUserAlerting          115
#define CFBOverride                 49 

/* H.450.11 Call Intrusion constants */
#define CallIntrusionRequest        43
#define CallIntrusionGetCIPL        44
#define CallIntrusionIsolate        45
#define CallIntrusionForcedRelease  46
#define CallIntrusionWOBRequest     47
#define CallIntrusionSilentMonitor  116
#define CallIntrusionNotification   117

/* H.450.12 Common Information Operations constants */
#define CmnRequest					84
#define CmnInform					85

/* TODO - define other H.450.x constants here */
static dissector_handle_t h4501_handle=NULL;

/* Initialize the protocol and registered fields */
static int proto_h4501 = -1;

static int hf_h4501 = -1;
static int hf_h4501_constrained_invokeId = -1;
static int hf_h4501_invokeId = -1;
static int hf_h4501_localOpcode = -1;
static int hf_h4501_globalCode = -1;
static int hf_h4501_globalargument = -1;
static int hf_h4501_opcode = -1;
static int hf_h4501_ReturnResult_result = -1;
static int hf_h4501_result = -1;
static int hf_h4501_ReturnResult = -1;
static int hf_h4501_localErrorCode = -1;
static int hf_h4501_errorCode = -1;
static int hf_h4501_parameter = -1;
static int hf_h4501_ReturnError = -1;
static int hf_h4501_GeneralProblem = -1;
static int hf_h4501_InvokeProblem = -1;
static int hf_h4501_ReturnResultProblem = -1;
static int hf_h4501_ReturnErrorProblem = -1;
static int hf_h4501_problem = -1;
static int hf_h4501_Reject = -1;

static int hf_h4502_CTIdentifyRes = -1;
static int hf_h4502_DummyRes = -1;
static int hf_h4502_DummyArg = -1;

static int hf_h4503DeactivateDiversionQArg = -1;
static int hf_h4503InterrogateDiversionQ = -1;
static int hf_h4503CheckRestrictionArg = -1;
static int hf_h4503CallReroutingArg = -1;
static int hf_h4503DivertingLegInformation1Arg = -1;
static int hf_h4503DivertingLegInformation2Arg = -1;
static int hf_h4503DivertingLegInformation3Arg = -1;
static int hf_h4503DivertingLegInformation4Arg = -1;
static int hf_h4503CfnrDivertedLegFailedArg = -1;

static int hf_h4504_HoldNotificArg = -1;
static int hf_h4504_RetrieveNotificArg = -1;
static int hf_h4504_RemoteHoldArg = -1;
static int hf_h4504_RemoteRetrieveArg = -1;
static int hf_h4504_RemoteRetrieveRes = -1;

static int hf_h4507_MWIActivateArg = -1;
static int hf_h4507_MWIDeactivateArg = -1;
static int hf_h4507_MwiDummyRes = -1;
static int hf_h4507_MWIInterrogateArg = -1;
static int hf_h4507_MWIInterrogateRes = -1;

static int hf_h4508_CallingNameArg = -1;
static int hf_h4508_AlertingNameArg = -1;
static int hf_h4508_ConnectedNameArg = -1;
static int hf_h4508_BusyNameArg = -1;
static int hf_h45012_CmnRequest = -1;
static int hf_h45012_CmnInform = -1;

static int hf_h4501_Invoke = -1;
static int hf_h4501_ROS = -1;


/*--- Included file: packet-h450-hf.c ---*/
#line 1 "packet-h450-hf.c"
static int hf_h450_CallTransferIdentify_PDU = -1;  /* CallTransferIdentify */
static int hf_h450_CallTransferAbandon_PDU = -1;  /* CallTransferAbandon */
static int hf_h450_CallTransferInitiate_PDU = -1;  /* CallTransferInitiate */
static int hf_h450_CallTransferSetup_PDU = -1;    /* CallTransferSetup */
static int hf_h450_CallTransferUpdate_PDU = -1;   /* CallTransferUpdate */
static int hf_h450_SubaddressTransfer_PDU = -1;   /* SubaddressTransfer */
static int hf_h450_CallTransferComplete_PDU = -1;  /* CallTransferComplete */
static int hf_h450_CallTransferActive_PDU = -1;   /* CallTransferActive */
static int hf_h450_ActivateDiversionQArg_PDU = -1;  /* ActivateDiversionQArg */
static int hf_h450_ActivateDiversionQRes_PDU = -1;  /* ActivateDiversionQRes */
static int hf_h450_DeactivateDiversionQRes_PDU = -1;  /* DeactivateDiversionQRes */
static int hf_h450_InterrogateDiversionQRes_PDU = -1;  /* InterrogateDiversionQRes */
static int hf_h450_CheckRestrictionRes_PDU = -1;  /* CheckRestrictionRes */
static int hf_h450_CallReroutingRes_PDU = -1;     /* CallReroutingRes */
static int hf_h450_networkFacilityExtension = -1;  /* NetworkFacilityExtension */
static int hf_h450_interpretationApdu = -1;       /* InterpretationApdu */
static int hf_h450_serviceApdu = -1;              /* ServiceApdus */
static int hf_h450_sourceEntity = -1;             /* EntityType */
static int hf_h450_sourceEntityAddress = -1;      /* AddressInformation */
static int hf_h450_destinationEntity = -1;        /* EntityType */
static int hf_h450_destinationEntityAddress = -1;  /* AddressInformation */
static int hf_h450_endpoint = -1;                 /* NULL */
static int hf_h450_anyEntity = -1;                /* NULL */
static int hf_h450_discardAnyUnrecognizedInvokePdu = -1;  /* NULL */
static int hf_h450_clearCallIfAnyInvokePduNotRecognized = -1;  /* NULL */
static int hf_h450_rejectAnyUnrecognizedInvokePdu = -1;  /* NULL */
static int hf_h450_rosApdus = -1;                 /* SEQUENCE_OF_ROSxxx */
static int hf_h450_rosApdus_item = -1;            /* ROSxxx */
static int hf_h450_addressScreened_presentationAllowedAddress = -1;  /* AddressScreened */
static int hf_h450_presentationRestricted = -1;   /* NULL */
static int hf_h450_numberNotAvailableDueToInterworking = -1;  /* NULL */
static int hf_h450_addressScreened_presentationRestrictedAddress = -1;  /* AddressScreened */
static int hf_h450_addressUnscreened_presentationAllowedAddress = -1;  /* Address */
static int hf_h450_addressUnscreened_presentationRestrictedAddress = -1;  /* Address */
static int hf_h450_numberScreened_presentationAllowedAddress = -1;  /* NumberScreened */
static int hf_h450_numberScreened_presentationRestrictedAddress = -1;  /* NumberScreened */
static int hf_h450_numberUnscreened_presentationAllowedAddress = -1;  /* PartyNumber */
static int hf_h450_numberUnscreened_presentationRestrictedAddress = -1;  /* PartyNumber */
static int hf_h450_partyNumber = -1;              /* PartyNumber */
static int hf_h450_screeningIndicator = -1;       /* ScreeningIndicator */
static int hf_h450_partySubaddress = -1;          /* PartySubaddress */
static int hf_h450_destinationAddress = -1;       /* SEQUENCE_OF_AliasAddress */
static int hf_h450_destinationAddress_item = -1;  /* AliasAddress */
static int hf_h450_remoteExtensionAddress = -1;   /* AliasAddress */
static int hf_h450_destinationAddressPresentationIndicator = -1;  /* PresentationIndicator */
static int hf_h450_destinationAddressScreeningIndicator = -1;  /* ScreeningIndicator */
static int hf_h450_remoteExtensionAddressPresentationIndicator = -1;  /* PresentationIndicator */
static int hf_h450_remoteExtensionAddressScreeningIndicator = -1;  /* ScreeningIndicator */
static int hf_h450_userSpecifiedSubaddress = -1;  /* UserSpecifiedSubaddress */
static int hf_h450_nsapSubaddress = -1;           /* NSAPSubaddress */
static int hf_h450_subaddressInformation = -1;    /* SubaddressInformation */
static int hf_h450_oddCountIndicator = -1;        /* BOOLEAN */
static int hf_h450_extensionSeq = -1;             /* ExtensionSeq */
static int hf_h450_nonStandardData = -1;          /* NonStandardParameter */
static int hf_h450_callIdentity = -1;             /* CallIdentity */
static int hf_h450_reroutingNumber = -1;          /* EndpointAddress */
static int hf_h450_cTInitiateArg_argumentExtension = -1;  /* ArgumentExtension */
static int hf_h450_transferringNumber = -1;       /* EndpointAddress */
static int hf_h450_cTSetupArg_argumentExtension = -1;  /* ArgumentExtension */
static int hf_h450_resultExtension = -1;          /* T_resultExtension */
static int hf_h450_redirectionNumber = -1;        /* EndpointAddress */
static int hf_h450_redirectionInfo = -1;          /* BMPString_SIZE_1_128 */
static int hf_h450_basicCallInfoElements = -1;    /* H225InformationElement */
static int hf_h450_cTUpdateArg_argumentExtension = -1;  /* ArgumentExtension */
static int hf_h450_redirectionSubaddress = -1;    /* PartySubaddress */
static int hf_h450_subaddressTransferArg_argumentExtension = -1;  /* ArgumentExtension */
static int hf_h450_endDesignation = -1;           /* EndDesignation */
static int hf_h450_callStatus = -1;               /* CallStatus */
static int hf_h450_cTCompleteArg_argumentExtension = -1;  /* ArgumentExtension */
static int hf_h450_connectedAddress = -1;         /* EndpointAddress */
static int hf_h450_connectedInfo = -1;            /* BMPString_SIZE_1_128 */
static int hf_h450_cTActiveArg_argumentExtension = -1;  /* ArgumentExtension */
static int hf_h450_ExtensionSeq_item = -1;        /* Extension */
static int hf_h450_procedure = -1;                /* Procedure */
static int hf_h450_basicService = -1;             /* BasicService */
static int hf_h450_divertedToAddress = -1;        /* EndpointAddress */
static int hf_h450_servedUserNr = -1;             /* EndpointAddress */
static int hf_h450_activatingUserNr = -1;         /* EndpointAddress */
static int hf_h450_activateDiversionQArg_extension = -1;  /* ActivateDiversionQArg_extension */
static int hf_h450_deactivatingUserNr = -1;       /* EndpointAddress */
static int hf_h450_deactivateDiversionQArg_extension = -1;  /* DeactivateDiversionQArg_extension */
static int hf_h450_interrogatingUserNr = -1;      /* EndpointAddress */
static int hf_h450_interrogateDiversionQ_extension = -1;  /* InterrogateDiversionQ_extension */
static int hf_h450_divertedToNr = -1;             /* EndpointAddress */
static int hf_h450_checkRestrictionArg_extension = -1;  /* CheckRestrictionArg_extension */
static int hf_h450_reroutingReason = -1;          /* DiversionReason */
static int hf_h450_originalReroutingReason = -1;  /* DiversionReason */
static int hf_h450_calledAddress = -1;            /* EndpointAddress */
static int hf_h450_diversionCounter = -1;         /* INTEGER_1_15 */
static int hf_h450_h225InfoElement = -1;          /* H225InformationElement */
static int hf_h450_lastReroutingNr = -1;          /* EndpointAddress */
static int hf_h450_subscriptionOption = -1;       /* SubscriptionOption */
static int hf_h450_callingPartySubaddress = -1;   /* PartySubaddress */
static int hf_h450_callingNumber = -1;            /* EndpointAddress */
static int hf_h450_callingInfo = -1;              /* BMPString_SIZE_1_128 */
static int hf_h450_originalCalledNr = -1;         /* EndpointAddress */
static int hf_h450_redirectingInfo = -1;          /* BMPString_SIZE_1_128 */
static int hf_h450_originalCalledInfo = -1;       /* BMPString_SIZE_1_128 */
static int hf_h450_callReroutingArg_extension = -1;  /* CallReroutingArg_extension */
static int hf_h450_diversionReason = -1;          /* DiversionReason */
static int hf_h450_nominatedNr = -1;              /* EndpointAddress */
static int hf_h450_nominatedInfo = -1;            /* BMPString_SIZE_1_128 */
static int hf_h450_redirectingNr = -1;            /* EndpointAddress */
static int hf_h450_divertingLegInformation1Arg_extension = -1;  /* DivertingLegInformation1Arg_extension */
static int hf_h450_originalDiversionReason = -1;  /* DiversionReason */
static int hf_h450_divertingNr = -1;              /* EndpointAddress */
static int hf_h450_extension = -1;                /* DivertingLegInformation2Arg_extension */
static int hf_h450_presentationAllowedIndicator = -1;  /* PresentationAllowedIndicator */
static int hf_h450_redirectionNr = -1;            /* EndpointAddress */
static int hf_h450_divertingLegInformation3Arg_extension = -1;  /* DivertingLegInformation3Arg_extension */
static int hf_h450_callingNr = -1;                /* EndpointAddress */
static int hf_h450_divertingLegInformation4Arg_extension = -1;  /* DivertingLegInformation4Arg_extension */
static int hf_h450_IntResultList_item = -1;       /* IntResult */
static int hf_h450_remoteEnabled = -1;            /* BOOLEAN */
static int hf_h450_intResult_extension = -1;      /* IntResult_extension */
static int hf_h450_holdNotificArg_extensionArg = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_extensionArg_item = -1;        /* MixedExtension */
static int hf_h450_retrieveNotificArg_extensionArg = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_remoteHoldArg_extensionArg = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_extensionRes = -1;             /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_extensionRes_item = -1;        /* MixedExtension */
static int hf_h450_remoteRetrieveArg_extensionArg = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_mixedExtension_extension = -1;  /* Extension */
static int hf_h450_parkingNumber = -1;            /* EndpointAddress */
static int hf_h450_parkedNumber = -1;             /* EndpointAddress */
static int hf_h450_parkedToNumber = -1;           /* EndpointAddress */
static int hf_h450_parkedToPosition = -1;         /* ParkedToPosition */
static int hf_h450_cpRequestArg_extensionArg = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_parkCondition = -1;            /* ParkCondition */
static int hf_h450_cpSetupArg_extensionArg = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_callPickupId = -1;             /* CallIdentifier */
static int hf_h450_groupMemberUserNr = -1;        /* EndpointAddress */
static int hf_h450_retrieveCallType = -1;         /* CallType */
static int hf_h450_partyToRetrieve = -1;          /* EndpointAddress */
static int hf_h450_retrieveAddress = -1;          /* EndpointAddress */
static int hf_h450_parkPosition = -1;             /* ParkedToPosition */
static int hf_h450_groupIndicationOnArg_extensionArg = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_groupIndicationOffArg_extensionArg = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_picking_upNumber = -1;         /* EndpointAddress */
static int hf_h450_pickrequArg_extensionArg = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_pickupArg_extensionArg = -1;   /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_pickExeArg_extensionArg = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_cpNotifyArg_extensionArg = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_cpickupNotifyArg_extensionArg = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_nbOfAddWaitingCalls = -1;      /* INTEGER_0_255 */
static int hf_h450_callWaitingArg_extensionArg = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_msgCentreId = -1;              /* MsgCentreId */
static int hf_h450_nbOfMessages = -1;             /* NbOfMessages */
static int hf_h450_originatingNr = -1;            /* EndpointAddress */
static int hf_h450_timestamp = -1;                /* TimeStamp */
static int hf_h450_priority = -1;                 /* INTEGER_0_9 */
static int hf_h450_mWIActivateArg_extensionArg = -1;  /* ExtensionArg */
static int hf_h450_MwiDummyRes_item = -1;         /* MixedExtension */
static int hf_h450_callbackReq = -1;              /* BOOLEAN */
static int hf_h450_mWIDeactivateArg_extensionArg = -1;  /* ExtensionArg */
static int hf_h450_mWIInterrogateArg_extensionArg = -1;  /* ExtensionArg */
static int hf_h450_MWIInterrogateRes_item = -1;   /* MWIInterrogateResElt */
static int hf_h450_mWIInterrogateResElt_extensionArg = -1;  /* ExtensionArg */
static int hf_h450_integer = -1;                  /* INTEGER_0_65535 */
static int hf_h450_mwipartyNumber = -1;           /* EndpointAddress */
static int hf_h450_numericString = -1;            /* NumericString_SIZE_1_10 */
static int hf_h450_ExtensionArg_item = -1;        /* MixedExtension */
static int hf_h450_name = -1;                     /* Name */
static int hf_h450_nameArg_extensionArg = -1;     /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_namePresentationAllowed = -1;  /* NamePresentationAllowed */
static int hf_h450_namePresentationRestricted = -1;  /* NamePresentationRestricted */
static int hf_h450_nameNotAvailable = -1;         /* NULL */
static int hf_h450_simpleName = -1;               /* SimpleName */
static int hf_h450_extendedName = -1;             /* ExtendedName */
static int hf_h450_restrictedNull = -1;           /* NULL */
static int hf_h450_numberA = -1;                  /* EndpointAddress */
static int hf_h450_numberB = -1;                  /* EndpointAddress */
static int hf_h450_ccIdentifier = -1;             /* CallIdentifier */
static int hf_h450_service = -1;                  /* BasicService */
static int hf_h450_can_retain_service = -1;       /* BOOLEAN */
static int hf_h450_retain_sig_connection = -1;    /* BOOLEAN */
static int hf_h450_ccRequestArg_extension = -1;   /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_extension_item = -1;           /* MixedExtension */
static int hf_h450_retain_service = -1;           /* BOOLEAN */
static int hf_h450_ccRequestRes_extension = -1;   /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_shortArg = -1;                 /* CcShortArg */
static int hf_h450_longArg = -1;                  /* CcLongArg */
static int hf_h450_ccShortArg_extension = -1;     /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_ccLongArg_extension = -1;      /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_coReqOptArg_extension = -1;    /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_rUAlertOptArg_extension = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_cfbOvrOptArg_extension = -1;   /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_ciCapabilityLevel = -1;        /* CICapabilityLevel */
static int hf_h450_cIRequestArg_argumentExtension = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_argumentExtension_item = -1;   /* MixedExtension */
static int hf_h450_ciStatusInformation = -1;      /* CIStatusInformation */
static int hf_h450_cIRequestRes_resultExtension = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_resultExtension_item = -1;     /* MixedExtension */
static int hf_h450_cIGetCIPLOptArg_argumentExtension = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_ciProtectionLevel = -1;        /* CIProtectionLevel */
static int hf_h450_silentMonitoringPermitted = -1;  /* NULL */
static int hf_h450_cIGetCIPLRes_resultExtension = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_cIIsOptArg_argumentExtension = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_cIIsOptRes_resultExtension = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_cIFrcRelArg_argumentExtension = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_cIFrcRelOptRes_resultExtension = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_cIWobOptArg_argumentExtension = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_cIWobOptRes_resultExtension = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_specificCall = -1;             /* CallIdentifier */
static int hf_h450_cISilentArg_argumentExtension = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_cISilentOptRes_resultExtension = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_cINotificationArg_argumentExtension = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_callIntrusionImpending = -1;   /* NULL */
static int hf_h450_callIntruded = -1;             /* NULL */
static int hf_h450_callIsolated = -1;             /* NULL */
static int hf_h450_callForceReleased = -1;        /* NULL */
static int hf_h450_callIntrusionComplete = -1;    /* NULL */
static int hf_h450_callIntrusionEnd = -1;         /* NULL */
static int hf_h450_featureList = -1;              /* FeatureList */
static int hf_h450_featureValues = -1;            /* FeatureValues */
static int hf_h450_featureControl = -1;           /* FeatureControl */
static int hf_h450_cmnArg_extension = -1;         /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_cmnRequestArg_extensionArg = -1;  /* SEQUENCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_ssCFreRoutingSupported = -1;   /* NULL */
static int hf_h450_ssCTreRoutingSupported = -1;   /* NULL */
static int hf_h450_ssCCBSPossible = -1;           /* NULL */
static int hf_h450_ssCCNRPossible = -1;           /* NULL */
static int hf_h450_ssCOSupported = -1;            /* NULL */
static int hf_h450_ssCIForcedReleaseSupported = -1;  /* NULL */
static int hf_h450_ssCIIsolationSupported = -1;   /* NULL */
static int hf_h450_ssCIWaitOnBusySupported = -1;  /* NULL */
static int hf_h450_ssCISilentMonitoringSupported = -1;  /* NULL */
static int hf_h450_ssCIConferenceSupported = -1;  /* NULL */
static int hf_h450_ssCHFarHoldSupported = -1;     /* NULL */
static int hf_h450_ssMWICallbackSupported = -1;   /* NULL */
static int hf_h450_ssCPCallParkSupported = -1;    /* NULL */
static int hf_h450_partyCategory = -1;            /* PartyCategory */
static int hf_h450_ssCIprotectionLevel = -1;      /* SSCIProtectionLevel */
static int hf_h450_ssCHDoNotHold = -1;            /* NULL */
static int hf_h450_ssCTDoNotTransfer = -1;        /* NULL */
static int hf_h450_ssMWICallbackCall = -1;        /* NULL */
static int hf_h450_ssCISilentMonitorPermitted = -1;  /* NULL */
static int hf_h450_unspecified_extension = -1;    /* Extension */
static int hf_h450_nonStandard = -1;              /* NonStandardParameter */
static int hf_h450_extensionId = -1;              /* OBJECT_IDENTIFIER */
static int hf_h450_extensionArgument = -1;        /* ExtensionArgument */

/*--- End of included file: packet-h450-hf.c ---*/
#line 195 "packet-h450-template.c"

/* Initialize the subtree pointers */
static gint ett_h4501 = -1;
static gint ett_h4501_opcode = -1;
static gint ett_h4501_result = -1;
static gint ett_h4501_errorCode = -1;

static gint ett_h4501_problem = -1;
static gint ett_h4501_Reject = -1;
static gint ett_h4501_ReturnError = -1;
static gint ett_h4501_ReturnResult = -1;
static gint ett_h4501_Invoke = -1;
static gint ett_h4501_ROS = -1;


/*--- Included file: packet-h450-ett.c ---*/
#line 1 "packet-h450-ett.c"
static gint ett_h450_H4501SupplementaryService = -1;
static gint ett_h450_NetworkFacilityExtension = -1;
static gint ett_h450_EntityType = -1;
static gint ett_h450_InterpretationApdu = -1;
static gint ett_h450_ServiceApdus = -1;
static gint ett_h450_SEQUENCE_OF_ROSxxx = -1;
static gint ett_h450_PresentedAddressScreened = -1;
static gint ett_h450_PresentedAddressUnscreened = -1;
static gint ett_h450_PresentedNumberScreened = -1;
static gint ett_h450_PresentedNumberUnscreened = -1;
static gint ett_h450_AddressScreened = -1;
static gint ett_h450_NumberScreened = -1;
static gint ett_h450_Address = -1;
static gint ett_h450_EndpointAddress = -1;
static gint ett_h450_SEQUENCE_OF_AliasAddress = -1;
static gint ett_h450_PartySubaddress = -1;
static gint ett_h450_UserSpecifiedSubaddress = -1;
static gint ett_h450_DummyArg = -1;
static gint ett_h450_DummyRes = -1;
static gint ett_h450_CTInitiateArg = -1;
static gint ett_h450_ArgumentExtension = -1;
static gint ett_h450_CTSetupArg = -1;
static gint ett_h450_CTIdentifyRes = -1;
static gint ett_h450_T_resultExtension = -1;
static gint ett_h450_CTUpdateArg = -1;
static gint ett_h450_SubaddressTransferArg = -1;
static gint ett_h450_CTCompleteArg = -1;
static gint ett_h450_CTActiveArg = -1;
static gint ett_h450_ExtensionSeq = -1;
static gint ett_h450_ActivateDiversionQArg = -1;
static gint ett_h450_ActivateDiversionQArg_extension = -1;
static gint ett_h450_ActivateDiversionQRes = -1;
static gint ett_h450_DeactivateDiversionQArg = -1;
static gint ett_h450_DeactivateDiversionQArg_extension = -1;
static gint ett_h450_DeactivateDiversionQRes = -1;
static gint ett_h450_InterrogateDiversionQ = -1;
static gint ett_h450_InterrogateDiversionQ_extension = -1;
static gint ett_h450_CheckRestrictionArg = -1;
static gint ett_h450_CheckRestrictionArg_extension = -1;
static gint ett_h450_CheckRestrictionRes = -1;
static gint ett_h450_CallReroutingArg = -1;
static gint ett_h450_CallReroutingArg_extension = -1;
static gint ett_h450_CallReroutingRes = -1;
static gint ett_h450_DivertingLegInformation1Arg = -1;
static gint ett_h450_DivertingLegInformation1Arg_extension = -1;
static gint ett_h450_DivertingLegInformation2Arg = -1;
static gint ett_h450_DivertingLegInformation2Arg_extension = -1;
static gint ett_h450_DivertingLegInformation3Arg = -1;
static gint ett_h450_DivertingLegInformation3Arg_extension = -1;
static gint ett_h450_DivertingLegInformation4Arg = -1;
static gint ett_h450_DivertingLegInformation4Arg_extension = -1;
static gint ett_h450_CfnrDivertedLegFailedArg = -1;
static gint ett_h450_IntResultList = -1;
static gint ett_h450_IntResult = -1;
static gint ett_h450_IntResult_extension = -1;
static gint ett_h450_HoldNotificArg = -1;
static gint ett_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension = -1;
static gint ett_h450_RetrieveNotificArg = -1;
static gint ett_h450_RemoteHoldArg = -1;
static gint ett_h450_RemoteHoldRes = -1;
static gint ett_h450_RemoteRetrieveArg = -1;
static gint ett_h450_RemoteRetrieveRes = -1;
static gint ett_h450_MixedExtension = -1;
static gint ett_h450_CpRequestArg = -1;
static gint ett_h450_CpRequestRes = -1;
static gint ett_h450_CpSetupArg = -1;
static gint ett_h450_CpSetupRes = -1;
static gint ett_h450_GroupIndicationOnArg = -1;
static gint ett_h450_GroupIndicationOnRes = -1;
static gint ett_h450_GroupIndicationOffArg = -1;
static gint ett_h450_GroupIndicationOffRes = -1;
static gint ett_h450_PickrequArg = -1;
static gint ett_h450_PickrequRes = -1;
static gint ett_h450_PickupArg = -1;
static gint ett_h450_PickupRes = -1;
static gint ett_h450_PickExeArg = -1;
static gint ett_h450_PickExeRes = -1;
static gint ett_h450_CpNotifyArg = -1;
static gint ett_h450_CpickupNotifyArg = -1;
static gint ett_h450_CallWaitingArg = -1;
static gint ett_h450_MWIActivateArg = -1;
static gint ett_h450_MwiDummyRes = -1;
static gint ett_h450_MWIDeactivateArg = -1;
static gint ett_h450_MWIInterrogateArg = -1;
static gint ett_h450_MWIInterrogateRes = -1;
static gint ett_h450_MWIInterrogateResElt = -1;
static gint ett_h450_MsgCentreId = -1;
static gint ett_h450_ExtensionArg = -1;
static gint ett_h450_NameArg = -1;
static gint ett_h450_Name = -1;
static gint ett_h450_NamePresentationAllowed = -1;
static gint ett_h450_NamePresentationRestricted = -1;
static gint ett_h450_CcRequestArg = -1;
static gint ett_h450_CcRequestRes = -1;
static gint ett_h450_CcArg = -1;
static gint ett_h450_CcShortArg = -1;
static gint ett_h450_CcLongArg = -1;
static gint ett_h450_CoReqOptArg = -1;
static gint ett_h450_RUAlertOptArg = -1;
static gint ett_h450_CfbOvrOptArg = -1;
static gint ett_h450_CIRequestArg = -1;
static gint ett_h450_CIRequestRes = -1;
static gint ett_h450_CIGetCIPLOptArg = -1;
static gint ett_h450_CIGetCIPLRes = -1;
static gint ett_h450_CIIsOptArg = -1;
static gint ett_h450_CIIsOptRes = -1;
static gint ett_h450_CIFrcRelArg = -1;
static gint ett_h450_CIFrcRelOptRes = -1;
static gint ett_h450_CIWobOptArg = -1;
static gint ett_h450_CIWobOptRes = -1;
static gint ett_h450_CISilentArg = -1;
static gint ett_h450_CISilentOptRes = -1;
static gint ett_h450_CINotificationArg = -1;
static gint ett_h450_CIStatusInformation = -1;
static gint ett_h450_CmnArg = -1;
static gint ett_h450_CmnRequestArg = -1;
static gint ett_h450_FeatureList = -1;
static gint ett_h450_FeatureValues = -1;
static gint ett_h450_FeatureControl = -1;
static gint ett_h450_Unspecified = -1;
static gint ett_h450_Extension = -1;

/*--- End of included file: packet-h450-ett.c ---*/
#line 210 "packet-h450-template.c"

/* Global variables */
static guint32 localOpcode;
static guint32 localErrorCode;
static const char *globalcode_oid_str;
static gboolean is_globalcode;

static const value_string localOpcode_vals[] = {
   /* H.450.2 Call Transfer opcodes */
   { CallTransferIdentify,    "callTransferIdentify"},
   { CallTransferAbandon,     "callTransferAbandon"},
   { CallTransferInitiate,    "callTransferInitiate"},
   { CallTransferSetup,       "callTransferSetup"},
   { CallTransferUpdate,      "callTransferUpdate"},
   { SubaddressTransfer,      "subaddressTransfer"},
   { CallTransferComplete,    "callTransferComplete"},
   { CallTransferActive,      "callTransferActive"},

   /* H.450.3 Call Diversion opcodes */
   { ActivateDiversionQ,      "activateDiversionQ"},
   { DeactivateDiversionQ,    "deactivateDiversionQ"},
   { InterrogateDiversionQ,   "interrogateDiversionQ"},
   { CheckRestriction,        "checkRestriction"},
   { CallRerouting,           "callRerouting"},
   { DivertingLegInformation1,"divertingLegInformation1"},
   { DivertingLegInformation2,"divertingLegInformation2"},
   { DivertingLegInformation3,"divertingLegInformation3"},
   { DivertingLegInformation4,"divertingLegInformation4"},
   { CfnrDivertedLegFailed,   "cfnrDivertedLegFailed"},

   /* H.450.4 Call Hold opcodes */
   { HoldNotific,             "holdNotific"},
   { RetrieveNotific,         "retrieveNotific"},
   { RemoteHold,              "remoteHold"},
   { RemoteRetrieve,          "remoteRetrieve"},

   /* H.450.5 Call Park and Pickup opcodes */
   { CpRequest,               "cpRequest"},
   { CpSetup,                 "cpSetup"},
   { GroupIndicationOn,       "groupIndicationOn"},
   { GroupIndicationOff,      "groupIndicationOff"},
   { Pickrequ,                "pickrequ"},
   { Pickup,                  "pickup"},
   { PickExe,                 "pickExe"},
   { CpNotify,                "cpNotify"},
   { CpickupNotify,           "cpickupNotify"},

   /* H.450.6 Call Waiting opcodes */
   { CallWaiting,             "callWaiting"},

   /* H.450.7 Message Waiting Indication constants */
   { MWIActivate,             "mwiActivate"},
   { MWIDeactivate,           "mwiDeactivate"},
   { MWIInterrogate,          "mwiInterrogate"}, 

   /* H.450.8 Name Identification constants */
   { NIcallingName,           "niCallingName"},
   { NIalertingName,          "niAlertingName"},
   { NIconnectedName,         "niConnectedName"},
   { NIbusyName,              "niBusyName"}, 

   /* H.450.9 Call Completion constants */
   { CCBSRequest,             "ccbsRequest"},
   { CCNRRequest,             "ccnrRequest"},
   { CCCancel,                "ccCancel"},
   { CCExecPossible,          "ccExecPossible"},
   { CCRingout,               "ccRingout"},
   { CCSuspend,               "ccSuspend"},
   { CCResume,                "ccResume"}, 

   /* H.450.10 Call Offer constants */
   { CallOfferRequest,        "callOfferRequest"},
   { RemoteUserAlerting,      "remoteUserAlerting"},
   { CFBOverride,             "cfbOverride"}, 

   /* H.450.11 Call Intrusion constants */
   { CallIntrusionRequest,      "callIntrusionRequest"},
   { CallIntrusionGetCIPL,      "callIntrusionGetCIPL"},
   { CallIntrusionIsolate,      "callIntrusionIsolate"},
   { CallIntrusionForcedRelease,"callIntrusionForcedRelease"},
   { CallIntrusionWOBRequest,   "callIntrusionWOBRequest"},
   { CallIntrusionSilentMonitor,"callIntrusionSilentMonitor"},
   { CallIntrusionNotification, "callIntrusionNotification"},

   /* TODO - add other H.450.x invoke opcodes here */
/* H.450.12 Common Information Operations constants */
   { CmnRequest,				"CmnRequest"},
   { CmnInform,					"CmnInform"},
	{  0, NULL }
};

static int dissect_h4501_argument(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree);
static int dissect_ros_ROSxxx(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree, int hf_ind _U_);




/*--- Included file: packet-h450-fn.c ---*/
#line 1 "packet-h450-fn.c"
/*--- Fields for imported types ---*/

static int dissect_rosApdus_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_ros_ROSxxx(tvb, offset, actx, tree, hf_h450_rosApdus_item);
}
static int dissect_numberUnscreened_presentationAllowedAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_PartyNumber(tvb, offset, actx, tree, hf_h450_numberUnscreened_presentationAllowedAddress);
}
static int dissect_numberUnscreened_presentationRestrictedAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_PartyNumber(tvb, offset, actx, tree, hf_h450_numberUnscreened_presentationRestrictedAddress);
}
static int dissect_partyNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_PartyNumber(tvb, offset, actx, tree, hf_h450_partyNumber);
}
static int dissect_screeningIndicator(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_ScreeningIndicator(tvb, offset, actx, tree, hf_h450_screeningIndicator);
}
static int dissect_destinationAddress_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_AliasAddress(tvb, offset, actx, tree, hf_h450_destinationAddress_item);
}
static int dissect_remoteExtensionAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_AliasAddress(tvb, offset, actx, tree, hf_h450_remoteExtensionAddress);
}
static int dissect_destinationAddressPresentationIndicator(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_PresentationIndicator(tvb, offset, actx, tree, hf_h450_destinationAddressPresentationIndicator);
}
static int dissect_destinationAddressScreeningIndicator(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_ScreeningIndicator(tvb, offset, actx, tree, hf_h450_destinationAddressScreeningIndicator);
}
static int dissect_remoteExtensionAddressPresentationIndicator(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_PresentationIndicator(tvb, offset, actx, tree, hf_h450_remoteExtensionAddressPresentationIndicator);
}
static int dissect_remoteExtensionAddressScreeningIndicator(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_ScreeningIndicator(tvb, offset, actx, tree, hf_h450_remoteExtensionAddressScreeningIndicator);
}
static int dissect_nonStandardData(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NonStandardParameter(tvb, offset, actx, tree, hf_h450_nonStandardData);
}
static int dissect_callPickupId(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_CallIdentifier(tvb, offset, actx, tree, hf_h450_callPickupId);
}
static int dissect_ccIdentifier(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_CallIdentifier(tvb, offset, actx, tree, hf_h450_ccIdentifier);
}
static int dissect_specificCall(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_CallIdentifier(tvb, offset, actx, tree, hf_h450_specificCall);
}
static int dissect_nonStandard(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NonStandardParameter(tvb, offset, actx, tree, hf_h450_nonStandard);
}



static int
dissect_h450_NULL(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_endpoint(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, actx, tree, hf_h450_endpoint);
}
static int dissect_anyEntity(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, actx, tree, hf_h450_anyEntity);
}
static int dissect_discardAnyUnrecognizedInvokePdu(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, actx, tree, hf_h450_discardAnyUnrecognizedInvokePdu);
}
static int dissect_clearCallIfAnyInvokePduNotRecognized(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, actx, tree, hf_h450_clearCallIfAnyInvokePduNotRecognized);
}
static int dissect_rejectAnyUnrecognizedInvokePdu(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, actx, tree, hf_h450_rejectAnyUnrecognizedInvokePdu);
}
static int dissect_presentationRestricted(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, actx, tree, hf_h450_presentationRestricted);
}
static int dissect_numberNotAvailableDueToInterworking(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, actx, tree, hf_h450_numberNotAvailableDueToInterworking);
}
static int dissect_nameNotAvailable(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, actx, tree, hf_h450_nameNotAvailable);
}
static int dissect_restrictedNull(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, actx, tree, hf_h450_restrictedNull);
}
static int dissect_silentMonitoringPermitted(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, actx, tree, hf_h450_silentMonitoringPermitted);
}
static int dissect_callIntrusionImpending(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, actx, tree, hf_h450_callIntrusionImpending);
}
static int dissect_callIntruded(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, actx, tree, hf_h450_callIntruded);
}
static int dissect_callIsolated(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, actx, tree, hf_h450_callIsolated);
}
static int dissect_callForceReleased(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, actx, tree, hf_h450_callForceReleased);
}
static int dissect_callIntrusionComplete(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, actx, tree, hf_h450_callIntrusionComplete);
}
static int dissect_callIntrusionEnd(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, actx, tree, hf_h450_callIntrusionEnd);
}
static int dissect_ssCFreRoutingSupported(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, actx, tree, hf_h450_ssCFreRoutingSupported);
}
static int dissect_ssCTreRoutingSupported(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, actx, tree, hf_h450_ssCTreRoutingSupported);
}
static int dissect_ssCCBSPossible(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, actx, tree, hf_h450_ssCCBSPossible);
}
static int dissect_ssCCNRPossible(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, actx, tree, hf_h450_ssCCNRPossible);
}
static int dissect_ssCOSupported(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, actx, tree, hf_h450_ssCOSupported);
}
static int dissect_ssCIForcedReleaseSupported(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, actx, tree, hf_h450_ssCIForcedReleaseSupported);
}
static int dissect_ssCIIsolationSupported(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, actx, tree, hf_h450_ssCIIsolationSupported);
}
static int dissect_ssCIWaitOnBusySupported(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, actx, tree, hf_h450_ssCIWaitOnBusySupported);
}
static int dissect_ssCISilentMonitoringSupported(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, actx, tree, hf_h450_ssCISilentMonitoringSupported);
}
static int dissect_ssCIConferenceSupported(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, actx, tree, hf_h450_ssCIConferenceSupported);
}
static int dissect_ssCHFarHoldSupported(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, actx, tree, hf_h450_ssCHFarHoldSupported);
}
static int dissect_ssMWICallbackSupported(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, actx, tree, hf_h450_ssMWICallbackSupported);
}
static int dissect_ssCPCallParkSupported(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, actx, tree, hf_h450_ssCPCallParkSupported);
}
static int dissect_ssCHDoNotHold(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, actx, tree, hf_h450_ssCHDoNotHold);
}
static int dissect_ssCTDoNotTransfer(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, actx, tree, hf_h450_ssCTDoNotTransfer);
}
static int dissect_ssMWICallbackCall(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, actx, tree, hf_h450_ssMWICallbackCall);
}
static int dissect_ssCISilentMonitorPermitted(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, actx, tree, hf_h450_ssCISilentMonitorPermitted);
}


static const value_string h450_EntityType_vals[] = {
  {   0, "endpoint" },
  {   1, "anyEntity" },
  { 0, NULL }
};

static const per_choice_t EntityType_choice[] = {
  {   0, "endpoint"                    , ASN1_EXTENSION_ROOT    , dissect_endpoint },
  {   1, "anyEntity"                   , ASN1_EXTENSION_ROOT    , dissect_anyEntity },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_EntityType(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_EntityType, EntityType_choice,
                                 NULL);

  return offset;
}
static int dissect_sourceEntity(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_EntityType(tvb, offset, actx, tree, hf_h450_sourceEntity);
}
static int dissect_destinationEntity(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_EntityType(tvb, offset, actx, tree, hf_h450_destinationEntity);
}



static int
dissect_h450_AddressInformation(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_h225_AliasAddress(tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_sourceEntityAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_AddressInformation(tvb, offset, actx, tree, hf_h450_sourceEntityAddress);
}
static int dissect_destinationEntityAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_AddressInformation(tvb, offset, actx, tree, hf_h450_destinationEntityAddress);
}


static const per_sequence_t NetworkFacilityExtension_sequence[] = {
  { "sourceEntity"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sourceEntity },
  { "sourceEntityAddress"         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sourceEntityAddress },
  { "destinationEntity"           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_destinationEntity },
  { "destinationEntityAddress"    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_destinationEntityAddress },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_NetworkFacilityExtension(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_NetworkFacilityExtension, NetworkFacilityExtension_sequence);

  return offset;
}
static int dissect_networkFacilityExtension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NetworkFacilityExtension(tvb, offset, actx, tree, hf_h450_networkFacilityExtension);
}


static const value_string h450_InterpretationApdu_vals[] = {
  {   0, "discardAnyUnrecognizedInvokePdu" },
  {   1, "clearCallIfAnyInvokePduNotRecognized" },
  {   2, "rejectAnyUnrecognizedInvokePdu" },
  { 0, NULL }
};

static const per_choice_t InterpretationApdu_choice[] = {
  {   0, "discardAnyUnrecognizedInvokePdu", ASN1_EXTENSION_ROOT    , dissect_discardAnyUnrecognizedInvokePdu },
  {   1, "clearCallIfAnyInvokePduNotRecognized", ASN1_EXTENSION_ROOT    , dissect_clearCallIfAnyInvokePduNotRecognized },
  {   2, "rejectAnyUnrecognizedInvokePdu", ASN1_EXTENSION_ROOT    , dissect_rejectAnyUnrecognizedInvokePdu },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_InterpretationApdu(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_InterpretationApdu, InterpretationApdu_choice,
                                 NULL);

  return offset;
}
static int dissect_interpretationApdu(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_InterpretationApdu(tvb, offset, actx, tree, hf_h450_interpretationApdu);
}


static const per_sequence_t SEQUENCE_OF_ROSxxx_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rosApdus_item },
};

static int
dissect_h450_SEQUENCE_OF_ROSxxx(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h450_SEQUENCE_OF_ROSxxx, SEQUENCE_OF_ROSxxx_sequence_of);

  return offset;
}
static int dissect_rosApdus(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_OF_ROSxxx(tvb, offset, actx, tree, hf_h450_rosApdus);
}


static const value_string h450_ServiceApdus_vals[] = {
  {   0, "rosApdus" },
  { 0, NULL }
};

static const per_choice_t ServiceApdus_choice[] = {
  {   0, "rosApdus"                    , ASN1_EXTENSION_ROOT    , dissect_rosApdus },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_ServiceApdus(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_ServiceApdus, ServiceApdus_choice,
                                 NULL);

  return offset;
}
static int dissect_serviceApdu(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_ServiceApdus(tvb, offset, actx, tree, hf_h450_serviceApdu);
}


static const per_sequence_t H4501SupplementaryService_sequence[] = {
  { "networkFacilityExtension"    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_networkFacilityExtension },
  { "interpretationApdu"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_interpretationApdu },
  { "serviceApdu"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_serviceApdu },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_H4501SupplementaryService(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_H4501SupplementaryService, H4501SupplementaryService_sequence);

  return offset;
}



static int
dissect_h450_Notassignedlocalopcode(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, NULL);

  return offset;
}



static int
dissect_h450_SubaddressInformation(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 20, NULL);

  return offset;
}
static int dissect_subaddressInformation(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SubaddressInformation(tvb, offset, actx, tree, hf_h450_subaddressInformation);
}



static int
dissect_h450_BOOLEAN(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}
static int dissect_oddCountIndicator(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_BOOLEAN(tvb, offset, actx, tree, hf_h450_oddCountIndicator);
}
static int dissect_remoteEnabled(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_BOOLEAN(tvb, offset, actx, tree, hf_h450_remoteEnabled);
}
static int dissect_callbackReq(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_BOOLEAN(tvb, offset, actx, tree, hf_h450_callbackReq);
}
static int dissect_can_retain_service(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_BOOLEAN(tvb, offset, actx, tree, hf_h450_can_retain_service);
}
static int dissect_retain_sig_connection(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_BOOLEAN(tvb, offset, actx, tree, hf_h450_retain_sig_connection);
}
static int dissect_retain_service(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_BOOLEAN(tvb, offset, actx, tree, hf_h450_retain_service);
}


static const per_sequence_t UserSpecifiedSubaddress_sequence[] = {
  { "subaddressInformation"       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_subaddressInformation },
  { "oddCountIndicator"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_oddCountIndicator },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_UserSpecifiedSubaddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_UserSpecifiedSubaddress, UserSpecifiedSubaddress_sequence);

  return offset;
}
static int dissect_userSpecifiedSubaddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_UserSpecifiedSubaddress(tvb, offset, actx, tree, hf_h450_userSpecifiedSubaddress);
}



static int
dissect_h450_NSAPSubaddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 20, NULL);

  return offset;
}
static int dissect_nsapSubaddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NSAPSubaddress(tvb, offset, actx, tree, hf_h450_nsapSubaddress);
}


static const value_string h450_PartySubaddress_vals[] = {
  {   0, "userSpecifiedSubaddress" },
  {   1, "nsapSubaddress" },
  { 0, NULL }
};

static const per_choice_t PartySubaddress_choice[] = {
  {   0, "userSpecifiedSubaddress"     , ASN1_EXTENSION_ROOT    , dissect_userSpecifiedSubaddress },
  {   1, "nsapSubaddress"              , ASN1_EXTENSION_ROOT    , dissect_nsapSubaddress },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_PartySubaddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_PartySubaddress, PartySubaddress_choice,
                                 NULL);

  return offset;
}
static int dissect_partySubaddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_PartySubaddress(tvb, offset, actx, tree, hf_h450_partySubaddress);
}
static int dissect_redirectionSubaddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_PartySubaddress(tvb, offset, actx, tree, hf_h450_redirectionSubaddress);
}
static int dissect_callingPartySubaddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_PartySubaddress(tvb, offset, actx, tree, hf_h450_callingPartySubaddress);
}


static const per_sequence_t AddressScreened_sequence[] = {
  { "partyNumber"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_partyNumber },
  { "screeningIndicator"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_screeningIndicator },
  { "partySubaddress"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_partySubaddress },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_AddressScreened(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_AddressScreened, AddressScreened_sequence);

  return offset;
}
static int dissect_addressScreened_presentationAllowedAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_AddressScreened(tvb, offset, actx, tree, hf_h450_addressScreened_presentationAllowedAddress);
}
static int dissect_addressScreened_presentationRestrictedAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_AddressScreened(tvb, offset, actx, tree, hf_h450_addressScreened_presentationRestrictedAddress);
}


static const value_string h450_PresentedAddressScreened_vals[] = {
  {   0, "presentationAllowedAddress" },
  {   1, "presentationRestricted" },
  {   2, "numberNotAvailableDueToInterworking" },
  {   3, "presentationRestrictedAddress" },
  { 0, NULL }
};

static const per_choice_t PresentedAddressScreened_choice[] = {
  {   0, "presentationAllowedAddress"  , ASN1_EXTENSION_ROOT    , dissect_addressScreened_presentationAllowedAddress },
  {   1, "presentationRestricted"      , ASN1_EXTENSION_ROOT    , dissect_presentationRestricted },
  {   2, "numberNotAvailableDueToInterworking", ASN1_EXTENSION_ROOT    , dissect_numberNotAvailableDueToInterworking },
  {   3, "presentationRestrictedAddress", ASN1_EXTENSION_ROOT    , dissect_addressScreened_presentationRestrictedAddress },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_PresentedAddressScreened(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_PresentedAddressScreened, PresentedAddressScreened_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t Address_sequence[] = {
  { "partyNumber"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_partyNumber },
  { "partySubaddress"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_partySubaddress },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_Address(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_Address, Address_sequence);

  return offset;
}
static int dissect_addressUnscreened_presentationAllowedAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_Address(tvb, offset, actx, tree, hf_h450_addressUnscreened_presentationAllowedAddress);
}
static int dissect_addressUnscreened_presentationRestrictedAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_Address(tvb, offset, actx, tree, hf_h450_addressUnscreened_presentationRestrictedAddress);
}


static const value_string h450_PresentedAddressUnscreened_vals[] = {
  {   0, "presentationAllowedAddress" },
  {   1, "presentationRestricted" },
  {   2, "numberNotAvailableDueToInterworking" },
  {   3, "presentationRestrictedAddress" },
  { 0, NULL }
};

static const per_choice_t PresentedAddressUnscreened_choice[] = {
  {   0, "presentationAllowedAddress"  , ASN1_EXTENSION_ROOT    , dissect_addressUnscreened_presentationAllowedAddress },
  {   1, "presentationRestricted"      , ASN1_EXTENSION_ROOT    , dissect_presentationRestricted },
  {   2, "numberNotAvailableDueToInterworking", ASN1_EXTENSION_ROOT    , dissect_numberNotAvailableDueToInterworking },
  {   3, "presentationRestrictedAddress", ASN1_EXTENSION_ROOT    , dissect_addressUnscreened_presentationRestrictedAddress },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_PresentedAddressUnscreened(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_PresentedAddressUnscreened, PresentedAddressUnscreened_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t NumberScreened_sequence[] = {
  { "partyNumber"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_partyNumber },
  { "screeningIndicator"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_screeningIndicator },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_NumberScreened(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_NumberScreened, NumberScreened_sequence);

  return offset;
}
static int dissect_numberScreened_presentationAllowedAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NumberScreened(tvb, offset, actx, tree, hf_h450_numberScreened_presentationAllowedAddress);
}
static int dissect_numberScreened_presentationRestrictedAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NumberScreened(tvb, offset, actx, tree, hf_h450_numberScreened_presentationRestrictedAddress);
}


static const value_string h450_PresentedNumberScreened_vals[] = {
  {   0, "presentationAllowedAddress" },
  {   1, "presentationRestricted" },
  {   2, "numberNotAvailableDueToInterworking" },
  {   3, "presentationRestrictedAddress" },
  { 0, NULL }
};

static const per_choice_t PresentedNumberScreened_choice[] = {
  {   0, "presentationAllowedAddress"  , ASN1_EXTENSION_ROOT    , dissect_numberScreened_presentationAllowedAddress },
  {   1, "presentationRestricted"      , ASN1_EXTENSION_ROOT    , dissect_presentationRestricted },
  {   2, "numberNotAvailableDueToInterworking", ASN1_EXTENSION_ROOT    , dissect_numberNotAvailableDueToInterworking },
  {   3, "presentationRestrictedAddress", ASN1_EXTENSION_ROOT    , dissect_numberScreened_presentationRestrictedAddress },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_PresentedNumberScreened(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_PresentedNumberScreened, PresentedNumberScreened_choice,
                                 NULL);

  return offset;
}


static const value_string h450_PresentedNumberUnscreened_vals[] = {
  {   0, "presentationAllowedAddress" },
  {   1, "presentationRestricted" },
  {   2, "numberNotAvailableDueToInterworking" },
  {   3, "presentationRestrictedAddress" },
  { 0, NULL }
};

static const per_choice_t PresentedNumberUnscreened_choice[] = {
  {   0, "presentationAllowedAddress"  , ASN1_EXTENSION_ROOT    , dissect_numberUnscreened_presentationAllowedAddress },
  {   1, "presentationRestricted"      , ASN1_EXTENSION_ROOT    , dissect_presentationRestricted },
  {   2, "numberNotAvailableDueToInterworking", ASN1_EXTENSION_ROOT    , dissect_numberNotAvailableDueToInterworking },
  {   3, "presentationRestrictedAddress", ASN1_EXTENSION_ROOT    , dissect_numberUnscreened_presentationRestrictedAddress },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_PresentedNumberUnscreened(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_PresentedNumberUnscreened, PresentedNumberUnscreened_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_AliasAddress_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_destinationAddress_item },
};

static int
dissect_h450_SEQUENCE_OF_AliasAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h450_SEQUENCE_OF_AliasAddress, SEQUENCE_OF_AliasAddress_sequence_of);

  return offset;
}
static int dissect_destinationAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_OF_AliasAddress(tvb, offset, actx, tree, hf_h450_destinationAddress);
}


static const per_sequence_t EndpointAddress_sequence[] = {
  { "destinationAddress"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_destinationAddress },
  { "remoteExtensionAddress"      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_remoteExtensionAddress },
  { "destinationAddressPresentationIndicator", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_destinationAddressPresentationIndicator },
  { "destinationAddressScreeningIndicator", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_destinationAddressScreeningIndicator },
  { "remoteExtensionAddressPresentationIndicator", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_remoteExtensionAddressPresentationIndicator },
  { "remoteExtensionAddressScreeningIndicator", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_remoteExtensionAddressScreeningIndicator },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_EndpointAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_EndpointAddress, EndpointAddress_sequence);

  return offset;
}
static int dissect_reroutingNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_EndpointAddress(tvb, offset, actx, tree, hf_h450_reroutingNumber);
}
static int dissect_transferringNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_EndpointAddress(tvb, offset, actx, tree, hf_h450_transferringNumber);
}
static int dissect_redirectionNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_EndpointAddress(tvb, offset, actx, tree, hf_h450_redirectionNumber);
}
static int dissect_connectedAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_EndpointAddress(tvb, offset, actx, tree, hf_h450_connectedAddress);
}
static int dissect_divertedToAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_EndpointAddress(tvb, offset, actx, tree, hf_h450_divertedToAddress);
}
static int dissect_servedUserNr(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_EndpointAddress(tvb, offset, actx, tree, hf_h450_servedUserNr);
}
static int dissect_activatingUserNr(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_EndpointAddress(tvb, offset, actx, tree, hf_h450_activatingUserNr);
}
static int dissect_deactivatingUserNr(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_EndpointAddress(tvb, offset, actx, tree, hf_h450_deactivatingUserNr);
}
static int dissect_interrogatingUserNr(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_EndpointAddress(tvb, offset, actx, tree, hf_h450_interrogatingUserNr);
}
static int dissect_divertedToNr(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_EndpointAddress(tvb, offset, actx, tree, hf_h450_divertedToNr);
}
static int dissect_calledAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_EndpointAddress(tvb, offset, actx, tree, hf_h450_calledAddress);
}
static int dissect_lastReroutingNr(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_EndpointAddress(tvb, offset, actx, tree, hf_h450_lastReroutingNr);
}
static int dissect_callingNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_EndpointAddress(tvb, offset, actx, tree, hf_h450_callingNumber);
}
static int dissect_originalCalledNr(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_EndpointAddress(tvb, offset, actx, tree, hf_h450_originalCalledNr);
}
static int dissect_nominatedNr(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_EndpointAddress(tvb, offset, actx, tree, hf_h450_nominatedNr);
}
static int dissect_redirectingNr(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_EndpointAddress(tvb, offset, actx, tree, hf_h450_redirectingNr);
}
static int dissect_divertingNr(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_EndpointAddress(tvb, offset, actx, tree, hf_h450_divertingNr);
}
static int dissect_redirectionNr(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_EndpointAddress(tvb, offset, actx, tree, hf_h450_redirectionNr);
}
static int dissect_callingNr(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_EndpointAddress(tvb, offset, actx, tree, hf_h450_callingNr);
}
static int dissect_parkingNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_EndpointAddress(tvb, offset, actx, tree, hf_h450_parkingNumber);
}
static int dissect_parkedNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_EndpointAddress(tvb, offset, actx, tree, hf_h450_parkedNumber);
}
static int dissect_parkedToNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_EndpointAddress(tvb, offset, actx, tree, hf_h450_parkedToNumber);
}
static int dissect_groupMemberUserNr(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_EndpointAddress(tvb, offset, actx, tree, hf_h450_groupMemberUserNr);
}
static int dissect_partyToRetrieve(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_EndpointAddress(tvb, offset, actx, tree, hf_h450_partyToRetrieve);
}
static int dissect_retrieveAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_EndpointAddress(tvb, offset, actx, tree, hf_h450_retrieveAddress);
}
static int dissect_picking_upNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_EndpointAddress(tvb, offset, actx, tree, hf_h450_picking_upNumber);
}
static int dissect_originatingNr(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_EndpointAddress(tvb, offset, actx, tree, hf_h450_originatingNr);
}
static int dissect_mwipartyNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_EndpointAddress(tvb, offset, actx, tree, hf_h450_mwipartyNumber);
}
static int dissect_numberA(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_EndpointAddress(tvb, offset, actx, tree, hf_h450_numberA);
}
static int dissect_numberB(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_EndpointAddress(tvb, offset, actx, tree, hf_h450_numberB);
}



static int
dissect_h450_PresentationAllowedIndicator(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}
static int dissect_presentationAllowedIndicator(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_PresentationAllowedIndicator(tvb, offset, actx, tree, hf_h450_presentationAllowedIndicator);
}



static int
dissect_h450_OBJECT_IDENTIFIER(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_object_identifier(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}
static int dissect_extensionId(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_OBJECT_IDENTIFIER(tvb, offset, actx, tree, hf_h450_extensionId);
}



static int
dissect_h450_ExtensionArgument(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, NULL);

  return offset;
}
static int dissect_extensionArgument(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_ExtensionArgument(tvb, offset, actx, tree, hf_h450_extensionArgument);
}


static const per_sequence_t Extension_sequence[] = {
  { "extensionId"                 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_extensionId },
  { "extensionArgument"           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_extensionArgument },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_Extension(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_Extension, Extension_sequence);

  return offset;
}
static int dissect_ExtensionSeq_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_Extension(tvb, offset, actx, tree, hf_h450_ExtensionSeq_item);
}
static int dissect_mixedExtension_extension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_Extension(tvb, offset, actx, tree, hf_h450_mixedExtension_extension);
}
static int dissect_unspecified_extension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_Extension(tvb, offset, actx, tree, hf_h450_unspecified_extension);
}


static const per_sequence_t ExtensionSeq_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ExtensionSeq_item },
};

static int
dissect_h450_ExtensionSeq(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h450_ExtensionSeq, ExtensionSeq_sequence_of);

  return offset;
}
static int dissect_extensionSeq(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_ExtensionSeq(tvb, offset, actx, tree, hf_h450_extensionSeq);
}


static const value_string h450_DummyArg_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t DummyArg_choice[] = {
  {   0, "extensionSeq"                , ASN1_NO_EXTENSIONS     , dissect_extensionSeq },
  {   1, "nonStandardData"             , ASN1_NO_EXTENSIONS     , dissect_nonStandardData },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_DummyArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_DummyArg, DummyArg_choice,
                                 NULL);

  return offset;
}



static int
dissect_h450_CallTransferIdentify(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_h450_DummyArg(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_h450_CallTransferAbandon(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_h450_DummyArg(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_h450_CallIdentity(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_NumericString(tvb, offset, actx, tree, hf_index,
                                          0, 4);

  return offset;
}
static int dissect_callIdentity(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_CallIdentity(tvb, offset, actx, tree, hf_h450_callIdentity);
}


static const value_string h450_ArgumentExtension_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t ArgumentExtension_choice[] = {
  {   0, "extensionSeq"                , ASN1_NO_EXTENSIONS     , dissect_extensionSeq },
  {   1, "nonStandardData"             , ASN1_NO_EXTENSIONS     , dissect_nonStandardData },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_ArgumentExtension(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_ArgumentExtension, ArgumentExtension_choice,
                                 NULL);

  return offset;
}
static int dissect_cTInitiateArg_argumentExtension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_ArgumentExtension(tvb, offset, actx, tree, hf_h450_cTInitiateArg_argumentExtension);
}
static int dissect_cTSetupArg_argumentExtension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_ArgumentExtension(tvb, offset, actx, tree, hf_h450_cTSetupArg_argumentExtension);
}
static int dissect_cTUpdateArg_argumentExtension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_ArgumentExtension(tvb, offset, actx, tree, hf_h450_cTUpdateArg_argumentExtension);
}
static int dissect_subaddressTransferArg_argumentExtension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_ArgumentExtension(tvb, offset, actx, tree, hf_h450_subaddressTransferArg_argumentExtension);
}
static int dissect_cTCompleteArg_argumentExtension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_ArgumentExtension(tvb, offset, actx, tree, hf_h450_cTCompleteArg_argumentExtension);
}
static int dissect_cTActiveArg_argumentExtension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_ArgumentExtension(tvb, offset, actx, tree, hf_h450_cTActiveArg_argumentExtension);
}


static const per_sequence_t CTInitiateArg_sequence[] = {
  { "callIdentity"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_callIdentity },
  { "reroutingNumber"             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_reroutingNumber },
  { "argumentExtension"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cTInitiateArg_argumentExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CTInitiateArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_CTInitiateArg, CTInitiateArg_sequence);

  return offset;
}



static int
dissect_h450_CallTransferInitiate(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_h450_CTInitiateArg(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t CTSetupArg_sequence[] = {
  { "callIdentity"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_callIdentity },
  { "transferringNumber"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_transferringNumber },
  { "argumentExtension"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cTSetupArg_argumentExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CTSetupArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_CTSetupArg, CTSetupArg_sequence);

  return offset;
}



static int
dissect_h450_CallTransferSetup(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_h450_CTSetupArg(tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_h450_BMPString_SIZE_1_128(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_BMPString(tvb, offset, actx, tree, hf_index,
                                          1, 128);

  return offset;
}
static int dissect_redirectionInfo(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_BMPString_SIZE_1_128(tvb, offset, actx, tree, hf_h450_redirectionInfo);
}
static int dissect_connectedInfo(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_BMPString_SIZE_1_128(tvb, offset, actx, tree, hf_h450_connectedInfo);
}
static int dissect_callingInfo(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_BMPString_SIZE_1_128(tvb, offset, actx, tree, hf_h450_callingInfo);
}
static int dissect_redirectingInfo(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_BMPString_SIZE_1_128(tvb, offset, actx, tree, hf_h450_redirectingInfo);
}
static int dissect_originalCalledInfo(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_BMPString_SIZE_1_128(tvb, offset, actx, tree, hf_h450_originalCalledInfo);
}
static int dissect_nominatedInfo(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_BMPString_SIZE_1_128(tvb, offset, actx, tree, hf_h450_nominatedInfo);
}



static int
dissect_h450_H225InformationElement(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, NULL);

  return offset;
}
static int dissect_basicCallInfoElements(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_H225InformationElement(tvb, offset, actx, tree, hf_h450_basicCallInfoElements);
}
static int dissect_h225InfoElement(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_H225InformationElement(tvb, offset, actx, tree, hf_h450_h225InfoElement);
}


static const per_sequence_t CTUpdateArg_sequence[] = {
  { "redirectionNumber"           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_redirectionNumber },
  { "redirectionInfo"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_redirectionInfo },
  { "basicCallInfoElements"       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_basicCallInfoElements },
  { "argumentExtension"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cTUpdateArg_argumentExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CTUpdateArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_CTUpdateArg, CTUpdateArg_sequence);

  return offset;
}



static int
dissect_h450_CallTransferUpdate(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_h450_CTUpdateArg(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t SubaddressTransferArg_sequence[] = {
  { "redirectionSubaddress"       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_redirectionSubaddress },
  { "argumentExtension"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_subaddressTransferArg_argumentExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_SubaddressTransferArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_SubaddressTransferArg, SubaddressTransferArg_sequence);

  return offset;
}



static int
dissect_h450_SubaddressTransfer(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_h450_SubaddressTransferArg(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string h450_EndDesignation_vals[] = {
  {   0, "primaryEnd" },
  {   1, "secondaryEnd" },
  { 0, NULL }
};


static int
dissect_h450_EndDesignation(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_endDesignation(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_EndDesignation(tvb, offset, actx, tree, hf_h450_endDesignation);
}


static const value_string h450_CallStatus_vals[] = {
  {   0, "answered" },
  {   1, "alerting" },
  { 0, NULL }
};


static int
dissect_h450_CallStatus(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_callStatus(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_CallStatus(tvb, offset, actx, tree, hf_h450_callStatus);
}


static const per_sequence_t CTCompleteArg_sequence[] = {
  { "endDesignation"              , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_endDesignation },
  { "redirectionNumber"           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_redirectionNumber },
  { "basicCallInfoElements"       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_basicCallInfoElements },
  { "redirectionInfo"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_redirectionInfo },
  { "callStatus"                  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_callStatus },
  { "argumentExtension"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cTCompleteArg_argumentExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CTCompleteArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_CTCompleteArg, CTCompleteArg_sequence);

  return offset;
}



static int
dissect_h450_CallTransferComplete(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_h450_CTCompleteArg(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t CTActiveArg_sequence[] = {
  { "connectedAddress"            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_connectedAddress },
  { "basicCallInfoElements"       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_basicCallInfoElements },
  { "connectedInfo"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_connectedInfo },
  { "argumentExtension"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cTActiveArg_argumentExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CTActiveArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_CTActiveArg, CTActiveArg_sequence);

  return offset;
}



static int
dissect_h450_CallTransferActive(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_h450_CTActiveArg(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string h450_DummyRes_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t DummyRes_choice[] = {
  {   0, "extensionSeq"                , ASN1_NO_EXTENSIONS     , dissect_extensionSeq },
  {   1, "nonStandardData"             , ASN1_NO_EXTENSIONS     , dissect_nonStandardData },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_DummyRes(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_DummyRes, DummyRes_choice,
                                 NULL);

  return offset;
}


static const value_string h450_T_resultExtension_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t T_resultExtension_choice[] = {
  {   0, "extensionSeq"                , ASN1_NO_EXTENSIONS     , dissect_extensionSeq },
  {   1, "nonStandardData"             , ASN1_NO_EXTENSIONS     , dissect_nonStandardData },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_T_resultExtension(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_T_resultExtension, T_resultExtension_choice,
                                 NULL);

  return offset;
}
static int dissect_resultExtension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_T_resultExtension(tvb, offset, actx, tree, hf_h450_resultExtension);
}


static const per_sequence_t CTIdentifyRes_sequence[] = {
  { "callIdentity"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_callIdentity },
  { "reroutingNumber"             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_reroutingNumber },
  { "resultExtension"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_resultExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CTIdentifyRes(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_CTIdentifyRes, CTIdentifyRes_sequence);

  return offset;
}


static const value_string h450_Procedure_vals[] = {
  {   0, "cfu" },
  {   1, "cfb" },
  {   2, "cfnr" },
  { 0, NULL }
};


static int
dissect_h450_Procedure(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_procedure(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_Procedure(tvb, offset, actx, tree, hf_h450_procedure);
}


static const value_string h450_BasicService_vals[] = {
  {   0, "allServices" },
  {   1, "speech" },
  {   2, "unrestrictedDigitalInformation" },
  {   3, "audio3100Hz" },
  {  32, "telephony" },
  {  33, "teletex" },
  {  34, "telefaxGroup4Class1" },
  {  35, "videotexSyntaxBased" },
  {  36, "videotelephony" },
  {  37, "telefaxGroup2-3" },
  {  38, "reservedNotUsed1" },
  {  39, "reservedNotUsed2" },
  {  40, "reservedNotUsed3" },
  {  41, "reservedNotUsed4" },
  {  42, "reservedNotUsed5" },
  {  51, "email" },
  {  52, "video" },
  {  53, "fileTransfer" },
  {  54, "shortMessageService" },
  {  55, "speechAndVideo" },
  {  56, "speechAndFax" },
  {  57, "speechAndEmail" },
  {  58, "videoAndFax" },
  {  59, "videoAndEmail" },
  {  60, "faxAndEmail" },
  {  61, "speechVideoAndFax" },
  {  62, "speechVideoAndEmail" },
  {  63, "speechFaxAndEmail" },
  {  64, "videoFaxAndEmail" },
  {  65, "speechVideoFaxAndEmail" },
  {  66, "multimediaUnknown" },
  {  67, "serviceUnknown" },
  {  68, "futureReserve1" },
  {  69, "futureReserve2" },
  {  70, "futureReserve3" },
  {  71, "futureReserve4" },
  {  72, "futureReserve5" },
  {  73, "futureReserve6" },
  {  74, "futureReserve7" },
  {  75, "futureReserve8" },
  { 0, NULL }
};

static guint32 BasicService_value_map[40+0] = {0, 1, 2, 3, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75};

static int
dissect_h450_BasicService(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     40, NULL, FALSE, 0, BasicService_value_map);

  return offset;
}
static int dissect_basicService(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_BasicService(tvb, offset, actx, tree, hf_h450_basicService);
}
static int dissect_service(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_BasicService(tvb, offset, actx, tree, hf_h450_service);
}


static const value_string h450_ActivateDiversionQArg_extension_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t ActivateDiversionQArg_extension_choice[] = {
  {   0, "extensionSeq"                , ASN1_NO_EXTENSIONS     , dissect_extensionSeq },
  {   1, "nonStandardData"             , ASN1_NO_EXTENSIONS     , dissect_nonStandardData },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_ActivateDiversionQArg_extension(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_ActivateDiversionQArg_extension, ActivateDiversionQArg_extension_choice,
                                 NULL);

  return offset;
}
static int dissect_activateDiversionQArg_extension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_ActivateDiversionQArg_extension(tvb, offset, actx, tree, hf_h450_activateDiversionQArg_extension);
}


static const per_sequence_t ActivateDiversionQArg_sequence[] = {
  { "procedure"                   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_procedure },
  { "basicService"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_basicService },
  { "divertedToAddress"           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_divertedToAddress },
  { "servedUserNr"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_servedUserNr },
  { "activatingUserNr"            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_activatingUserNr },
  { "extension"                   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_activateDiversionQArg_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_ActivateDiversionQArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_ActivateDiversionQArg, ActivateDiversionQArg_sequence);

  return offset;
}


static const value_string h450_ActivateDiversionQRes_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t ActivateDiversionQRes_choice[] = {
  {   0, "extensionSeq"                , ASN1_NO_EXTENSIONS     , dissect_extensionSeq },
  {   1, "nonStandardData"             , ASN1_NO_EXTENSIONS     , dissect_nonStandardData },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_ActivateDiversionQRes(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_ActivateDiversionQRes, ActivateDiversionQRes_choice,
                                 NULL);

  return offset;
}


static const value_string h450_DeactivateDiversionQArg_extension_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t DeactivateDiversionQArg_extension_choice[] = {
  {   0, "extensionSeq"                , ASN1_NO_EXTENSIONS     , dissect_extensionSeq },
  {   1, "nonStandardData"             , ASN1_NO_EXTENSIONS     , dissect_nonStandardData },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_DeactivateDiversionQArg_extension(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_DeactivateDiversionQArg_extension, DeactivateDiversionQArg_extension_choice,
                                 NULL);

  return offset;
}
static int dissect_deactivateDiversionQArg_extension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_DeactivateDiversionQArg_extension(tvb, offset, actx, tree, hf_h450_deactivateDiversionQArg_extension);
}


static const per_sequence_t DeactivateDiversionQArg_sequence[] = {
  { "procedure"                   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_procedure },
  { "basicService"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_basicService },
  { "servedUserNr"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_servedUserNr },
  { "deactivatingUserNr"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_deactivatingUserNr },
  { "extension"                   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_deactivateDiversionQArg_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_DeactivateDiversionQArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_DeactivateDiversionQArg, DeactivateDiversionQArg_sequence);

  return offset;
}


static const value_string h450_DeactivateDiversionQRes_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t DeactivateDiversionQRes_choice[] = {
  {   0, "extensionSeq"                , ASN1_NO_EXTENSIONS     , dissect_extensionSeq },
  {   1, "nonStandardData"             , ASN1_NO_EXTENSIONS     , dissect_nonStandardData },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_DeactivateDiversionQRes(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_DeactivateDiversionQRes, DeactivateDiversionQRes_choice,
                                 NULL);

  return offset;
}


static const value_string h450_InterrogateDiversionQ_extension_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t InterrogateDiversionQ_extension_choice[] = {
  {   0, "extensionSeq"                , ASN1_NO_EXTENSIONS     , dissect_extensionSeq },
  {   1, "nonStandardData"             , ASN1_NO_EXTENSIONS     , dissect_nonStandardData },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_InterrogateDiversionQ_extension(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_InterrogateDiversionQ_extension, InterrogateDiversionQ_extension_choice,
                                 NULL);

  return offset;
}
static int dissect_interrogateDiversionQ_extension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_InterrogateDiversionQ_extension(tvb, offset, actx, tree, hf_h450_interrogateDiversionQ_extension);
}


static const per_sequence_t InterrogateDiversionQ_sequence[] = {
  { "procedure"                   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_procedure },
  { "basicService"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_basicService },
  { "servedUserNr"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_servedUserNr },
  { "interrogatingUserNr"         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_interrogatingUserNr },
  { "extension"                   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_interrogateDiversionQ_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_InterrogateDiversionQ(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_InterrogateDiversionQ, InterrogateDiversionQ_sequence);

  return offset;
}


static const value_string h450_IntResult_extension_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t IntResult_extension_choice[] = {
  {   0, "extensionSeq"                , ASN1_NO_EXTENSIONS     , dissect_extensionSeq },
  {   1, "nonStandardData"             , ASN1_NO_EXTENSIONS     , dissect_nonStandardData },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_IntResult_extension(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_IntResult_extension, IntResult_extension_choice,
                                 NULL);

  return offset;
}
static int dissect_intResult_extension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_IntResult_extension(tvb, offset, actx, tree, hf_h450_intResult_extension);
}


static const per_sequence_t IntResult_sequence[] = {
  { "servedUserNr"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_servedUserNr },
  { "basicService"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_basicService },
  { "procedure"                   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_procedure },
  { "divertedToAddress"           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_divertedToAddress },
  { "remoteEnabled"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_remoteEnabled },
  { "extension"                   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_intResult_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_IntResult(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_IntResult, IntResult_sequence);

  return offset;
}
static int dissect_IntResultList_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_IntResult(tvb, offset, actx, tree, hf_h450_IntResultList_item);
}


static const per_sequence_t IntResultList_set_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_IntResultList_item },
};

static int
dissect_h450_IntResultList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_set_of(tvb, offset, actx, tree, hf_index,
                                             ett_h450_IntResultList, IntResultList_set_of,
                                             0, 29);

  return offset;
}



static int
dissect_h450_InterrogateDiversionQRes(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_h450_IntResultList(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string h450_CheckRestrictionArg_extension_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t CheckRestrictionArg_extension_choice[] = {
  {   0, "extensionSeq"                , ASN1_NO_EXTENSIONS     , dissect_extensionSeq },
  {   1, "nonStandardData"             , ASN1_NO_EXTENSIONS     , dissect_nonStandardData },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_CheckRestrictionArg_extension(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_CheckRestrictionArg_extension, CheckRestrictionArg_extension_choice,
                                 NULL);

  return offset;
}
static int dissect_checkRestrictionArg_extension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_CheckRestrictionArg_extension(tvb, offset, actx, tree, hf_h450_checkRestrictionArg_extension);
}


static const per_sequence_t CheckRestrictionArg_sequence[] = {
  { "servedUserNr"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_servedUserNr },
  { "basicService"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_basicService },
  { "divertedToNr"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_divertedToNr },
  { "extension"                   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_checkRestrictionArg_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CheckRestrictionArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_CheckRestrictionArg, CheckRestrictionArg_sequence);

  return offset;
}


static const value_string h450_CheckRestrictionRes_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t CheckRestrictionRes_choice[] = {
  {   0, "extensionSeq"                , ASN1_NO_EXTENSIONS     , dissect_extensionSeq },
  {   1, "nonStandardData"             , ASN1_NO_EXTENSIONS     , dissect_nonStandardData },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_CheckRestrictionRes(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_CheckRestrictionRes, CheckRestrictionRes_choice,
                                 NULL);

  return offset;
}


static const value_string h450_DiversionReason_vals[] = {
  {   0, "unknown" },
  {   1, "cfu" },
  {   2, "cfb" },
  {   3, "cfnr" },
  { 0, NULL }
};


static int
dissect_h450_DiversionReason(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_reroutingReason(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_DiversionReason(tvb, offset, actx, tree, hf_h450_reroutingReason);
}
static int dissect_originalReroutingReason(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_DiversionReason(tvb, offset, actx, tree, hf_h450_originalReroutingReason);
}
static int dissect_diversionReason(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_DiversionReason(tvb, offset, actx, tree, hf_h450_diversionReason);
}
static int dissect_originalDiversionReason(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_DiversionReason(tvb, offset, actx, tree, hf_h450_originalDiversionReason);
}



static int
dissect_h450_INTEGER_1_15(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              1U, 15U, NULL, FALSE);

  return offset;
}
static int dissect_diversionCounter(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_INTEGER_1_15(tvb, offset, actx, tree, hf_h450_diversionCounter);
}


static const value_string h450_SubscriptionOption_vals[] = {
  {   0, "noNotification" },
  {   1, "notificationWithoutDivertedToNr" },
  {   2, "notificationWithDivertedToNr" },
  { 0, NULL }
};


static int
dissect_h450_SubscriptionOption(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_subscriptionOption(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SubscriptionOption(tvb, offset, actx, tree, hf_h450_subscriptionOption);
}


static const value_string h450_CallReroutingArg_extension_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t CallReroutingArg_extension_choice[] = {
  {   0, "extensionSeq"                , ASN1_NO_EXTENSIONS     , dissect_extensionSeq },
  {   1, "nonStandardData"             , ASN1_NO_EXTENSIONS     , dissect_nonStandardData },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_CallReroutingArg_extension(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_CallReroutingArg_extension, CallReroutingArg_extension_choice,
                                 NULL);

  return offset;
}
static int dissect_callReroutingArg_extension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_CallReroutingArg_extension(tvb, offset, actx, tree, hf_h450_callReroutingArg_extension);
}


static const per_sequence_t CallReroutingArg_sequence[] = {
  { "reroutingReason"             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_reroutingReason },
  { "originalReroutingReason"     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_originalReroutingReason },
  { "calledAddress"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_calledAddress },
  { "diversionCounter"            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_diversionCounter },
  { "h225InfoElement"             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h225InfoElement },
  { "lastReroutingNr"             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_lastReroutingNr },
  { "subscriptionOption"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_subscriptionOption },
  { "callingPartySubaddress"      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_callingPartySubaddress },
  { "callingNumber"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_callingNumber },
  { "callingInfo"                 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_callingInfo },
  { "originalCalledNr"            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_originalCalledNr },
  { "redirectingInfo"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_redirectingInfo },
  { "originalCalledInfo"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_originalCalledInfo },
  { "extension"                   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_callReroutingArg_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CallReroutingArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_CallReroutingArg, CallReroutingArg_sequence);

  return offset;
}


static const value_string h450_CallReroutingRes_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t CallReroutingRes_choice[] = {
  {   0, "extensionSeq"                , ASN1_NO_EXTENSIONS     , dissect_extensionSeq },
  {   1, "nonStandardData"             , ASN1_NO_EXTENSIONS     , dissect_nonStandardData },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_CallReroutingRes(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_CallReroutingRes, CallReroutingRes_choice,
                                 NULL);

  return offset;
}


static const value_string h450_DivertingLegInformation1Arg_extension_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t DivertingLegInformation1Arg_extension_choice[] = {
  {   0, "extensionSeq"                , ASN1_NO_EXTENSIONS     , dissect_extensionSeq },
  {   1, "nonStandardData"             , ASN1_NO_EXTENSIONS     , dissect_nonStandardData },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_DivertingLegInformation1Arg_extension(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_DivertingLegInformation1Arg_extension, DivertingLegInformation1Arg_extension_choice,
                                 NULL);

  return offset;
}
static int dissect_divertingLegInformation1Arg_extension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_DivertingLegInformation1Arg_extension(tvb, offset, actx, tree, hf_h450_divertingLegInformation1Arg_extension);
}


static const per_sequence_t DivertingLegInformation1Arg_sequence[] = {
  { "diversionReason"             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_diversionReason },
  { "subscriptionOption"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_subscriptionOption },
  { "nominatedNr"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nominatedNr },
  { "nominatedInfo"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nominatedInfo },
  { "redirectingNr"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_redirectingNr },
  { "redirectingInfo"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_redirectingInfo },
  { "extension"                   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_divertingLegInformation1Arg_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_DivertingLegInformation1Arg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_DivertingLegInformation1Arg, DivertingLegInformation1Arg_sequence);

  return offset;
}


static const value_string h450_DivertingLegInformation2Arg_extension_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t DivertingLegInformation2Arg_extension_choice[] = {
  {   0, "extensionSeq"                , ASN1_NO_EXTENSIONS     , dissect_extensionSeq },
  {   1, "nonStandardData"             , ASN1_NO_EXTENSIONS     , dissect_nonStandardData },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_DivertingLegInformation2Arg_extension(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_DivertingLegInformation2Arg_extension, DivertingLegInformation2Arg_extension_choice,
                                 NULL);

  return offset;
}
static int dissect_extension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_DivertingLegInformation2Arg_extension(tvb, offset, actx, tree, hf_h450_extension);
}


static const per_sequence_t DivertingLegInformation2Arg_sequence[] = {
  { "diversionCounter"            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_diversionCounter },
  { "diversionReason"             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_diversionReason },
  { "originalDiversionReason"     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_originalDiversionReason },
  { "divertingNr"                 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_divertingNr },
  { "originalCalledNr"            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_originalCalledNr },
  { "redirectingInfo"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_redirectingInfo },
  { "originalCalledInfo"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_originalCalledInfo },
  { "extension"                   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_DivertingLegInformation2Arg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_DivertingLegInformation2Arg, DivertingLegInformation2Arg_sequence);

  return offset;
}


static const value_string h450_DivertingLegInformation3Arg_extension_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t DivertingLegInformation3Arg_extension_choice[] = {
  {   0, "extensionSeq"                , ASN1_NO_EXTENSIONS     , dissect_extensionSeq },
  {   1, "nonStandardData"             , ASN1_NO_EXTENSIONS     , dissect_nonStandardData },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_DivertingLegInformation3Arg_extension(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_DivertingLegInformation3Arg_extension, DivertingLegInformation3Arg_extension_choice,
                                 NULL);

  return offset;
}
static int dissect_divertingLegInformation3Arg_extension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_DivertingLegInformation3Arg_extension(tvb, offset, actx, tree, hf_h450_divertingLegInformation3Arg_extension);
}


static const per_sequence_t DivertingLegInformation3Arg_sequence[] = {
  { "presentationAllowedIndicator", ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_presentationAllowedIndicator },
  { "redirectionNr"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_redirectionNr },
  { "redirectionInfo"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_redirectionInfo },
  { "extension"                   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_divertingLegInformation3Arg_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_DivertingLegInformation3Arg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_DivertingLegInformation3Arg, DivertingLegInformation3Arg_sequence);

  return offset;
}


static const value_string h450_DivertingLegInformation4Arg_extension_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t DivertingLegInformation4Arg_extension_choice[] = {
  {   0, "extensionSeq"                , ASN1_NO_EXTENSIONS     , dissect_extensionSeq },
  {   1, "nonStandardData"             , ASN1_NO_EXTENSIONS     , dissect_nonStandardData },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_DivertingLegInformation4Arg_extension(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_DivertingLegInformation4Arg_extension, DivertingLegInformation4Arg_extension_choice,
                                 NULL);

  return offset;
}
static int dissect_divertingLegInformation4Arg_extension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_DivertingLegInformation4Arg_extension(tvb, offset, actx, tree, hf_h450_divertingLegInformation4Arg_extension);
}


static const per_sequence_t DivertingLegInformation4Arg_sequence[] = {
  { "diversionReason"             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_diversionReason },
  { "subscriptionOption"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_subscriptionOption },
  { "callingNr"                   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_callingNr },
  { "callingInfo"                 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_callingInfo },
  { "nominatedNr"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nominatedNr },
  { "nominatedInfo"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nominatedInfo },
  { "extension"                   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_divertingLegInformation4Arg_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_DivertingLegInformation4Arg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_DivertingLegInformation4Arg, DivertingLegInformation4Arg_sequence);

  return offset;
}


static const value_string h450_CfnrDivertedLegFailedArg_vals[] = {
  {   0, "extensionSeq" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t CfnrDivertedLegFailedArg_choice[] = {
  {   0, "extensionSeq"                , ASN1_NO_EXTENSIONS     , dissect_extensionSeq },
  {   1, "nonStandardData"             , ASN1_NO_EXTENSIONS     , dissect_nonStandardData },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_CfnrDivertedLegFailedArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_CfnrDivertedLegFailedArg, CfnrDivertedLegFailedArg_choice,
                                 NULL);

  return offset;
}


static const value_string h450_MixedExtension_vals[] = {
  {   0, "extension" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t MixedExtension_choice[] = {
  {   0, "extension"                   , ASN1_NO_EXTENSIONS     , dissect_mixedExtension_extension },
  {   1, "nonStandardData"             , ASN1_NO_EXTENSIONS     , dissect_nonStandardData },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_MixedExtension(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_MixedExtension, MixedExtension_choice,
                                 NULL);

  return offset;
}
static int dissect_extensionArg_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_MixedExtension(tvb, offset, actx, tree, hf_h450_extensionArg_item);
}
static int dissect_extensionRes_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_MixedExtension(tvb, offset, actx, tree, hf_h450_extensionRes_item);
}
static int dissect_MwiDummyRes_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_MixedExtension(tvb, offset, actx, tree, hf_h450_MwiDummyRes_item);
}
static int dissect_ExtensionArg_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_MixedExtension(tvb, offset, actx, tree, hf_h450_ExtensionArg_item);
}
static int dissect_extension_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_MixedExtension(tvb, offset, actx, tree, hf_h450_extension_item);
}
static int dissect_argumentExtension_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_MixedExtension(tvb, offset, actx, tree, hf_h450_argumentExtension_item);
}
static int dissect_resultExtension_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_MixedExtension(tvb, offset, actx, tree, hf_h450_resultExtension_item);
}


static const per_sequence_t SEQUENCE_SIZE_0_255_OF_MixedExtension_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_extensionArg_item },
};

static int
dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension, SEQUENCE_SIZE_0_255_OF_MixedExtension_sequence_of,
                                                  0, 255);

  return offset;
}
static int dissect_holdNotificArg_extensionArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvb, offset, actx, tree, hf_h450_holdNotificArg_extensionArg);
}
static int dissect_retrieveNotificArg_extensionArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvb, offset, actx, tree, hf_h450_retrieveNotificArg_extensionArg);
}
static int dissect_remoteHoldArg_extensionArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvb, offset, actx, tree, hf_h450_remoteHoldArg_extensionArg);
}
static int dissect_extensionRes(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvb, offset, actx, tree, hf_h450_extensionRes);
}
static int dissect_remoteRetrieveArg_extensionArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvb, offset, actx, tree, hf_h450_remoteRetrieveArg_extensionArg);
}
static int dissect_cpRequestArg_extensionArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvb, offset, actx, tree, hf_h450_cpRequestArg_extensionArg);
}
static int dissect_cpSetupArg_extensionArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvb, offset, actx, tree, hf_h450_cpSetupArg_extensionArg);
}
static int dissect_groupIndicationOnArg_extensionArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvb, offset, actx, tree, hf_h450_groupIndicationOnArg_extensionArg);
}
static int dissect_groupIndicationOffArg_extensionArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvb, offset, actx, tree, hf_h450_groupIndicationOffArg_extensionArg);
}
static int dissect_pickrequArg_extensionArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvb, offset, actx, tree, hf_h450_pickrequArg_extensionArg);
}
static int dissect_pickupArg_extensionArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvb, offset, actx, tree, hf_h450_pickupArg_extensionArg);
}
static int dissect_pickExeArg_extensionArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvb, offset, actx, tree, hf_h450_pickExeArg_extensionArg);
}
static int dissect_cpNotifyArg_extensionArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvb, offset, actx, tree, hf_h450_cpNotifyArg_extensionArg);
}
static int dissect_cpickupNotifyArg_extensionArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvb, offset, actx, tree, hf_h450_cpickupNotifyArg_extensionArg);
}
static int dissect_callWaitingArg_extensionArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvb, offset, actx, tree, hf_h450_callWaitingArg_extensionArg);
}
static int dissect_nameArg_extensionArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvb, offset, actx, tree, hf_h450_nameArg_extensionArg);
}
static int dissect_ccRequestArg_extension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvb, offset, actx, tree, hf_h450_ccRequestArg_extension);
}
static int dissect_ccRequestRes_extension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvb, offset, actx, tree, hf_h450_ccRequestRes_extension);
}
static int dissect_ccShortArg_extension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvb, offset, actx, tree, hf_h450_ccShortArg_extension);
}
static int dissect_ccLongArg_extension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvb, offset, actx, tree, hf_h450_ccLongArg_extension);
}
static int dissect_coReqOptArg_extension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvb, offset, actx, tree, hf_h450_coReqOptArg_extension);
}
static int dissect_rUAlertOptArg_extension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvb, offset, actx, tree, hf_h450_rUAlertOptArg_extension);
}
static int dissect_cfbOvrOptArg_extension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvb, offset, actx, tree, hf_h450_cfbOvrOptArg_extension);
}
static int dissect_cIRequestArg_argumentExtension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvb, offset, actx, tree, hf_h450_cIRequestArg_argumentExtension);
}
static int dissect_cIRequestRes_resultExtension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvb, offset, actx, tree, hf_h450_cIRequestRes_resultExtension);
}
static int dissect_cIGetCIPLOptArg_argumentExtension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvb, offset, actx, tree, hf_h450_cIGetCIPLOptArg_argumentExtension);
}
static int dissect_cIGetCIPLRes_resultExtension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvb, offset, actx, tree, hf_h450_cIGetCIPLRes_resultExtension);
}
static int dissect_cIIsOptArg_argumentExtension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvb, offset, actx, tree, hf_h450_cIIsOptArg_argumentExtension);
}
static int dissect_cIIsOptRes_resultExtension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvb, offset, actx, tree, hf_h450_cIIsOptRes_resultExtension);
}
static int dissect_cIFrcRelArg_argumentExtension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvb, offset, actx, tree, hf_h450_cIFrcRelArg_argumentExtension);
}
static int dissect_cIFrcRelOptRes_resultExtension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvb, offset, actx, tree, hf_h450_cIFrcRelOptRes_resultExtension);
}
static int dissect_cIWobOptArg_argumentExtension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvb, offset, actx, tree, hf_h450_cIWobOptArg_argumentExtension);
}
static int dissect_cIWobOptRes_resultExtension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvb, offset, actx, tree, hf_h450_cIWobOptRes_resultExtension);
}
static int dissect_cISilentArg_argumentExtension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvb, offset, actx, tree, hf_h450_cISilentArg_argumentExtension);
}
static int dissect_cISilentOptRes_resultExtension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvb, offset, actx, tree, hf_h450_cISilentOptRes_resultExtension);
}
static int dissect_cINotificationArg_argumentExtension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvb, offset, actx, tree, hf_h450_cINotificationArg_argumentExtension);
}
static int dissect_cmnArg_extension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvb, offset, actx, tree, hf_h450_cmnArg_extension);
}
static int dissect_cmnRequestArg_extensionArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension(tvb, offset, actx, tree, hf_h450_cmnRequestArg_extensionArg);
}


static const per_sequence_t HoldNotificArg_sequence[] = {
  { "extensionArg"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_holdNotificArg_extensionArg },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_HoldNotificArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_HoldNotificArg, HoldNotificArg_sequence);

  return offset;
}


static const per_sequence_t RetrieveNotificArg_sequence[] = {
  { "extensionArg"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_retrieveNotificArg_extensionArg },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_RetrieveNotificArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_RetrieveNotificArg, RetrieveNotificArg_sequence);

  return offset;
}


static const per_sequence_t RemoteHoldArg_sequence[] = {
  { "extensionArg"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_remoteHoldArg_extensionArg },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_RemoteHoldArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_RemoteHoldArg, RemoteHoldArg_sequence);

  return offset;
}


static const per_sequence_t RemoteHoldRes_sequence[] = {
  { "extensionRes"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_extensionRes },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_RemoteHoldRes(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_RemoteHoldRes, RemoteHoldRes_sequence);

  return offset;
}


static const per_sequence_t RemoteRetrieveArg_sequence[] = {
  { "extensionArg"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_remoteRetrieveArg_extensionArg },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_RemoteRetrieveArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_RemoteRetrieveArg, RemoteRetrieveArg_sequence);

  return offset;
}


static const per_sequence_t RemoteRetrieveRes_sequence[] = {
  { "extensionRes"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_extensionRes },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_RemoteRetrieveRes(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_RemoteRetrieveRes, RemoteRetrieveRes_sequence);

  return offset;
}



static int
dissect_h450_ParkedToPosition(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 65535U, NULL, FALSE);

  return offset;
}
static int dissect_parkedToPosition(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_ParkedToPosition(tvb, offset, actx, tree, hf_h450_parkedToPosition);
}
static int dissect_parkPosition(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_ParkedToPosition(tvb, offset, actx, tree, hf_h450_parkPosition);
}


static const per_sequence_t CpRequestArg_sequence[] = {
  { "parkingNumber"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_parkingNumber },
  { "parkedNumber"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_parkedNumber },
  { "parkedToNumber"              , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_parkedToNumber },
  { "parkedToPosition"            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_parkedToPosition },
  { "extensionArg"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cpRequestArg_extensionArg },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CpRequestArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_CpRequestArg, CpRequestArg_sequence);

  return offset;
}


static const value_string h450_ParkCondition_vals[] = {
  {   0, "unspecified" },
  {   1, "parkedToUserIdle" },
  {   2, "parkedToUserBusy" },
  {   3, "parkedToGroup" },
  { 0, NULL }
};


static int
dissect_h450_ParkCondition(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_parkCondition(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_ParkCondition(tvb, offset, actx, tree, hf_h450_parkCondition);
}


static const per_sequence_t CpRequestRes_sequence[] = {
  { "parkedToNumber"              , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_parkedToNumber },
  { "parkedToPosition"            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_parkedToPosition },
  { "parkCondition"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_parkCondition },
  { "extensionRes"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_extensionRes },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CpRequestRes(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_CpRequestRes, CpRequestRes_sequence);

  return offset;
}


static const per_sequence_t CpSetupArg_sequence[] = {
  { "parkingNumber"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_parkingNumber },
  { "parkedNumber"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_parkedNumber },
  { "parkedToNumber"              , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_parkedToNumber },
  { "parkedToPosition"            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_parkedToPosition },
  { "extensionArg"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cpSetupArg_extensionArg },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CpSetupArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_CpSetupArg, CpSetupArg_sequence);

  return offset;
}


static const per_sequence_t CpSetupRes_sequence[] = {
  { "parkedToNumber"              , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_parkedToNumber },
  { "parkedToPosition"            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_parkedToPosition },
  { "parkCondition"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_parkCondition },
  { "extensionRes"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_extensionRes },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CpSetupRes(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_CpSetupRes, CpSetupRes_sequence);

  return offset;
}


static const value_string h450_CallType_vals[] = {
  {   0, "parkedCall" },
  {   1, "alertingCall" },
  { 0, NULL }
};


static int
dissect_h450_CallType(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_retrieveCallType(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_CallType(tvb, offset, actx, tree, hf_h450_retrieveCallType);
}


static const per_sequence_t GroupIndicationOnArg_sequence[] = {
  { "callPickupId"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_callPickupId },
  { "groupMemberUserNr"           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_groupMemberUserNr },
  { "retrieveCallType"            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_retrieveCallType },
  { "partyToRetrieve"             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_partyToRetrieve },
  { "retrieveAddress"             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_retrieveAddress },
  { "parkPosition"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_parkPosition },
  { "extensionArg"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_groupIndicationOnArg_extensionArg },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_GroupIndicationOnArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_GroupIndicationOnArg, GroupIndicationOnArg_sequence);

  return offset;
}


static const per_sequence_t GroupIndicationOnRes_sequence[] = {
  { "extensionRes"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_extensionRes },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_GroupIndicationOnRes(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_GroupIndicationOnRes, GroupIndicationOnRes_sequence);

  return offset;
}


static const per_sequence_t GroupIndicationOffArg_sequence[] = {
  { "callPickupId"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_callPickupId },
  { "groupMemberUserNr"           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_groupMemberUserNr },
  { "extensionArg"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_groupIndicationOffArg_extensionArg },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_GroupIndicationOffArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_GroupIndicationOffArg, GroupIndicationOffArg_sequence);

  return offset;
}


static const per_sequence_t GroupIndicationOffRes_sequence[] = {
  { "extensionRes"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_extensionRes },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_GroupIndicationOffRes(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_GroupIndicationOffRes, GroupIndicationOffRes_sequence);

  return offset;
}


static const per_sequence_t PickrequArg_sequence[] = {
  { "picking-upNumber"            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_picking_upNumber },
  { "callPickupId"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_callPickupId },
  { "partyToRetrieve"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_partyToRetrieve },
  { "retrieveAddress"             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_retrieveAddress },
  { "parkPosition"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_parkPosition },
  { "extensionArg"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pickrequArg_extensionArg },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_PickrequArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_PickrequArg, PickrequArg_sequence);

  return offset;
}


static const per_sequence_t PickrequRes_sequence[] = {
  { "callPickupId"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_callPickupId },
  { "extensionRes"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_extensionRes },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_PickrequRes(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_PickrequRes, PickrequRes_sequence);

  return offset;
}


static const per_sequence_t PickupArg_sequence[] = {
  { "callPickupId"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_callPickupId },
  { "picking-upNumber"            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_picking_upNumber },
  { "extensionArg"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pickupArg_extensionArg },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_PickupArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_PickupArg, PickupArg_sequence);

  return offset;
}


static const per_sequence_t PickupRes_sequence[] = {
  { "extensionRes"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_extensionRes },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_PickupRes(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_PickupRes, PickupRes_sequence);

  return offset;
}


static const per_sequence_t PickExeArg_sequence[] = {
  { "callPickupId"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_callPickupId },
  { "picking-upNumber"            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_picking_upNumber },
  { "partyToRetrieve"             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_partyToRetrieve },
  { "extensionArg"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_pickExeArg_extensionArg },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_PickExeArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_PickExeArg, PickExeArg_sequence);

  return offset;
}


static const per_sequence_t PickExeRes_sequence[] = {
  { "extensionRes"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_extensionRes },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_PickExeRes(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_PickExeRes, PickExeRes_sequence);

  return offset;
}


static const per_sequence_t CpNotifyArg_sequence[] = {
  { "parkingNumber"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_parkingNumber },
  { "extensionArg"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cpNotifyArg_extensionArg },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CpNotifyArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_CpNotifyArg, CpNotifyArg_sequence);

  return offset;
}


static const per_sequence_t CpickupNotifyArg_sequence[] = {
  { "picking-upNumber"            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_picking_upNumber },
  { "extensionArg"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cpickupNotifyArg_extensionArg },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CpickupNotifyArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_CpickupNotifyArg, CpickupNotifyArg_sequence);

  return offset;
}



static int
dissect_h450_INTEGER_0_255(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 255U, NULL, FALSE);

  return offset;
}
static int dissect_nbOfAddWaitingCalls(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_INTEGER_0_255(tvb, offset, actx, tree, hf_h450_nbOfAddWaitingCalls);
}


static const per_sequence_t CallWaitingArg_sequence[] = {
  { "nbOfAddWaitingCalls"         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nbOfAddWaitingCalls },
  { "extensionArg"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_callWaitingArg_extensionArg },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CallWaitingArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_CallWaitingArg, CallWaitingArg_sequence);

  return offset;
}



static int
dissect_h450_INTEGER_0_65535(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 65535U, NULL, FALSE);

  return offset;
}
static int dissect_integer(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_INTEGER_0_65535(tvb, offset, actx, tree, hf_h450_integer);
}



static int
dissect_h450_NumericString_SIZE_1_10(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_NumericString(tvb, offset, actx, tree, hf_index,
                                          1, 10);

  return offset;
}
static int dissect_numericString(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NumericString_SIZE_1_10(tvb, offset, actx, tree, hf_h450_numericString);
}


static const value_string h450_MsgCentreId_vals[] = {
  {   0, "integer" },
  {   1, "mwipartyNumber" },
  {   2, "numericString" },
  { 0, NULL }
};

static const per_choice_t MsgCentreId_choice[] = {
  {   0, "integer"                     , ASN1_NO_EXTENSIONS     , dissect_integer },
  {   1, "mwipartyNumber"              , ASN1_NO_EXTENSIONS     , dissect_mwipartyNumber },
  {   2, "numericString"               , ASN1_NO_EXTENSIONS     , dissect_numericString },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_MsgCentreId(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_MsgCentreId, MsgCentreId_choice,
                                 NULL);

  return offset;
}
static int dissect_msgCentreId(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_MsgCentreId(tvb, offset, actx, tree, hf_h450_msgCentreId);
}



static int
dissect_h450_NbOfMessages(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 65535U, NULL, FALSE);

  return offset;
}
static int dissect_nbOfMessages(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NbOfMessages(tvb, offset, actx, tree, hf_h450_nbOfMessages);
}



static int
dissect_h450_TimeStamp(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_VisibleString(tvb, offset, actx, tree, hf_index,
                                        12, 19);

  return offset;
}
static int dissect_timestamp(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_TimeStamp(tvb, offset, actx, tree, hf_h450_timestamp);
}



static int
dissect_h450_INTEGER_0_9(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 9U, NULL, FALSE);

  return offset;
}
static int dissect_priority(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_INTEGER_0_9(tvb, offset, actx, tree, hf_h450_priority);
}


static const per_sequence_t ExtensionArg_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ExtensionArg_item },
};

static int
dissect_h450_ExtensionArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h450_ExtensionArg, ExtensionArg_sequence_of,
                                                  0, 255);

  return offset;
}
static int dissect_mWIActivateArg_extensionArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_ExtensionArg(tvb, offset, actx, tree, hf_h450_mWIActivateArg_extensionArg);
}
static int dissect_mWIDeactivateArg_extensionArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_ExtensionArg(tvb, offset, actx, tree, hf_h450_mWIDeactivateArg_extensionArg);
}
static int dissect_mWIInterrogateArg_extensionArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_ExtensionArg(tvb, offset, actx, tree, hf_h450_mWIInterrogateArg_extensionArg);
}
static int dissect_mWIInterrogateResElt_extensionArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_ExtensionArg(tvb, offset, actx, tree, hf_h450_mWIInterrogateResElt_extensionArg);
}


static const per_sequence_t MWIActivateArg_sequence[] = {
  { "servedUserNr"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_servedUserNr },
  { "basicService"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_basicService },
  { "msgCentreId"                 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_msgCentreId },
  { "nbOfMessages"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nbOfMessages },
  { "originatingNr"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_originatingNr },
  { "timestamp"                   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_timestamp },
  { "priority"                    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_priority },
  { "extensionArg"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_mWIActivateArg_extensionArg },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_MWIActivateArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_MWIActivateArg, MWIActivateArg_sequence);

  return offset;
}



static int
dissect_h450_MwiActivate(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_h450_MWIActivateArg(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t MWIDeactivateArg_sequence[] = {
  { "servedUserNr"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_servedUserNr },
  { "basicService"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_basicService },
  { "msgCentreId"                 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_msgCentreId },
  { "callbackReq"                 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_callbackReq },
  { "extensionArg"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_mWIDeactivateArg_extensionArg },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_MWIDeactivateArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_MWIDeactivateArg, MWIDeactivateArg_sequence);

  return offset;
}



static int
dissect_h450_MwiDeactivate(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_h450_MWIDeactivateArg(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t MWIInterrogateArg_sequence[] = {
  { "servedUserNr"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_servedUserNr },
  { "basicService"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_basicService },
  { "msgCentreId"                 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_msgCentreId },
  { "callbackReq"                 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_callbackReq },
  { "extensionArg"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_mWIInterrogateArg_extensionArg },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_MWIInterrogateArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_MWIInterrogateArg, MWIInterrogateArg_sequence);

  return offset;
}



static int
dissect_h450_MwiInterrogate(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_h450_MWIInterrogateArg(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t MwiDummyRes_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_MwiDummyRes_item },
};

static int
dissect_h450_MwiDummyRes(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h450_MwiDummyRes, MwiDummyRes_sequence_of,
                                                  0, 255);

  return offset;
}


static const per_sequence_t MWIInterrogateResElt_sequence[] = {
  { "basicService"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_basicService },
  { "msgCentreId"                 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_msgCentreId },
  { "nbOfMessages"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nbOfMessages },
  { "originatingNr"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_originatingNr },
  { "timestamp"                   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_timestamp },
  { "priority"                    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_priority },
  { "extensionArg"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_mWIInterrogateResElt_extensionArg },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_MWIInterrogateResElt(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_MWIInterrogateResElt, MWIInterrogateResElt_sequence);

  return offset;
}
static int dissect_MWIInterrogateRes_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_MWIInterrogateResElt(tvb, offset, actx, tree, hf_h450_MWIInterrogateRes_item);
}


static const per_sequence_t MWIInterrogateRes_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_MWIInterrogateRes_item },
};

static int
dissect_h450_MWIInterrogateRes(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h450_MWIInterrogateRes, MWIInterrogateRes_sequence_of,
                                                  1, 64);

  return offset;
}



static int
dissect_h450_SimpleName(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 50, NULL);

  return offset;
}
static int dissect_simpleName(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SimpleName(tvb, offset, actx, tree, hf_h450_simpleName);
}



static int
dissect_h450_ExtendedName(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_BMPString(tvb, offset, actx, tree, hf_index,
                                          1, 256);

  return offset;
}
static int dissect_extendedName(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_ExtendedName(tvb, offset, actx, tree, hf_h450_extendedName);
}


static const value_string h450_NamePresentationAllowed_vals[] = {
  {   0, "simpleName" },
  {   1, "extendedName" },
  { 0, NULL }
};

static const per_choice_t NamePresentationAllowed_choice[] = {
  {   0, "simpleName"                  , ASN1_EXTENSION_ROOT    , dissect_simpleName },
  {   1, "extendedName"                , ASN1_EXTENSION_ROOT    , dissect_extendedName },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_NamePresentationAllowed(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_NamePresentationAllowed, NamePresentationAllowed_choice,
                                 NULL);

  return offset;
}
static int dissect_namePresentationAllowed(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NamePresentationAllowed(tvb, offset, actx, tree, hf_h450_namePresentationAllowed);
}


static const value_string h450_NamePresentationRestricted_vals[] = {
  {   0, "simpleName" },
  {   1, "extendedName" },
  {   2, "restrictedNull" },
  { 0, NULL }
};

static const per_choice_t NamePresentationRestricted_choice[] = {
  {   0, "simpleName"                  , ASN1_EXTENSION_ROOT    , dissect_simpleName },
  {   1, "extendedName"                , ASN1_EXTENSION_ROOT    , dissect_extendedName },
  {   2, "restrictedNull"              , ASN1_EXTENSION_ROOT    , dissect_restrictedNull },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_NamePresentationRestricted(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_NamePresentationRestricted, NamePresentationRestricted_choice,
                                 NULL);

  return offset;
}
static int dissect_namePresentationRestricted(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_NamePresentationRestricted(tvb, offset, actx, tree, hf_h450_namePresentationRestricted);
}


static const value_string h450_Name_vals[] = {
  {   0, "namePresentationAllowed" },
  {   1, "namePresentationRestricted" },
  {   2, "nameNotAvailable" },
  { 0, NULL }
};

static const per_choice_t Name_choice[] = {
  {   0, "namePresentationAllowed"     , ASN1_EXTENSION_ROOT    , dissect_namePresentationAllowed },
  {   1, "namePresentationRestricted"  , ASN1_EXTENSION_ROOT    , dissect_namePresentationRestricted },
  {   2, "nameNotAvailable"            , ASN1_EXTENSION_ROOT    , dissect_nameNotAvailable },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_Name(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_Name, Name_choice,
                                 NULL);

  return offset;
}
static int dissect_name(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_Name(tvb, offset, actx, tree, hf_h450_name);
}


static const per_sequence_t NameArg_sequence[] = {
  { "name"                        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_name },
  { "extensionArg"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nameArg_extensionArg },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_NameArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_NameArg, NameArg_sequence);

  return offset;
}


static const per_sequence_t CcRequestArg_sequence[] = {
  { "numberA"                     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_numberA },
  { "numberB"                     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_numberB },
  { "ccIdentifier"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ccIdentifier },
  { "service"                     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_service },
  { "can-retain-service"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_can_retain_service },
  { "retain-sig-connection"       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_retain_sig_connection },
  { "extension"                   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ccRequestArg_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CcRequestArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_CcRequestArg, CcRequestArg_sequence);

  return offset;
}


static const per_sequence_t CcRequestRes_sequence[] = {
  { "retain-service"              , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_retain_service },
  { "extension"                   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ccRequestRes_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CcRequestRes(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_CcRequestRes, CcRequestRes_sequence);

  return offset;
}


static const per_sequence_t CcShortArg_sequence[] = {
  { "ccIdentifier"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ccIdentifier },
  { "extension"                   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ccShortArg_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CcShortArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_CcShortArg, CcShortArg_sequence);

  return offset;
}
static int dissect_shortArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_CcShortArg(tvb, offset, actx, tree, hf_h450_shortArg);
}


static const per_sequence_t CcLongArg_sequence[] = {
  { "numberA"                     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_numberA },
  { "numberB"                     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_numberB },
  { "ccIdentifier"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ccIdentifier },
  { "service"                     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_service },
  { "extension"                   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ccLongArg_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CcLongArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_CcLongArg, CcLongArg_sequence);

  return offset;
}
static int dissect_longArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_CcLongArg(tvb, offset, actx, tree, hf_h450_longArg);
}


static const value_string h450_CcArg_vals[] = {
  {   0, "shortArg" },
  {   1, "longArg" },
  { 0, NULL }
};

static const per_choice_t CcArg_choice[] = {
  {   0, "shortArg"                    , ASN1_EXTENSION_ROOT    , dissect_shortArg },
  {   1, "longArg"                     , ASN1_EXTENSION_ROOT    , dissect_longArg },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_CcArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_CcArg, CcArg_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t CoReqOptArg_sequence[] = {
  { "extension"                   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_coReqOptArg_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CoReqOptArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_CoReqOptArg, CoReqOptArg_sequence);

  return offset;
}


static const per_sequence_t RUAlertOptArg_sequence[] = {
  { "extension"                   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rUAlertOptArg_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_RUAlertOptArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_RUAlertOptArg, RUAlertOptArg_sequence);

  return offset;
}


static const per_sequence_t CfbOvrOptArg_sequence[] = {
  { "extension"                   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cfbOvrOptArg_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CfbOvrOptArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_CfbOvrOptArg, CfbOvrOptArg_sequence);

  return offset;
}


static const value_string h450_CICapabilityLevel_vals[] = {
  {   1, "intrusionLowCap" },
  {   2, "intrusionMediumCap" },
  {   3, "intrusionHighCap" },
  { 0, NULL }
};


static int
dissect_h450_CICapabilityLevel(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              1U, 3U, NULL, FALSE);

  return offset;
}
static int dissect_ciCapabilityLevel(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_CICapabilityLevel(tvb, offset, actx, tree, hf_h450_ciCapabilityLevel);
}


static const per_sequence_t CIRequestArg_sequence[] = {
  { "ciCapabilityLevel"           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ciCapabilityLevel },
  { "argumentExtension"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cIRequestArg_argumentExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CIRequestArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_CIRequestArg, CIRequestArg_sequence);

  return offset;
}


static const value_string h450_CIStatusInformation_vals[] = {
  {   0, "callIntrusionImpending" },
  {   1, "callIntruded" },
  {   2, "callIsolated" },
  {   3, "callForceReleased" },
  {   4, "callIntrusionComplete" },
  {   5, "callIntrusionEnd" },
  { 0, NULL }
};

static const per_choice_t CIStatusInformation_choice[] = {
  {   0, "callIntrusionImpending"      , ASN1_EXTENSION_ROOT    , dissect_callIntrusionImpending },
  {   1, "callIntruded"                , ASN1_EXTENSION_ROOT    , dissect_callIntruded },
  {   2, "callIsolated"                , ASN1_EXTENSION_ROOT    , dissect_callIsolated },
  {   3, "callForceReleased"           , ASN1_EXTENSION_ROOT    , dissect_callForceReleased },
  {   4, "callIntrusionComplete"       , ASN1_EXTENSION_ROOT    , dissect_callIntrusionComplete },
  {   5, "callIntrusionEnd"            , ASN1_EXTENSION_ROOT    , dissect_callIntrusionEnd },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_CIStatusInformation(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_CIStatusInformation, CIStatusInformation_choice,
                                 NULL);

  return offset;
}
static int dissect_ciStatusInformation(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_CIStatusInformation(tvb, offset, actx, tree, hf_h450_ciStatusInformation);
}


static const per_sequence_t CIRequestRes_sequence[] = {
  { "ciStatusInformation"         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ciStatusInformation },
  { "resultExtension"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cIRequestRes_resultExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CIRequestRes(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_CIRequestRes, CIRequestRes_sequence);

  return offset;
}


static const per_sequence_t CIGetCIPLOptArg_sequence[] = {
  { "argumentExtension"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cIGetCIPLOptArg_argumentExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CIGetCIPLOptArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_CIGetCIPLOptArg, CIGetCIPLOptArg_sequence);

  return offset;
}


static const value_string h450_CIProtectionLevel_vals[] = {
  {   0, "lowProtection" },
  {   1, "mediumProtection" },
  {   2, "highProtection" },
  {   3, "fullProtection" },
  { 0, NULL }
};


static int
dissect_h450_CIProtectionLevel(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 3U, NULL, FALSE);

  return offset;
}
static int dissect_ciProtectionLevel(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_CIProtectionLevel(tvb, offset, actx, tree, hf_h450_ciProtectionLevel);
}


static const per_sequence_t CIGetCIPLRes_sequence[] = {
  { "ciProtectionLevel"           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ciProtectionLevel },
  { "silentMonitoringPermitted"   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_silentMonitoringPermitted },
  { "resultExtension"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cIGetCIPLRes_resultExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CIGetCIPLRes(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_CIGetCIPLRes, CIGetCIPLRes_sequence);

  return offset;
}


static const per_sequence_t CIIsOptArg_sequence[] = {
  { "argumentExtension"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cIIsOptArg_argumentExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CIIsOptArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_CIIsOptArg, CIIsOptArg_sequence);

  return offset;
}


static const per_sequence_t CIIsOptRes_sequence[] = {
  { "resultExtension"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cIIsOptRes_resultExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CIIsOptRes(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_CIIsOptRes, CIIsOptRes_sequence);

  return offset;
}


static const per_sequence_t CIFrcRelArg_sequence[] = {
  { "ciCapabilityLevel"           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ciCapabilityLevel },
  { "argumentExtension"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cIFrcRelArg_argumentExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CIFrcRelArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_CIFrcRelArg, CIFrcRelArg_sequence);

  return offset;
}


static const per_sequence_t CIFrcRelOptRes_sequence[] = {
  { "resultExtension"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cIFrcRelOptRes_resultExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CIFrcRelOptRes(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_CIFrcRelOptRes, CIFrcRelOptRes_sequence);

  return offset;
}


static const per_sequence_t CIWobOptArg_sequence[] = {
  { "argumentExtension"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cIWobOptArg_argumentExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CIWobOptArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_CIWobOptArg, CIWobOptArg_sequence);

  return offset;
}


static const per_sequence_t CIWobOptRes_sequence[] = {
  { "resultExtension"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cIWobOptRes_resultExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CIWobOptRes(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_CIWobOptRes, CIWobOptRes_sequence);

  return offset;
}


static const per_sequence_t CISilentArg_sequence[] = {
  { "ciCapabilityLevel"           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ciCapabilityLevel },
  { "specificCall"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_specificCall },
  { "argumentExtension"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cISilentArg_argumentExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CISilentArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_CISilentArg, CISilentArg_sequence);

  return offset;
}


static const per_sequence_t CISilentOptRes_sequence[] = {
  { "resultExtension"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cISilentOptRes_resultExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CISilentOptRes(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_CISilentOptRes, CISilentOptRes_sequence);

  return offset;
}


static const per_sequence_t CINotificationArg_sequence[] = {
  { "ciStatusInformation"         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ciStatusInformation },
  { "argumentExtension"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cINotificationArg_argumentExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CINotificationArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_CINotificationArg, CINotificationArg_sequence);

  return offset;
}


static const per_sequence_t FeatureList_sequence[] = {
  { "ssCFreRoutingSupported"      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ssCFreRoutingSupported },
  { "ssCTreRoutingSupported"      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ssCTreRoutingSupported },
  { "ssCCBSPossible"              , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ssCCBSPossible },
  { "ssCCNRPossible"              , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ssCCNRPossible },
  { "ssCOSupported"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ssCOSupported },
  { "ssCIForcedReleaseSupported"  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ssCIForcedReleaseSupported },
  { "ssCIIsolationSupported"      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ssCIIsolationSupported },
  { "ssCIWaitOnBusySupported"     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ssCIWaitOnBusySupported },
  { "ssCISilentMonitoringSupported", ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ssCISilentMonitoringSupported },
  { "ssCIConferenceSupported"     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ssCIConferenceSupported },
  { "ssCHFarHoldSupported"        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ssCHFarHoldSupported },
  { "ssMWICallbackSupported"      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ssMWICallbackSupported },
  { "ssCPCallParkSupported"       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ssCPCallParkSupported },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_FeatureList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_FeatureList, FeatureList_sequence);

  return offset;
}
static int dissect_featureList(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_FeatureList(tvb, offset, actx, tree, hf_h450_featureList);
}


static const value_string h450_PartyCategory_vals[] = {
  {   0, "unknown" },
  {   1, "extension" },
  {   2, "attendant" },
  {   3, "emergExt" },
  { 0, NULL }
};


static int
dissect_h450_PartyCategory(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_partyCategory(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_PartyCategory(tvb, offset, actx, tree, hf_h450_partyCategory);
}



static int
dissect_h450_SSCIProtectionLevel(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 3U, NULL, FALSE);

  return offset;
}
static int dissect_ssCIprotectionLevel(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_SSCIProtectionLevel(tvb, offset, actx, tree, hf_h450_ssCIprotectionLevel);
}


static const per_sequence_t FeatureValues_sequence[] = {
  { "partyCategory"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_partyCategory },
  { "ssCIprotectionLevel"         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ssCIprotectionLevel },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_FeatureValues(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_FeatureValues, FeatureValues_sequence);

  return offset;
}
static int dissect_featureValues(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_FeatureValues(tvb, offset, actx, tree, hf_h450_featureValues);
}


static const per_sequence_t FeatureControl_sequence[] = {
  { "ssCHDoNotHold"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ssCHDoNotHold },
  { "ssCTDoNotTransfer"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ssCTDoNotTransfer },
  { "ssMWICallbackCall"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ssMWICallbackCall },
  { "ssCISilentMonitorPermitted"  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ssCISilentMonitorPermitted },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_FeatureControl(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_FeatureControl, FeatureControl_sequence);

  return offset;
}
static int dissect_featureControl(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h450_FeatureControl(tvb, offset, actx, tree, hf_h450_featureControl);
}


static const per_sequence_t CmnArg_sequence[] = {
  { "featureList"                 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_featureList },
  { "featureValues"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_featureValues },
  { "featureControl"              , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_featureControl },
  { "extension"                   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cmnArg_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CmnArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_CmnArg, CmnArg_sequence);

  return offset;
}


static const per_sequence_t CmnRequestArg_sequence[] = {
  { "extensionArg"                , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_cmnRequestArg_extensionArg },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CmnRequestArg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h450_CmnRequestArg, CmnRequestArg_sequence);

  return offset;
}


static const value_string h450_Unspecified_vals[] = {
  {   0, "extension" },
  {   1, "nonStandard" },
  { 0, NULL }
};

static const per_choice_t Unspecified_choice[] = {
  {   0, "extension"                   , ASN1_NO_EXTENSIONS     , dissect_unspecified_extension },
  {   1, "nonStandard"                 , ASN1_NO_EXTENSIONS     , dissect_nonStandard },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_Unspecified(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h450_Unspecified, Unspecified_choice,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static void dissect_CallTransferIdentify_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  asn_ctx_t asn_ctx;
  asn_ctx_init(&asn_ctx, ASN_ENC_PER, TRUE, pinfo);
  dissect_h450_CallTransferIdentify(tvb, 0, &asn_ctx, tree, hf_h450_CallTransferIdentify_PDU);
}
static void dissect_CallTransferAbandon_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  asn_ctx_t asn_ctx;
  asn_ctx_init(&asn_ctx, ASN_ENC_PER, TRUE, pinfo);
  dissect_h450_CallTransferAbandon(tvb, 0, &asn_ctx, tree, hf_h450_CallTransferAbandon_PDU);
}
static void dissect_CallTransferInitiate_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  asn_ctx_t asn_ctx;
  asn_ctx_init(&asn_ctx, ASN_ENC_PER, TRUE, pinfo);
  dissect_h450_CallTransferInitiate(tvb, 0, &asn_ctx, tree, hf_h450_CallTransferInitiate_PDU);
}
static void dissect_CallTransferSetup_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  asn_ctx_t asn_ctx;
  asn_ctx_init(&asn_ctx, ASN_ENC_PER, TRUE, pinfo);
  dissect_h450_CallTransferSetup(tvb, 0, &asn_ctx, tree, hf_h450_CallTransferSetup_PDU);
}
static void dissect_CallTransferUpdate_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  asn_ctx_t asn_ctx;
  asn_ctx_init(&asn_ctx, ASN_ENC_PER, TRUE, pinfo);
  dissect_h450_CallTransferUpdate(tvb, 0, &asn_ctx, tree, hf_h450_CallTransferUpdate_PDU);
}
static void dissect_SubaddressTransfer_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  asn_ctx_t asn_ctx;
  asn_ctx_init(&asn_ctx, ASN_ENC_PER, TRUE, pinfo);
  dissect_h450_SubaddressTransfer(tvb, 0, &asn_ctx, tree, hf_h450_SubaddressTransfer_PDU);
}
static void dissect_CallTransferComplete_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  asn_ctx_t asn_ctx;
  asn_ctx_init(&asn_ctx, ASN_ENC_PER, TRUE, pinfo);
  dissect_h450_CallTransferComplete(tvb, 0, &asn_ctx, tree, hf_h450_CallTransferComplete_PDU);
}
static void dissect_CallTransferActive_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  asn_ctx_t asn_ctx;
  asn_ctx_init(&asn_ctx, ASN_ENC_PER, TRUE, pinfo);
  dissect_h450_CallTransferActive(tvb, 0, &asn_ctx, tree, hf_h450_CallTransferActive_PDU);
}
static void dissect_ActivateDiversionQArg_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  asn_ctx_t asn_ctx;
  asn_ctx_init(&asn_ctx, ASN_ENC_PER, TRUE, pinfo);
  dissect_h450_ActivateDiversionQArg(tvb, 0, &asn_ctx, tree, hf_h450_ActivateDiversionQArg_PDU);
}
static void dissect_ActivateDiversionQRes_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  asn_ctx_t asn_ctx;
  asn_ctx_init(&asn_ctx, ASN_ENC_PER, TRUE, pinfo);
  dissect_h450_ActivateDiversionQRes(tvb, 0, &asn_ctx, tree, hf_h450_ActivateDiversionQRes_PDU);
}
static void dissect_DeactivateDiversionQRes_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  asn_ctx_t asn_ctx;
  asn_ctx_init(&asn_ctx, ASN_ENC_PER, TRUE, pinfo);
  dissect_h450_DeactivateDiversionQRes(tvb, 0, &asn_ctx, tree, hf_h450_DeactivateDiversionQRes_PDU);
}
static void dissect_InterrogateDiversionQRes_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  asn_ctx_t asn_ctx;
  asn_ctx_init(&asn_ctx, ASN_ENC_PER, TRUE, pinfo);
  dissect_h450_InterrogateDiversionQRes(tvb, 0, &asn_ctx, tree, hf_h450_InterrogateDiversionQRes_PDU);
}
static void dissect_CheckRestrictionRes_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  asn_ctx_t asn_ctx;
  asn_ctx_init(&asn_ctx, ASN_ENC_PER, TRUE, pinfo);
  dissect_h450_CheckRestrictionRes(tvb, 0, &asn_ctx, tree, hf_h450_CheckRestrictionRes_PDU);
}
static void dissect_CallReroutingRes_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  asn_ctx_t asn_ctx;
  asn_ctx_init(&asn_ctx, ASN_ENC_PER, TRUE, pinfo);
  dissect_h450_CallReroutingRes(tvb, 0, &asn_ctx, tree, hf_h450_CallReroutingRes_PDU);
}


/*--- End of included file: packet-h450-fn.c ---*/
#line 307 "packet-h450-template.c"

static const value_string InvokeProblem_vals[] = {
   {  0, "duplicateInvocation"},
   {  1, "unrecognizedOperation"},
   {  2, "mistypedArgument"},
   {  3, "resourceLimitation"},
   {  4, "releaseInProgress"},
   {  5, "unrecognizedLinkedId"},
   {  6, "linkedResponseUnexpected"},
   {  7, "unexpectedLinkedOperation"},
   {  0, NULL }
};
static int
dissect_h4501_InvokeProblem(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree)
{
   offset=dissect_per_constrained_integer(tvb, offset, actx, tree, hf_h4501_InvokeProblem, 0, 7, NULL, FALSE);
   return offset;
}


static const value_string ReturnResultProblem_vals[] = {
   {  0, "unrecognizedInvocation"},
   {  1, "resultResponseUnexpected"},
   {  2, "mistypedResult"},
   {  0, NULL }
};
static int
dissect_h4501_ReturnResultProblem(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree)
{
   offset=dissect_per_constrained_integer(tvb, offset, actx, tree, hf_h4501_ReturnResultProblem, 0, 2, NULL, FALSE);
   return offset;
}


static const value_string ReturnErrorProblem_vals[] = {
   {  0, "unrecognizedInvocation"},
   {  1, "errorResponseUnexpected"},
   {  2, "unrecognizedError"},
   {  3, "unexpectedError"},
   {  4, "mistypedParameter"},
   {  0, NULL }
};
static int
dissect_h4501_ReturnErrorProblem(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree)
{
   offset=dissect_per_constrained_integer(tvb, offset, actx, tree, hf_h4501_ReturnErrorProblem, 0, 4, NULL, FALSE);
   return offset;
}

static const value_string GeneralProblem_vals[] = {
   {  0, "unrecognizedCompenent"},
   {  1, "mistypedCompenent"},
   {  2, "badlyStructuredCompenent"},
   {  0, NULL }
};
static int
dissect_h4501_GeneralProblem(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree)
{
   offset=dissect_per_constrained_integer(tvb, offset, actx, tree, hf_h4501_GeneralProblem, 0, 2, NULL, FALSE);
   return offset;
}
static int
dissect_h4501_ReturnResult_result(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree)
{
   tvbuff_t *result_tvb = NULL;

   offset=dissect_per_octet_string(tvb, offset, actx, tree, -1, NO_BOUND, NO_BOUND, &result_tvb);

   if(tvb_length(result_tvb)){
      switch (localOpcode) {
      case CallTransferIdentify:
         dissect_h450_CTIdentifyRes(result_tvb, 0, actx, tree, hf_h4502_CTIdentifyRes);
         break;

      case CallTransferInitiate:
      case CallTransferSetup:
         dissect_h450_DummyRes(result_tvb, 0, actx , tree, hf_h4502_DummyRes);
         break;

	  case ActivateDiversionQ:
		  dissect_ActivateDiversionQRes_PDU(result_tvb, actx->pinfo, tree);
		  break;
	  case DeactivateDiversionQ:
		  dissect_DeactivateDiversionQRes_PDU(result_tvb, actx->pinfo, tree);
		  break;
	  case InterrogateDiversionQ:
		  dissect_InterrogateDiversionQRes_PDU(result_tvb, actx->pinfo, tree);
		  break;
	  case CheckRestriction:
		  dissect_CheckRestrictionRes_PDU(result_tvb, actx->pinfo, tree);
		  break;
	  case CallRerouting:
		  dissect_CallReroutingRes_PDU(result_tvb, actx->pinfo, tree);
		  break;

	case RemoteRetrieve:
         dissect_h450_RemoteRetrieveRes(result_tvb, 0, actx , tree, hf_h4504_RemoteRetrieveRes);
         break;
	case MWIActivate:
		dissect_h450_MwiDummyRes(result_tvb, 0, actx , tree, hf_h4507_MwiDummyRes);
		break;
	case MWIDeactivate:
		dissect_h450_MwiDummyRes(result_tvb, 0, actx , tree, hf_h4507_MwiDummyRes);
		break;
	case MWIInterrogate:
		dissect_h450_MWIInterrogateRes(result_tvb, 0, actx , tree, hf_h4507_MWIInterrogateRes);
		break;

      default:
PER_NOT_DECODED_YET("Unrecognized H.450.x return result");
         break;
      }
   }

   return offset;
}

static int
dissect_h4501_localOpcode(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree)
{
   offset=dissect_per_integer(tvb, offset, actx, tree, hf_h4501_localOpcode, &localOpcode);
   is_globalcode = FALSE;
	return offset;
}


static int
dissect_h4501_globalCode(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree)
{
	offset=dissect_per_object_identifier_str(tvb, offset, actx, tree, hf_h4501_globalCode, &globalcode_oid_str);
	is_globalcode = TRUE;
   return offset;
}


static const value_string opcode_vals[] = {
	{ 0, "local" },
	{ 1, "global" },
	{ 0, NULL}
};
static const per_choice_t opcode_choice[] = {
	{ 0, "local", ASN1_NO_EXTENSIONS,
		dissect_h4501_localOpcode },
	{ 1, "global", ASN1_NO_EXTENSIONS,
		dissect_h4501_globalCode },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h4501_opcode(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree)
{
   offset=dissect_per_choice(tvb, offset, actx, tree, hf_h4501_opcode, ett_h4501_opcode, opcode_choice, NULL);
   return offset;
}

static const per_sequence_t result_sequence[] = {
	{ "opcode", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h4501_opcode },
	{ "result", ASN1_EXTENSION_ROOT, ASN1_NOT_OPTIONAL,
		dissect_h4501_ReturnResult_result },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h4501_result(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree)
{
   offset=dissect_per_sequence(tvb, offset, actx, tree, hf_h4501_result, ett_h4501_result, result_sequence);
   return offset;
}

static int
dissect_h4501_parameter(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree)
{
   /* TODO - decode return error parameter based on localErrorCode */
   offset=dissect_per_octet_string(tvb, offset, actx, tree, hf_h4501_parameter, NO_BOUND, NO_BOUND, NULL);
   return offset;
}
static const value_string localErrorCode_vals[] = {
   /* H.450.1 general error list */
   {    0, "userNotSubscribed"},
   {    1, "RejectedByNetwork"},
   {    2, "RejectedByUser"},
   {    3, "NotAvailable"},
   {    5, "InsufficientInformation"},
   {    6, "InvalidServedUserNumber"},
   {    7, "InvalidCallState"},
   {    8, "BasicServiceNotProvided"},
   {    9, "NotIncomingCall"},
   {   10, "SupplementaryServiceInteractionNotAllowed"},
   {   11, "ResourceUnavailable"},
   {   25, "CallFailure"},
   {   43, "ProceduralError"},

   /* H.450.2 Call Transfer return errors */
   { 1004, "invalidReroutingNumber"},
   { 1005, "unrecognizedCallIdentity"},
   { 1006, "establishmentFailure"},
   { 1008, "unspecified"},

   /* H.450.4 Call Hold return errors */
   { 2002, "undefined"},

   /* H.450.5 Call Park and Pickup return errors */
   { 2000, "callPickupIdInvalid"},
   { 2001, "callAlreadyPickedUp"},

   /* H.450.7 Message Waiting Indication return errors */
   { 1018, "invalidMsgCentreId"},
   {   31, "notActivated"},    

   /* H.450.9 Call Completion return errors */
   { 1010, "shortTermRejection"},
   { 1011, "longTermRejection"},
   { 1012, "remoteUserBusyAgain"},
   { 1013, "failureToMatch"},    

   /* H.450.11 Call Intrusion return errors */
   { 1009, "notBusy"},
   { 1000, "temporarilyUnavailable"},
   { 1007, "notAuthorized"},

   /* TODO - add other H.450.x error codes here */

   {  0, NULL }
};
static int
dissect_h4501_localErrorCode(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree)
{
   offset=dissect_per_integer(tvb, offset, actx, tree, hf_h4501_localErrorCode, &localErrorCode);
	return offset;
}


static const value_string errorCode_vals[] = {
	{ 0, "local" },
	{ 1, "global" },
	{ 0, NULL}
};
static const per_choice_t errorCode_choice[] = {
	{ 0, "local", ASN1_NO_EXTENSIONS,
		dissect_h4501_localErrorCode },
	{ 1, "global", ASN1_NO_EXTENSIONS,
		dissect_h4501_globalCode },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h4501_errorCode(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree)
{
   offset=dissect_per_choice(tvb, offset, actx, tree, hf_h4501_errorCode, ett_h4501_errorCode, errorCode_choice, NULL);
   return offset;
}

static const value_string problem_vals[] = {
	{ 0, "general" },
	{ 1, "invoke" },
	{ 2, "returnResult" },
	{ 3, "returnError" },
	{ 0, NULL}
};
static const per_choice_t problem_choice[] = {
	{ 0, "general", ASN1_NO_EXTENSIONS,
		dissect_h4501_GeneralProblem },
	{ 1, "invoke", ASN1_NO_EXTENSIONS,
		dissect_h4501_InvokeProblem },
	{ 2, "returnResult", ASN1_NO_EXTENSIONS,
		dissect_h4501_ReturnResultProblem },
	{ 3, "returnError", ASN1_NO_EXTENSIONS,
		dissect_h4501_ReturnErrorProblem },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h4501_problem(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree)
{
   offset=dissect_per_choice(tvb, offset, actx, tree, hf_h4501_problem, ett_h4501_problem, problem_choice, NULL);
   return offset;
}
static int
dissect_h4501_constrained_invokeId(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree)
{
   offset=dissect_per_constrained_integer(tvb, offset, actx, tree, hf_h4501_constrained_invokeId, 0, 65535, NULL, FALSE);
	return offset;
}


static int
dissect_h4501_invokeId(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree)
{
   offset=dissect_per_integer(tvb, offset, actx, tree, hf_h4501_invokeId, NULL);
	return offset;
}

static const per_sequence_t Reject_sequence[] = {
	{ "invokeID", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h4501_invokeId },
	{ "problem", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h4501_problem },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h4501_Reject(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree)
{
   offset=dissect_per_sequence(tvb, offset, actx, tree, hf_h4501_Reject, ett_h4501_Reject, Reject_sequence);
   return offset;
}

static const per_sequence_t ReturnError_sequence[] = {
	{ "invokeID", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h4501_invokeId },
	{ "errorCode", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h4501_errorCode },
	{ "parameter", ASN1_NO_EXTENSIONS, ASN1_OPTIONAL,
		dissect_h4501_parameter },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h4501_ReturnError(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree)
{
   offset=dissect_per_sequence(tvb, offset, actx, tree, hf_h4501_ReturnError, ett_h4501_ReturnError, ReturnError_sequence);
   return offset;
}

static const per_sequence_t ReturnResult_sequence[] = {
	{ "invokeID", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h4501_invokeId },
	{ "result", ASN1_NO_EXTENSIONS, ASN1_OPTIONAL,
		dissect_h4501_result },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h4501_ReturnResult(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree)
{
   offset=dissect_per_sequence(tvb, offset, actx, tree, hf_h4501_ReturnResult, ett_h4501_ReturnResult, ReturnResult_sequence);
   return offset;
}

static const per_sequence_t Invoke_sequence[] = {
	{ "invokeID", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h4501_constrained_invokeId },
	{ "linkedId", ASN1_NO_EXTENSIONS, ASN1_OPTIONAL,
		dissect_h4501_invokeId },
	{ "opcode", ASN1_NO_EXTENSIONS, ASN1_NOT_OPTIONAL,
		dissect_h4501_opcode },
	{ "argument", ASN1_NO_EXTENSIONS, ASN1_OPTIONAL,
		dissect_h4501_argument },
	{ NULL, 0, 0, NULL }
};
static int
dissect_h4501_Invoke(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree)
{
   offset=dissect_per_sequence(tvb, offset, actx, tree, hf_h4501_Invoke, ett_h4501_Invoke, Invoke_sequence);
   return offset;
}

static const value_string ROS_vals[] = {
	{ 1, "invoke" },
	{ 2, "returnResult" },
	{ 3, "returnError" },
	{ 4, "reject" },
	{ 0, NULL}
};
static const per_choice_t ROS_choice[] = {
	{ 1, "invoke", ASN1_NO_EXTENSIONS,
		dissect_h4501_Invoke },
	{ 2, "returnResult", ASN1_NO_EXTENSIONS,
		dissect_h4501_ReturnResult },
	{ 3, "returnError", ASN1_NO_EXTENSIONS,
		dissect_h4501_ReturnError },
	{ 4, "reject", ASN1_NO_EXTENSIONS,
		dissect_h4501_Reject },
	{ 0, NULL, 0, NULL }
};
static int
dissect_h4501_ROS(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree)
{
   offset=dissect_per_choice(tvb, offset, actx, tree, hf_h4501_ROS, ett_h4501_ROS, ROS_choice, NULL);
   return offset;
}

static int
dissect_h4501_argument(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree)
{
   tvbuff_t *argument_tvb = NULL;

  if ( is_globalcode ){
	  /* TODO call oid dissector
	   * call_ber_oid_callback isn't realy apropriate ?
	   */
	  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_h4501_globalargument, NO_BOUND, NO_BOUND, NULL);
	  is_globalcode = FALSE;
	  return offset;

  }

   offset=dissect_per_octet_string(tvb, offset, actx, tree, -1, NO_BOUND, NO_BOUND, &argument_tvb);

   if(tvb_length(argument_tvb)){
      switch (localOpcode) {
		  /* h450.2 */
		  case CallTransferIdentify:  /* Localvalue 7 */
			  dissect_CallTransferIdentify_PDU(argument_tvb, actx->pinfo, tree);
			  break;
	      case CallTransferAbandon:   /* Localvalue 8 */
			  dissect_CallTransferAbandon_PDU(argument_tvb, actx->pinfo, tree);
			  break;
		   case CallTransferInitiate:  /* Localvalue 9 */
			  dissect_CallTransferInitiate_PDU(argument_tvb, actx->pinfo, tree);
			  break;
	      case CallTransferSetup:		/* Localvalue 10 */
			  dissect_CallTransferSetup_PDU(argument_tvb, actx->pinfo, tree);
			  break;
	      case CallTransferUpdate:		/* Localvalue 13 */
			  dissect_CallTransferUpdate_PDU(argument_tvb, actx->pinfo, tree);
			  break;
		  case SubaddressTransfer:		/* Localvalue 14 */
			  dissect_SubaddressTransfer_PDU(argument_tvb, actx->pinfo, tree);
			  break;
	      case CallTransferComplete:	/* Localvalue 12 */
			  dissect_CallTransferComplete_PDU(argument_tvb, actx->pinfo, tree);
			  break;
	      case CallTransferActive:		/* Localvalue 11 */
			  dissect_CallTransferActive_PDU(argument_tvb, actx->pinfo, tree);
			  break;
		  /* h450.3*/
		  case ActivateDiversionQ:          /* Localvalue 15 */
			  dissect_ActivateDiversionQArg_PDU(argument_tvb, actx->pinfo, tree);
			  break;
		  case DeactivateDiversionQ:        /* Localvalue 16 */
	         dissect_h450_DeactivateDiversionQArg(argument_tvb, 0, actx , tree, hf_h4503DeactivateDiversionQArg);
		     break;
		  case InterrogateDiversionQ:       /* Localvalue 17 */
	         dissect_h450_InterrogateDiversionQ(argument_tvb, 0, actx , tree, hf_h4503InterrogateDiversionQ);
		     break;
		  case CheckRestriction:            /* Localvalue 18 */
	         dissect_h450_CheckRestrictionArg(argument_tvb, 0, actx , tree, hf_h4503CheckRestrictionArg);
		     break;
		  case CallRerouting:               /* Localvalue 19 */
	         dissect_h450_CallReroutingArg(argument_tvb, 0, actx , tree, hf_h4503CallReroutingArg);
		     break;
		  case DivertingLegInformation1:    /* Localvalue 20 */
	         dissect_h450_DivertingLegInformation1Arg(argument_tvb, 0, actx , tree, hf_h4503DivertingLegInformation1Arg);
		     break;
		  case DivertingLegInformation2:   /* Localvalue 21 */
	         dissect_h450_DivertingLegInformation2Arg(argument_tvb, 0, actx , tree, hf_h4503DivertingLegInformation2Arg);
		     break;
		  case DivertingLegInformation3:   /* Localvalue 22 */
	         dissect_h450_DivertingLegInformation3Arg(argument_tvb, 0, actx , tree, hf_h4503DivertingLegInformation3Arg);
		     break;
		  case DivertingLegInformation4:    /* Localvalue 100 */
	         dissect_h450_DivertingLegInformation4Arg(argument_tvb, 0, actx , tree, hf_h4503DivertingLegInformation4Arg);
		     break;
		  case CfnrDivertedLegFailed:       /* Localvalue 23 */
	         dissect_h450_CfnrDivertedLegFailedArg(argument_tvb, 0, actx , tree, hf_h4503CfnrDivertedLegFailedArg);
		     break;
		  /* H.450.4 Call Hold */
	      case HoldNotific:				/* Localvalue 101 */
			   dissect_h450_HoldNotificArg(argument_tvb, 0, actx , tree, hf_h4504_HoldNotificArg);
		     break;
	      case RetrieveNotific:			/* Localvalue 102 */
			   dissect_h450_RetrieveNotificArg(argument_tvb, 0, actx , tree, hf_h4504_RetrieveNotificArg);
		     break;
	      case RemoteHold:				/* Localvalue 103 */
			   dissect_h450_RemoteHoldArg(argument_tvb, 0, actx , tree, hf_h4504_RemoteHoldArg);
		     break;
	      case RemoteRetrieve:			/* Localvalue 104 */
			   dissect_h450_RemoteRetrieveArg(argument_tvb, 0, actx , tree, hf_h4504_RemoteRetrieveArg);
		     break;

/* H.450.5 Call Park and Pickup constants */
		  case CpRequest:                   /* Localvalue 106 */
		  case CpSetup:                     /* Localvalue 107 */
		  case GroupIndicationOn:           /* Localvalue 108 */
		  case GroupIndicationOff:          /* Localvalue 109 */
		  case Pickrequ:                    /* Localvalue 110 */
		  case Pickup:                      /* Localvalue 111 */
		  case PickExe:                     /* Localvalue 112 */
		  case CpNotify:                    /* Localvalue 113 */
		  case CpickupNotify:               /* Localvalue 114 */

/* H.450.6 Call Waiting constants */
		  case CallWaiting:                 /* Localvalue 105 */
PER_NOT_DECODED_YET("Unrecognized H.450.x operation");
	         break;

		  /* H.450.7 Message Waiting Indication  */
		  case MWIActivate:				/* Localvalue 80 */
			   dissect_h450_MWIActivateArg(argument_tvb, 0, actx , tree, hf_h4507_MWIActivateArg);
		     break;
		  case MWIDeactivate:			/* Localvalue 81 */
			   dissect_h450_MWIDeactivateArg(argument_tvb, 0, actx , tree, hf_h4507_MWIDeactivateArg);
		     break;
		  case MWIInterrogate:			/* Localvalue 82 */
			   dissect_h450_MWIInterrogateArg(argument_tvb, 0, actx , tree, hf_h4507_MWIInterrogateArg);
		     break;

		  /* H.450.8 Name Identification */
		  case NIcallingName:			/* Localvalue 0 */
			  dissect_h450_NameArg(argument_tvb, 0, actx , tree, hf_h4508_CallingNameArg);
			  break;
		  case NIalertingName:			/* Localvalue 1 */
			  dissect_h450_NameArg(argument_tvb, 0, actx , tree, hf_h4508_AlertingNameArg);
			  break;
		  case NIconnectedName:			/* Localvalue 2 */
			  dissect_h450_NameArg(argument_tvb, 0, actx , tree, hf_h4508_ConnectedNameArg);
			  break;
		  case NIbusyName:			/* Localvalue 3 */
			  dissect_h450_NameArg(argument_tvb, 0, actx , tree, hf_h4508_BusyNameArg);
			  break;

/* H.450.9 Call Completion constants */
		  case CCBSRequest:                 /* Localvalue 40 */
		  case CCNRRequest:                 /* Localvalue 27 */
		  case CCCancel:                    /* Localvalue 28 */
		  case CCExecPossible:              /* Localvalue 29 */
		  case CCRingout:                   /* Localvalue 31 */
		  case CCSuspend:                   /* Localvalue 32 */
		  case CCResume:                    /* Localvalue 33 */ 

/* H.450.10 Call Offer constants */
		  case CallOfferRequest:            /* Localvalue 34 */
		  case RemoteUserAlerting:          /* Localvalue 115 */
		  case CFBOverride:                 /* Localvalue 49  */

/* H.450.11 Call Intrusion constants */
		  case CallIntrusionRequest:        /* Localvalue 43 */
		  case CallIntrusionGetCIPL:        /* Localvalue 44 */
		  case CallIntrusionIsolate:        /* Localvalue 45 */
		  case CallIntrusionForcedRelease:  /* Localvalue 46 */
		  case CallIntrusionWOBRequest:     /* Localvalue 47 */
		  case CallIntrusionSilentMonitor:  /* Localvalue 116 */
		  case CallIntrusionNotification:   /* Localvalue 117 */
PER_NOT_DECODED_YET("Unrecognized H.450.x operation");
break;
/* H.450.12 Common Information Operations constants */
		  case CmnRequest:					/* Localvalue 84 */
			  dissect_h450_CmnRequestArg(argument_tvb, 0, actx , tree, hf_h45012_CmnRequest);
			  break;
		  case CmnInform:					/* Localvalue 85 */
			  dissect_h450_CmnArg(argument_tvb, 0, actx , tree, hf_h45012_CmnInform);
			  break;

	      /* TODO - decode other H.450.x invoke arguments here */
	     default:
PER_NOT_DECODED_YET("Unrecognized H.450.x operation");
	         break;
	  }
  }
   return offset;
}
static int 
dissect_ros_ROSxxx(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree, int hf_ind _U_){

	offset = dissect_h4501_ROS(tvb, offset, actx, tree);
	return offset;

}
static void
dissect_h4501(tvbuff_t *tvb, packet_info *pinfo, proto_tree* tree)
{
   proto_item *it;
   proto_tree *tr;
   guint32 offset=0;
   asn_ctx_t asn_ctx;

   it=proto_tree_add_protocol_format(tree, proto_h4501, tvb, 0, -1, "H.450.1");
   tr=proto_item_add_subtree(it, ett_h4501);

   asn_ctx_init(&asn_ctx, ASN_ENC_PER, TRUE, pinfo);
   dissect_h450_H4501SupplementaryService(tvb, offset, &asn_ctx, tr, hf_h4501);
}

/*--- proto_register_h450 -------------------------------------------*/
void proto_register_h450(void) {

  /* List of fields */
	static hf_register_info hf[] = {
   { &hf_h4501,
      { "SupplementaryService", "h4501.SupplementaryService", FT_NONE, BASE_NONE,
      NULL, 0, "SupplementaryService sequence", HFILL }},
  { &hf_h4501_constrained_invokeId,
      { "invokeId", "h4501.invokeId", FT_UINT32, BASE_DEC,
      NULL, 0, "invokeId", HFILL }},
   { &hf_h4501_invokeId,
      { "invokeId", "h4501.invokeId", FT_INT32, BASE_DEC,
      NULL, 0, "invokeId", HFILL }},
   { &hf_h4501_localOpcode,
      { "opcode", "h4501.opcode", FT_INT32, BASE_DEC,
      VALS(localOpcode_vals), 0, "local", HFILL }},
   { &hf_h4501_globalCode,
      { "global", "h4501.global", FT_STRING, BASE_HEX,
      NULL, 0, "global", HFILL }},
   { &hf_h4501_globalargument,
      { "argument", "h4501.argument", FT_BYTES, BASE_HEX,
      NULL, 0, "argument", HFILL }},
   { &hf_h4501_opcode,
      { "opcode", "h4501.opcode", FT_UINT32, BASE_DEC,
      VALS(opcode_vals), 0, "opcode choice", HFILL }},
   { &hf_h4501_ReturnResult_result,
      { "result", "h4501.ReturnResult.result", FT_BYTES, BASE_HEX,
      NULL, 0, "result", HFILL }},
   { &hf_h4501_result,
      { "result", "h4501.result", FT_NONE, BASE_NONE,
      NULL, 0, "result sequence of", HFILL }},
   { &hf_h4501_ReturnResult,
      { "ReturnResult", "h4501.ReturnResult", FT_NONE, BASE_NONE,
      NULL, 0, "ReturnResult sequence of", HFILL }},
   { &hf_h4501_localErrorCode,
      { "errorCode", "h4501.errorCode", FT_INT32, BASE_DEC,
      VALS(localErrorCode_vals), 0, "local", HFILL }},
   { &hf_h4501_errorCode,
      { "errorCode", "h4501.errorCode", FT_UINT32, BASE_DEC,
      VALS(errorCode_vals), 0, "errorCode", HFILL }},
   { &hf_h4501_parameter,
      { "parameter", "h4501.parameter", FT_BYTES, BASE_HEX,
      NULL, 0, "parameter", HFILL }},
   { &hf_h4501_ReturnError,
      { "ReturnError", "h4501.ReturnError", FT_NONE, BASE_NONE,
      NULL, 0, "ReturnError sequence of", HFILL }},
   { &hf_h4501_GeneralProblem,
      { "GeneralProblem", "h4501.GeneralProblem", FT_UINT32, BASE_DEC,
      VALS(GeneralProblem_vals), 0, "GeneralProblem", HFILL }},
   { &hf_h4501_InvokeProblem,
      { "InvokeProblem", "h4501.InvokeProblem", FT_UINT32, BASE_DEC,
      VALS(InvokeProblem_vals), 0, "InvokeProblem", HFILL }},
   { &hf_h4501_ReturnResultProblem,
      { "ReturnResultProblem", "h4501.ReturnResultProblem", FT_UINT32, BASE_DEC,
      VALS(ReturnResultProblem_vals), 0, "ReturnResultProblem", HFILL }},
   { &hf_h4501_ReturnErrorProblem,
      { "ReturnErrorProblem", "h4501.ReturnErrorProblem", FT_UINT32, BASE_DEC,
      VALS(ReturnErrorProblem_vals), 0, "ReturnErrorProblem", HFILL }},
   { &hf_h4501_problem,
      { "problem", "h4501.problem", FT_UINT32, BASE_DEC,
      VALS(problem_vals), 0, "problem choice", HFILL }},
   { &hf_h4501_Reject,
      { "Reject", "h4501.Reject", FT_NONE, BASE_NONE,
      NULL, 0, "Reject sequence of", HFILL }},
   { &hf_h4501_ROS,
      { "ROS", "h4501.ROS", FT_UINT32, BASE_DEC,
      VALS(ROS_vals), 0, "ROS choice", HFILL }},
   { &hf_h4501_Invoke,
      { "Invoke", "h4501.Invoke", FT_NONE, BASE_NONE,
      NULL, 0, "Invoke sequence of", HFILL }},
   { &hf_h4502_CTIdentifyRes,
      { "CTIdentifyRes", "h4502.CTIdentifyRes", FT_NONE, BASE_NONE,
      NULL, 0, "CTIdentifyRes sequence of", HFILL }},
   { &hf_h4502_DummyRes,
      { "DummyRes", "h4502.DummyRes", FT_UINT32, BASE_DEC,
      VALS(h450_DummyRes_vals), 0, "DummyRes Choice", HFILL }},
   { &hf_h4502_DummyArg,
      { "DummyArg", "h4502.DummyArg", FT_UINT32, BASE_DEC,
      VALS(h450_DummyArg_vals), 0, "DummyArg choice", HFILL }},
   { &hf_h4503DeactivateDiversionQArg,
      { "DeactivateDiversionQArg", "h4503.DeactivateDiversionQArg", FT_NONE, BASE_NONE,
      NULL, 0, "ActivateDiversionQArg sequence of", HFILL }},
   { &hf_h4503InterrogateDiversionQ,
      { "InterrogateDiversionQ", "h4503.InterrogateDiversionQ", FT_NONE, BASE_NONE,
      NULL, 0, "InterrogateDiversionQ sequence of", HFILL }},
   { &hf_h4503CheckRestrictionArg,
      { "CheckRestrictionArg", "h4503.CheckRestrictionArg", FT_NONE, BASE_NONE,
      NULL, 0, "CheckRestrictionArg sequence of", HFILL }},
   { &hf_h4503CallReroutingArg,
      { "CallReroutingArg", "h4503.CallReroutingArg", FT_NONE, BASE_NONE,
      NULL, 0, "ActivateDiversionQArg sequence of", HFILL }},
   { &hf_h4503DivertingLegInformation1Arg,
      { "DivertingLegInformation1Arg", "h4503.DivertingLegInformation1Arg", FT_NONE, BASE_NONE,
      NULL, 0, "DivertingLegInformation1Arg sequence of", HFILL }},
   { &hf_h4503DivertingLegInformation2Arg,
      { "DivertingLegInformation2Arg", "h4503.DivertingLegInformation2Arg", FT_NONE, BASE_NONE,
      NULL, 0, "DivertingLegInformation1Arg sequence of", HFILL }},
   { &hf_h4503DivertingLegInformation3Arg,
      { "DivertingLegInformation3Arg", "h4503.DivertingLegInformation3Arg", FT_NONE, BASE_NONE,
      NULL, 0, "DivertingLegInformation1Arg sequence of", HFILL }},
   { &hf_h4503DivertingLegInformation4Arg,
      { "DivertingLegInformation4Arg", "h4503.DivertingLegInformation4Arg", FT_NONE, BASE_NONE,
      NULL, 0, "DivertingLegInformation4Arg sequence of", HFILL }},
   { &hf_h4503CfnrDivertedLegFailedArg,
      { "CfnrDivertedLegFailedArg", "h4503.CfnrDivertedLegFailedArg", FT_NONE, BASE_NONE,
      NULL, 0, "ActivateDiversionQArg sequence of", HFILL }},

   { &hf_h4504_HoldNotificArg,
      { "HoldNotificArg", "h4504.HoldNotificArg", FT_NONE, BASE_NONE,
      NULL, 0, "HoldNotificArg sequence of", HFILL }},
   { &hf_h4504_RetrieveNotificArg,
      { "RetrieveNotificArg", "h4504.RetrieveNotificArg", FT_NONE, BASE_NONE,
      NULL, 0, "RetrieveNotificArg sequence of", HFILL }},
   { &hf_h4504_RemoteHoldArg,
      { "RemoteHoldArg", "h4504.RemoteHoldArg", FT_NONE, BASE_NONE,
      NULL, 0, "RemoteHoldArg sequence of", HFILL }},
   { &hf_h4504_RemoteRetrieveArg,
      { "RemoteRetrieveArg", "h4504.RemoteRetrieveArg", FT_NONE, BASE_NONE,
      NULL, 0, "RemoteRetrieveArg sequence of", HFILL }},
   { &hf_h4504_RemoteRetrieveRes,
      { "RemoteRetrieveRes", "h4504.RemoteRetrieveRes", FT_NONE, BASE_NONE,
      NULL, 0, "RemoteRetrieveRes sequence of", HFILL }},

   { &hf_h4507_MWIActivateArg,
      { "MWIActivateArg", "h4507.MWIActivateArg", FT_NONE, BASE_NONE,
      NULL, 0, "MWIActivateArg sequence of", HFILL }},
   { &hf_h4507_MwiDummyRes,
      { "MwiDummyRes", "h4507.MwiDummyRes", FT_NONE, BASE_NONE,
      NULL, 0, "MwiDummyRes sequence of", HFILL }},
   { &hf_h4507_MWIDeactivateArg,
      { "MWIDeactivateArg", "h4507.MWIDeactivateArg", FT_NONE, BASE_NONE,
      NULL, 0, "MWIDeactivateArg sequence of", HFILL }},
   { &hf_h4507_MWIInterrogateArg,
      { "MWIInterrogateArg", "h4507.MWIInterrogateArg", FT_NONE, BASE_NONE,
      NULL, 0, "MWIInterrogateArg sequence of", HFILL }},
   { &hf_h4507_MWIInterrogateRes,
      { "MWIInterrogateRes", "h4507.MWIInterrogateRes", FT_NONE, BASE_NONE,
      NULL, 0, "MWIInterrogateRes sequence of", HFILL }},

   { &hf_h4508_CallingNameArg,
      { "CallingNameArg", "h4508.CallingNameArg", FT_NONE, BASE_NONE,
      NULL, 0, "CallingNameArg sequence of", HFILL }},
   { &hf_h4508_AlertingNameArg,
      { "AlertingNameArg", "h4508.AlertingNameArg", FT_NONE, BASE_NONE,
      NULL, 0, "AlertingNameArg sequence of", HFILL }},
   { &hf_h4508_ConnectedNameArg,
      { "ConnectedNameArg", "h4508.ConnectedNameArg", FT_NONE, BASE_NONE,
      NULL, 0, "ConnectedNameArg sequence of", HFILL }},
   { &hf_h4508_BusyNameArg,
      { "BusyNameArg", "h4508.BusyNameArg", FT_NONE, BASE_NONE,
      NULL, 0, "BusyNameArg sequence of", HFILL }},
   { &hf_h45012_CmnRequest,
      { "CmnRequest", "h4508.CmnRequest", FT_NONE, BASE_NONE,
      NULL, 0, "CmnRequest sequence of", HFILL }},
   { &hf_h45012_CmnInform,
      { "CmnRequest", "h4508.CmnRequest", FT_NONE, BASE_NONE,
      NULL, 0, "CmnRequest sequence of", HFILL }},


/*--- Included file: packet-h450-hfarr.c ---*/
#line 1 "packet-h450-hfarr.c"
    { &hf_h450_CallTransferIdentify_PDU,
      { "CallTransferIdentify", "h450.CallTransferIdentify",
        FT_UINT32, BASE_DEC, VALS(h450_DummyArg_vals), 0,
        "CallTransferIdentify", HFILL }},
    { &hf_h450_CallTransferAbandon_PDU,
      { "CallTransferAbandon", "h450.CallTransferAbandon",
        FT_UINT32, BASE_DEC, VALS(h450_DummyArg_vals), 0,
        "CallTransferAbandon", HFILL }},
    { &hf_h450_CallTransferInitiate_PDU,
      { "CallTransferInitiate", "h450.CallTransferInitiate",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallTransferInitiate", HFILL }},
    { &hf_h450_CallTransferSetup_PDU,
      { "CallTransferSetup", "h450.CallTransferSetup",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallTransferSetup", HFILL }},
    { &hf_h450_CallTransferUpdate_PDU,
      { "CallTransferUpdate", "h450.CallTransferUpdate",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallTransferUpdate", HFILL }},
    { &hf_h450_SubaddressTransfer_PDU,
      { "SubaddressTransfer", "h450.SubaddressTransfer",
        FT_NONE, BASE_NONE, NULL, 0,
        "SubaddressTransfer", HFILL }},
    { &hf_h450_CallTransferComplete_PDU,
      { "CallTransferComplete", "h450.CallTransferComplete",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallTransferComplete", HFILL }},
    { &hf_h450_CallTransferActive_PDU,
      { "CallTransferActive", "h450.CallTransferActive",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallTransferActive", HFILL }},
    { &hf_h450_ActivateDiversionQArg_PDU,
      { "ActivateDiversionQArg", "h450.ActivateDiversionQArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "ActivateDiversionQArg", HFILL }},
    { &hf_h450_ActivateDiversionQRes_PDU,
      { "ActivateDiversionQRes", "h450.ActivateDiversionQRes",
        FT_UINT32, BASE_DEC, VALS(h450_ActivateDiversionQRes_vals), 0,
        "ActivateDiversionQRes", HFILL }},
    { &hf_h450_DeactivateDiversionQRes_PDU,
      { "DeactivateDiversionQRes", "h450.DeactivateDiversionQRes",
        FT_UINT32, BASE_DEC, VALS(h450_DeactivateDiversionQRes_vals), 0,
        "DeactivateDiversionQRes", HFILL }},
    { &hf_h450_InterrogateDiversionQRes_PDU,
      { "InterrogateDiversionQRes", "h450.InterrogateDiversionQRes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "InterrogateDiversionQRes", HFILL }},
    { &hf_h450_CheckRestrictionRes_PDU,
      { "CheckRestrictionRes", "h450.CheckRestrictionRes",
        FT_UINT32, BASE_DEC, VALS(h450_CheckRestrictionRes_vals), 0,
        "CheckRestrictionRes", HFILL }},
    { &hf_h450_CallReroutingRes_PDU,
      { "CallReroutingRes", "h450.CallReroutingRes",
        FT_UINT32, BASE_DEC, VALS(h450_CallReroutingRes_vals), 0,
        "CallReroutingRes", HFILL }},
    { &hf_h450_networkFacilityExtension,
      { "networkFacilityExtension", "h450.networkFacilityExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        "H4501SupplementaryService/networkFacilityExtension", HFILL }},
    { &hf_h450_interpretationApdu,
      { "interpretationApdu", "h450.interpretationApdu",
        FT_UINT32, BASE_DEC, VALS(h450_InterpretationApdu_vals), 0,
        "H4501SupplementaryService/interpretationApdu", HFILL }},
    { &hf_h450_serviceApdu,
      { "serviceApdu", "h450.serviceApdu",
        FT_UINT32, BASE_DEC, VALS(h450_ServiceApdus_vals), 0,
        "H4501SupplementaryService/serviceApdu", HFILL }},
    { &hf_h450_sourceEntity,
      { "sourceEntity", "h450.sourceEntity",
        FT_UINT32, BASE_DEC, VALS(h450_EntityType_vals), 0,
        "NetworkFacilityExtension/sourceEntity", HFILL }},
    { &hf_h450_sourceEntityAddress,
      { "sourceEntityAddress", "h450.sourceEntityAddress",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "NetworkFacilityExtension/sourceEntityAddress", HFILL }},
    { &hf_h450_destinationEntity,
      { "destinationEntity", "h450.destinationEntity",
        FT_UINT32, BASE_DEC, VALS(h450_EntityType_vals), 0,
        "NetworkFacilityExtension/destinationEntity", HFILL }},
    { &hf_h450_destinationEntityAddress,
      { "destinationEntityAddress", "h450.destinationEntityAddress",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "NetworkFacilityExtension/destinationEntityAddress", HFILL }},
    { &hf_h450_endpoint,
      { "endpoint", "h450.endpoint",
        FT_NONE, BASE_NONE, NULL, 0,
        "EntityType/endpoint", HFILL }},
    { &hf_h450_anyEntity,
      { "anyEntity", "h450.anyEntity",
        FT_NONE, BASE_NONE, NULL, 0,
        "EntityType/anyEntity", HFILL }},
    { &hf_h450_discardAnyUnrecognizedInvokePdu,
      { "discardAnyUnrecognizedInvokePdu", "h450.discardAnyUnrecognizedInvokePdu",
        FT_NONE, BASE_NONE, NULL, 0,
        "InterpretationApdu/discardAnyUnrecognizedInvokePdu", HFILL }},
    { &hf_h450_clearCallIfAnyInvokePduNotRecognized,
      { "clearCallIfAnyInvokePduNotRecognized", "h450.clearCallIfAnyInvokePduNotRecognized",
        FT_NONE, BASE_NONE, NULL, 0,
        "InterpretationApdu/clearCallIfAnyInvokePduNotRecognized", HFILL }},
    { &hf_h450_rejectAnyUnrecognizedInvokePdu,
      { "rejectAnyUnrecognizedInvokePdu", "h450.rejectAnyUnrecognizedInvokePdu",
        FT_NONE, BASE_NONE, NULL, 0,
        "InterpretationApdu/rejectAnyUnrecognizedInvokePdu", HFILL }},
    { &hf_h450_rosApdus,
      { "rosApdus", "h450.rosApdus",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ServiceApdus/rosApdus", HFILL }},
    { &hf_h450_rosApdus_item,
      { "Item", "h450.rosApdus_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServiceApdus/rosApdus/_item", HFILL }},
    { &hf_h450_addressScreened_presentationAllowedAddress,
      { "presentationAllowedAddress", "h450.presentationAllowedAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "PresentedAddressScreened/presentationAllowedAddress", HFILL }},
    { &hf_h450_presentationRestricted,
      { "presentationRestricted", "h450.presentationRestricted",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h450_numberNotAvailableDueToInterworking,
      { "numberNotAvailableDueToInterworking", "h450.numberNotAvailableDueToInterworking",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h450_addressScreened_presentationRestrictedAddress,
      { "presentationRestrictedAddress", "h450.presentationRestrictedAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "PresentedAddressScreened/presentationRestrictedAddress", HFILL }},
    { &hf_h450_addressUnscreened_presentationAllowedAddress,
      { "presentationAllowedAddress", "h450.presentationAllowedAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "PresentedAddressUnscreened/presentationAllowedAddress", HFILL }},
    { &hf_h450_addressUnscreened_presentationRestrictedAddress,
      { "presentationRestrictedAddress", "h450.presentationRestrictedAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "PresentedAddressUnscreened/presentationRestrictedAddress", HFILL }},
    { &hf_h450_numberScreened_presentationAllowedAddress,
      { "presentationAllowedAddress", "h450.presentationAllowedAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "PresentedNumberScreened/presentationAllowedAddress", HFILL }},
    { &hf_h450_numberScreened_presentationRestrictedAddress,
      { "presentationRestrictedAddress", "h450.presentationRestrictedAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "PresentedNumberScreened/presentationRestrictedAddress", HFILL }},
    { &hf_h450_numberUnscreened_presentationAllowedAddress,
      { "presentationAllowedAddress", "h450.presentationAllowedAddress",
        FT_UINT32, BASE_DEC, VALS(h225_PartyNumber_vals), 0,
        "PresentedNumberUnscreened/presentationAllowedAddress", HFILL }},
    { &hf_h450_numberUnscreened_presentationRestrictedAddress,
      { "presentationRestrictedAddress", "h450.presentationRestrictedAddress",
        FT_UINT32, BASE_DEC, VALS(h225_PartyNumber_vals), 0,
        "PresentedNumberUnscreened/presentationRestrictedAddress", HFILL }},
    { &hf_h450_partyNumber,
      { "partyNumber", "h450.partyNumber",
        FT_UINT32, BASE_DEC, VALS(h225_PartyNumber_vals), 0,
        "", HFILL }},
    { &hf_h450_screeningIndicator,
      { "screeningIndicator", "h450.screeningIndicator",
        FT_UINT32, BASE_DEC, VALS(h225_ScreeningIndicator_vals), 0,
        "", HFILL }},
    { &hf_h450_partySubaddress,
      { "partySubaddress", "h450.partySubaddress",
        FT_UINT32, BASE_DEC, VALS(h450_PartySubaddress_vals), 0,
        "", HFILL }},
    { &hf_h450_destinationAddress,
      { "destinationAddress", "h450.destinationAddress",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EndpointAddress/destinationAddress", HFILL }},
    { &hf_h450_destinationAddress_item,
      { "Item", "h450.destinationAddress_item",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "EndpointAddress/destinationAddress/_item", HFILL }},
    { &hf_h450_remoteExtensionAddress,
      { "remoteExtensionAddress", "h450.remoteExtensionAddress",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "EndpointAddress/remoteExtensionAddress", HFILL }},
    { &hf_h450_destinationAddressPresentationIndicator,
      { "destinationAddressPresentationIndicator", "h450.destinationAddressPresentationIndicator",
        FT_UINT32, BASE_DEC, VALS(h225_PresentationIndicator_vals), 0,
        "EndpointAddress/destinationAddressPresentationIndicator", HFILL }},
    { &hf_h450_destinationAddressScreeningIndicator,
      { "destinationAddressScreeningIndicator", "h450.destinationAddressScreeningIndicator",
        FT_UINT32, BASE_DEC, VALS(h225_ScreeningIndicator_vals), 0,
        "EndpointAddress/destinationAddressScreeningIndicator", HFILL }},
    { &hf_h450_remoteExtensionAddressPresentationIndicator,
      { "remoteExtensionAddressPresentationIndicator", "h450.remoteExtensionAddressPresentationIndicator",
        FT_UINT32, BASE_DEC, VALS(h225_PresentationIndicator_vals), 0,
        "EndpointAddress/remoteExtensionAddressPresentationIndicator", HFILL }},
    { &hf_h450_remoteExtensionAddressScreeningIndicator,
      { "remoteExtensionAddressScreeningIndicator", "h450.remoteExtensionAddressScreeningIndicator",
        FT_UINT32, BASE_DEC, VALS(h225_ScreeningIndicator_vals), 0,
        "EndpointAddress/remoteExtensionAddressScreeningIndicator", HFILL }},
    { &hf_h450_userSpecifiedSubaddress,
      { "userSpecifiedSubaddress", "h450.userSpecifiedSubaddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "PartySubaddress/userSpecifiedSubaddress", HFILL }},
    { &hf_h450_nsapSubaddress,
      { "nsapSubaddress", "h450.nsapSubaddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PartySubaddress/nsapSubaddress", HFILL }},
    { &hf_h450_subaddressInformation,
      { "subaddressInformation", "h450.subaddressInformation",
        FT_BYTES, BASE_HEX, NULL, 0,
        "UserSpecifiedSubaddress/subaddressInformation", HFILL }},
    { &hf_h450_oddCountIndicator,
      { "oddCountIndicator", "h450.oddCountIndicator",
        FT_BOOLEAN, 8, NULL, 0,
        "UserSpecifiedSubaddress/oddCountIndicator", HFILL }},
    { &hf_h450_extensionSeq,
      { "extensionSeq", "h450.extensionSeq",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h450_nonStandardData,
      { "nonStandardData", "h450.nonStandardData",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h450_callIdentity,
      { "callIdentity", "h450.callIdentity",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h450_reroutingNumber,
      { "reroutingNumber", "h450.reroutingNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h450_cTInitiateArg_argumentExtension,
      { "argumentExtension", "h450.argumentExtension",
        FT_UINT32, BASE_DEC, VALS(h450_ArgumentExtension_vals), 0,
        "CTInitiateArg/argumentExtension", HFILL }},
    { &hf_h450_transferringNumber,
      { "transferringNumber", "h450.transferringNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        "CTSetupArg/transferringNumber", HFILL }},
    { &hf_h450_cTSetupArg_argumentExtension,
      { "argumentExtension", "h450.argumentExtension",
        FT_UINT32, BASE_DEC, VALS(h450_ArgumentExtension_vals), 0,
        "CTSetupArg/argumentExtension", HFILL }},
    { &hf_h450_resultExtension,
      { "resultExtension", "h450.resultExtension",
        FT_UINT32, BASE_DEC, VALS(h450_T_resultExtension_vals), 0,
        "CTIdentifyRes/resultExtension", HFILL }},
    { &hf_h450_redirectionNumber,
      { "redirectionNumber", "h450.redirectionNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h450_redirectionInfo,
      { "redirectionInfo", "h450.redirectionInfo",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h450_basicCallInfoElements,
      { "basicCallInfoElements", "h450.basicCallInfoElements",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_h450_cTUpdateArg_argumentExtension,
      { "argumentExtension", "h450.argumentExtension",
        FT_UINT32, BASE_DEC, VALS(h450_ArgumentExtension_vals), 0,
        "CTUpdateArg/argumentExtension", HFILL }},
    { &hf_h450_redirectionSubaddress,
      { "redirectionSubaddress", "h450.redirectionSubaddress",
        FT_UINT32, BASE_DEC, VALS(h450_PartySubaddress_vals), 0,
        "SubaddressTransferArg/redirectionSubaddress", HFILL }},
    { &hf_h450_subaddressTransferArg_argumentExtension,
      { "argumentExtension", "h450.argumentExtension",
        FT_UINT32, BASE_DEC, VALS(h450_ArgumentExtension_vals), 0,
        "SubaddressTransferArg/argumentExtension", HFILL }},
    { &hf_h450_endDesignation,
      { "endDesignation", "h450.endDesignation",
        FT_UINT32, BASE_DEC, VALS(h450_EndDesignation_vals), 0,
        "CTCompleteArg/endDesignation", HFILL }},
    { &hf_h450_callStatus,
      { "callStatus", "h450.callStatus",
        FT_UINT32, BASE_DEC, VALS(h450_CallStatus_vals), 0,
        "CTCompleteArg/callStatus", HFILL }},
    { &hf_h450_cTCompleteArg_argumentExtension,
      { "argumentExtension", "h450.argumentExtension",
        FT_UINT32, BASE_DEC, VALS(h450_ArgumentExtension_vals), 0,
        "CTCompleteArg/argumentExtension", HFILL }},
    { &hf_h450_connectedAddress,
      { "connectedAddress", "h450.connectedAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "CTActiveArg/connectedAddress", HFILL }},
    { &hf_h450_connectedInfo,
      { "connectedInfo", "h450.connectedInfo",
        FT_STRING, BASE_NONE, NULL, 0,
        "CTActiveArg/connectedInfo", HFILL }},
    { &hf_h450_cTActiveArg_argumentExtension,
      { "argumentExtension", "h450.argumentExtension",
        FT_UINT32, BASE_DEC, VALS(h450_ArgumentExtension_vals), 0,
        "CTActiveArg/argumentExtension", HFILL }},
    { &hf_h450_ExtensionSeq_item,
      { "Item", "h450.ExtensionSeq_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ExtensionSeq/_item", HFILL }},
    { &hf_h450_procedure,
      { "procedure", "h450.procedure",
        FT_UINT32, BASE_DEC, VALS(h450_Procedure_vals), 0,
        "", HFILL }},
    { &hf_h450_basicService,
      { "basicService", "h450.basicService",
        FT_UINT32, BASE_DEC, VALS(h450_BasicService_vals), 0,
        "", HFILL }},
    { &hf_h450_divertedToAddress,
      { "divertedToAddress", "h450.divertedToAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h450_servedUserNr,
      { "servedUserNr", "h450.servedUserNr",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h450_activatingUserNr,
      { "activatingUserNr", "h450.activatingUserNr",
        FT_NONE, BASE_NONE, NULL, 0,
        "ActivateDiversionQArg/activatingUserNr", HFILL }},
    { &hf_h450_activateDiversionQArg_extension,
      { "extension", "h450.extension",
        FT_UINT32, BASE_DEC, VALS(h450_ActivateDiversionQArg_extension_vals), 0,
        "ActivateDiversionQArg/extension", HFILL }},
    { &hf_h450_deactivatingUserNr,
      { "deactivatingUserNr", "h450.deactivatingUserNr",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeactivateDiversionQArg/deactivatingUserNr", HFILL }},
    { &hf_h450_deactivateDiversionQArg_extension,
      { "extension", "h450.extension",
        FT_UINT32, BASE_DEC, VALS(h450_DeactivateDiversionQArg_extension_vals), 0,
        "DeactivateDiversionQArg/extension", HFILL }},
    { &hf_h450_interrogatingUserNr,
      { "interrogatingUserNr", "h450.interrogatingUserNr",
        FT_NONE, BASE_NONE, NULL, 0,
        "InterrogateDiversionQ/interrogatingUserNr", HFILL }},
    { &hf_h450_interrogateDiversionQ_extension,
      { "extension", "h450.extension",
        FT_UINT32, BASE_DEC, VALS(h450_InterrogateDiversionQ_extension_vals), 0,
        "InterrogateDiversionQ/extension", HFILL }},
    { &hf_h450_divertedToNr,
      { "divertedToNr", "h450.divertedToNr",
        FT_NONE, BASE_NONE, NULL, 0,
        "CheckRestrictionArg/divertedToNr", HFILL }},
    { &hf_h450_checkRestrictionArg_extension,
      { "extension", "h450.extension",
        FT_UINT32, BASE_DEC, VALS(h450_CheckRestrictionArg_extension_vals), 0,
        "CheckRestrictionArg/extension", HFILL }},
    { &hf_h450_reroutingReason,
      { "reroutingReason", "h450.reroutingReason",
        FT_UINT32, BASE_DEC, VALS(h450_DiversionReason_vals), 0,
        "CallReroutingArg/reroutingReason", HFILL }},
    { &hf_h450_originalReroutingReason,
      { "originalReroutingReason", "h450.originalReroutingReason",
        FT_UINT32, BASE_DEC, VALS(h450_DiversionReason_vals), 0,
        "CallReroutingArg/originalReroutingReason", HFILL }},
    { &hf_h450_calledAddress,
      { "calledAddress", "h450.calledAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallReroutingArg/calledAddress", HFILL }},
    { &hf_h450_diversionCounter,
      { "diversionCounter", "h450.diversionCounter",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h450_h225InfoElement,
      { "h225InfoElement", "h450.h225InfoElement",
        FT_BYTES, BASE_HEX, NULL, 0,
        "CallReroutingArg/h225InfoElement", HFILL }},
    { &hf_h450_lastReroutingNr,
      { "lastReroutingNr", "h450.lastReroutingNr",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallReroutingArg/lastReroutingNr", HFILL }},
    { &hf_h450_subscriptionOption,
      { "subscriptionOption", "h450.subscriptionOption",
        FT_UINT32, BASE_DEC, VALS(h450_SubscriptionOption_vals), 0,
        "", HFILL }},
    { &hf_h450_callingPartySubaddress,
      { "callingPartySubaddress", "h450.callingPartySubaddress",
        FT_UINT32, BASE_DEC, VALS(h450_PartySubaddress_vals), 0,
        "CallReroutingArg/callingPartySubaddress", HFILL }},
    { &hf_h450_callingNumber,
      { "callingNumber", "h450.callingNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallReroutingArg/callingNumber", HFILL }},
    { &hf_h450_callingInfo,
      { "callingInfo", "h450.callingInfo",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h450_originalCalledNr,
      { "originalCalledNr", "h450.originalCalledNr",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h450_redirectingInfo,
      { "redirectingInfo", "h450.redirectingInfo",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h450_originalCalledInfo,
      { "originalCalledInfo", "h450.originalCalledInfo",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h450_callReroutingArg_extension,
      { "extension", "h450.extension",
        FT_UINT32, BASE_DEC, VALS(h450_CallReroutingArg_extension_vals), 0,
        "CallReroutingArg/extension", HFILL }},
    { &hf_h450_diversionReason,
      { "diversionReason", "h450.diversionReason",
        FT_UINT32, BASE_DEC, VALS(h450_DiversionReason_vals), 0,
        "", HFILL }},
    { &hf_h450_nominatedNr,
      { "nominatedNr", "h450.nominatedNr",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h450_nominatedInfo,
      { "nominatedInfo", "h450.nominatedInfo",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h450_redirectingNr,
      { "redirectingNr", "h450.redirectingNr",
        FT_NONE, BASE_NONE, NULL, 0,
        "DivertingLegInformation1Arg/redirectingNr", HFILL }},
    { &hf_h450_divertingLegInformation1Arg_extension,
      { "extension", "h450.extension",
        FT_UINT32, BASE_DEC, VALS(h450_DivertingLegInformation1Arg_extension_vals), 0,
        "DivertingLegInformation1Arg/extension", HFILL }},
    { &hf_h450_originalDiversionReason,
      { "originalDiversionReason", "h450.originalDiversionReason",
        FT_UINT32, BASE_DEC, VALS(h450_DiversionReason_vals), 0,
        "DivertingLegInformation2Arg/originalDiversionReason", HFILL }},
    { &hf_h450_divertingNr,
      { "divertingNr", "h450.divertingNr",
        FT_NONE, BASE_NONE, NULL, 0,
        "DivertingLegInformation2Arg/divertingNr", HFILL }},
    { &hf_h450_extension,
      { "extension", "h450.extension",
        FT_UINT32, BASE_DEC, VALS(h450_DivertingLegInformation2Arg_extension_vals), 0,
        "DivertingLegInformation2Arg/extension", HFILL }},
    { &hf_h450_presentationAllowedIndicator,
      { "presentationAllowedIndicator", "h450.presentationAllowedIndicator",
        FT_BOOLEAN, 8, NULL, 0,
        "DivertingLegInformation3Arg/presentationAllowedIndicator", HFILL }},
    { &hf_h450_redirectionNr,
      { "redirectionNr", "h450.redirectionNr",
        FT_NONE, BASE_NONE, NULL, 0,
        "DivertingLegInformation3Arg/redirectionNr", HFILL }},
    { &hf_h450_divertingLegInformation3Arg_extension,
      { "extension", "h450.extension",
        FT_UINT32, BASE_DEC, VALS(h450_DivertingLegInformation3Arg_extension_vals), 0,
        "DivertingLegInformation3Arg/extension", HFILL }},
    { &hf_h450_callingNr,
      { "callingNr", "h450.callingNr",
        FT_NONE, BASE_NONE, NULL, 0,
        "DivertingLegInformation4Arg/callingNr", HFILL }},
    { &hf_h450_divertingLegInformation4Arg_extension,
      { "extension", "h450.extension",
        FT_UINT32, BASE_DEC, VALS(h450_DivertingLegInformation4Arg_extension_vals), 0,
        "DivertingLegInformation4Arg/extension", HFILL }},
    { &hf_h450_IntResultList_item,
      { "Item", "h450.IntResultList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "IntResultList/_item", HFILL }},
    { &hf_h450_remoteEnabled,
      { "remoteEnabled", "h450.remoteEnabled",
        FT_BOOLEAN, 8, NULL, 0,
        "IntResult/remoteEnabled", HFILL }},
    { &hf_h450_intResult_extension,
      { "extension", "h450.extension",
        FT_UINT32, BASE_DEC, VALS(h450_IntResult_extension_vals), 0,
        "IntResult/extension", HFILL }},
    { &hf_h450_holdNotificArg_extensionArg,
      { "extensionArg", "h450.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "HoldNotificArg/extensionArg", HFILL }},
    { &hf_h450_extensionArg_item,
      { "Item", "h450.extensionArg_item",
        FT_UINT32, BASE_DEC, VALS(h450_MixedExtension_vals), 0,
        "", HFILL }},
    { &hf_h450_retrieveNotificArg_extensionArg,
      { "extensionArg", "h450.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RetrieveNotificArg/extensionArg", HFILL }},
    { &hf_h450_remoteHoldArg_extensionArg,
      { "extensionArg", "h450.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RemoteHoldArg/extensionArg", HFILL }},
    { &hf_h450_extensionRes,
      { "extensionRes", "h450.extensionRes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h450_extensionRes_item,
      { "Item", "h450.extensionRes_item",
        FT_UINT32, BASE_DEC, VALS(h450_MixedExtension_vals), 0,
        "", HFILL }},
    { &hf_h450_remoteRetrieveArg_extensionArg,
      { "extensionArg", "h450.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RemoteRetrieveArg/extensionArg", HFILL }},
    { &hf_h450_mixedExtension_extension,
      { "extension", "h450.extension",
        FT_NONE, BASE_NONE, NULL, 0,
        "MixedExtension/extension", HFILL }},
    { &hf_h450_parkingNumber,
      { "parkingNumber", "h450.parkingNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h450_parkedNumber,
      { "parkedNumber", "h450.parkedNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h450_parkedToNumber,
      { "parkedToNumber", "h450.parkedToNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h450_parkedToPosition,
      { "parkedToPosition", "h450.parkedToPosition",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h450_cpRequestArg_extensionArg,
      { "extensionArg", "h450.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CpRequestArg/extensionArg", HFILL }},
    { &hf_h450_parkCondition,
      { "parkCondition", "h450.parkCondition",
        FT_UINT32, BASE_DEC, VALS(h450_ParkCondition_vals), 0,
        "", HFILL }},
    { &hf_h450_cpSetupArg_extensionArg,
      { "extensionArg", "h450.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CpSetupArg/extensionArg", HFILL }},
    { &hf_h450_callPickupId,
      { "callPickupId", "h450.callPickupId",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h450_groupMemberUserNr,
      { "groupMemberUserNr", "h450.groupMemberUserNr",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h450_retrieveCallType,
      { "retrieveCallType", "h450.retrieveCallType",
        FT_UINT32, BASE_DEC, VALS(h450_CallType_vals), 0,
        "GroupIndicationOnArg/retrieveCallType", HFILL }},
    { &hf_h450_partyToRetrieve,
      { "partyToRetrieve", "h450.partyToRetrieve",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h450_retrieveAddress,
      { "retrieveAddress", "h450.retrieveAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h450_parkPosition,
      { "parkPosition", "h450.parkPosition",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h450_groupIndicationOnArg_extensionArg,
      { "extensionArg", "h450.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GroupIndicationOnArg/extensionArg", HFILL }},
    { &hf_h450_groupIndicationOffArg_extensionArg,
      { "extensionArg", "h450.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GroupIndicationOffArg/extensionArg", HFILL }},
    { &hf_h450_picking_upNumber,
      { "picking-upNumber", "h450.picking_upNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h450_pickrequArg_extensionArg,
      { "extensionArg", "h450.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PickrequArg/extensionArg", HFILL }},
    { &hf_h450_pickupArg_extensionArg,
      { "extensionArg", "h450.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PickupArg/extensionArg", HFILL }},
    { &hf_h450_pickExeArg_extensionArg,
      { "extensionArg", "h450.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PickExeArg/extensionArg", HFILL }},
    { &hf_h450_cpNotifyArg_extensionArg,
      { "extensionArg", "h450.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CpNotifyArg/extensionArg", HFILL }},
    { &hf_h450_cpickupNotifyArg_extensionArg,
      { "extensionArg", "h450.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CpickupNotifyArg/extensionArg", HFILL }},
    { &hf_h450_nbOfAddWaitingCalls,
      { "nbOfAddWaitingCalls", "h450.nbOfAddWaitingCalls",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CallWaitingArg/nbOfAddWaitingCalls", HFILL }},
    { &hf_h450_callWaitingArg_extensionArg,
      { "extensionArg", "h450.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CallWaitingArg/extensionArg", HFILL }},
    { &hf_h450_msgCentreId,
      { "msgCentreId", "h450.msgCentreId",
        FT_UINT32, BASE_DEC, VALS(h450_MsgCentreId_vals), 0,
        "", HFILL }},
    { &hf_h450_nbOfMessages,
      { "nbOfMessages", "h450.nbOfMessages",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h450_originatingNr,
      { "originatingNr", "h450.originatingNr",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h450_timestamp,
      { "timestamp", "h450.timestamp",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h450_priority,
      { "priority", "h450.priority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h450_mWIActivateArg_extensionArg,
      { "extensionArg", "h450.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MWIActivateArg/extensionArg", HFILL }},
    { &hf_h450_MwiDummyRes_item,
      { "Item", "h450.MwiDummyRes_item",
        FT_UINT32, BASE_DEC, VALS(h450_MixedExtension_vals), 0,
        "MwiDummyRes/_item", HFILL }},
    { &hf_h450_callbackReq,
      { "callbackReq", "h450.callbackReq",
        FT_BOOLEAN, 8, NULL, 0,
        "", HFILL }},
    { &hf_h450_mWIDeactivateArg_extensionArg,
      { "extensionArg", "h450.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MWIDeactivateArg/extensionArg", HFILL }},
    { &hf_h450_mWIInterrogateArg_extensionArg,
      { "extensionArg", "h450.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MWIInterrogateArg/extensionArg", HFILL }},
    { &hf_h450_MWIInterrogateRes_item,
      { "Item", "h450.MWIInterrogateRes_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "MWIInterrogateRes/_item", HFILL }},
    { &hf_h450_mWIInterrogateResElt_extensionArg,
      { "extensionArg", "h450.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MWIInterrogateResElt/extensionArg", HFILL }},
    { &hf_h450_integer,
      { "integer", "h450.integer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MsgCentreId/integer", HFILL }},
    { &hf_h450_mwipartyNumber,
      { "mwipartyNumber", "h450.mwipartyNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        "MsgCentreId/mwipartyNumber", HFILL }},
    { &hf_h450_numericString,
      { "numericString", "h450.numericString",
        FT_STRING, BASE_NONE, NULL, 0,
        "MsgCentreId/numericString", HFILL }},
    { &hf_h450_ExtensionArg_item,
      { "Item", "h450.ExtensionArg_item",
        FT_UINT32, BASE_DEC, VALS(h450_MixedExtension_vals), 0,
        "ExtensionArg/_item", HFILL }},
    { &hf_h450_name,
      { "name", "h450.name",
        FT_UINT32, BASE_DEC, VALS(h450_Name_vals), 0,
        "NameArg/name", HFILL }},
    { &hf_h450_nameArg_extensionArg,
      { "extensionArg", "h450.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NameArg/extensionArg", HFILL }},
    { &hf_h450_namePresentationAllowed,
      { "namePresentationAllowed", "h450.namePresentationAllowed",
        FT_UINT32, BASE_DEC, VALS(h450_NamePresentationAllowed_vals), 0,
        "Name/namePresentationAllowed", HFILL }},
    { &hf_h450_namePresentationRestricted,
      { "namePresentationRestricted", "h450.namePresentationRestricted",
        FT_UINT32, BASE_DEC, VALS(h450_NamePresentationRestricted_vals), 0,
        "Name/namePresentationRestricted", HFILL }},
    { &hf_h450_nameNotAvailable,
      { "nameNotAvailable", "h450.nameNotAvailable",
        FT_NONE, BASE_NONE, NULL, 0,
        "Name/nameNotAvailable", HFILL }},
    { &hf_h450_simpleName,
      { "simpleName", "h450.simpleName",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_h450_extendedName,
      { "extendedName", "h450.extendedName",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h450_restrictedNull,
      { "restrictedNull", "h450.restrictedNull",
        FT_NONE, BASE_NONE, NULL, 0,
        "NamePresentationRestricted/restrictedNull", HFILL }},
    { &hf_h450_numberA,
      { "numberA", "h450.numberA",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h450_numberB,
      { "numberB", "h450.numberB",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h450_ccIdentifier,
      { "ccIdentifier", "h450.ccIdentifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h450_service,
      { "service", "h450.service",
        FT_UINT32, BASE_DEC, VALS(h450_BasicService_vals), 0,
        "", HFILL }},
    { &hf_h450_can_retain_service,
      { "can-retain-service", "h450.can_retain_service",
        FT_BOOLEAN, 8, NULL, 0,
        "CcRequestArg/can-retain-service", HFILL }},
    { &hf_h450_retain_sig_connection,
      { "retain-sig-connection", "h450.retain_sig_connection",
        FT_BOOLEAN, 8, NULL, 0,
        "CcRequestArg/retain-sig-connection", HFILL }},
    { &hf_h450_ccRequestArg_extension,
      { "extension", "h450.extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CcRequestArg/extension", HFILL }},
    { &hf_h450_extension_item,
      { "Item", "h450.extension_item",
        FT_UINT32, BASE_DEC, VALS(h450_MixedExtension_vals), 0,
        "", HFILL }},
    { &hf_h450_retain_service,
      { "retain-service", "h450.retain_service",
        FT_BOOLEAN, 8, NULL, 0,
        "CcRequestRes/retain-service", HFILL }},
    { &hf_h450_ccRequestRes_extension,
      { "extension", "h450.extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CcRequestRes/extension", HFILL }},
    { &hf_h450_shortArg,
      { "shortArg", "h450.shortArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "CcArg/shortArg", HFILL }},
    { &hf_h450_longArg,
      { "longArg", "h450.longArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "CcArg/longArg", HFILL }},
    { &hf_h450_ccShortArg_extension,
      { "extension", "h450.extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CcShortArg/extension", HFILL }},
    { &hf_h450_ccLongArg_extension,
      { "extension", "h450.extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CcLongArg/extension", HFILL }},
    { &hf_h450_coReqOptArg_extension,
      { "extension", "h450.extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CoReqOptArg/extension", HFILL }},
    { &hf_h450_rUAlertOptArg_extension,
      { "extension", "h450.extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RUAlertOptArg/extension", HFILL }},
    { &hf_h450_cfbOvrOptArg_extension,
      { "extension", "h450.extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CfbOvrOptArg/extension", HFILL }},
    { &hf_h450_ciCapabilityLevel,
      { "ciCapabilityLevel", "h450.ciCapabilityLevel",
        FT_UINT32, BASE_DEC, VALS(h450_CICapabilityLevel_vals), 0,
        "", HFILL }},
    { &hf_h450_cIRequestArg_argumentExtension,
      { "argumentExtension", "h450.argumentExtension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CIRequestArg/argumentExtension", HFILL }},
    { &hf_h450_argumentExtension_item,
      { "Item", "h450.argumentExtension_item",
        FT_UINT32, BASE_DEC, VALS(h450_MixedExtension_vals), 0,
        "", HFILL }},
    { &hf_h450_ciStatusInformation,
      { "ciStatusInformation", "h450.ciStatusInformation",
        FT_UINT32, BASE_DEC, VALS(h450_CIStatusInformation_vals), 0,
        "", HFILL }},
    { &hf_h450_cIRequestRes_resultExtension,
      { "resultExtension", "h450.resultExtension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CIRequestRes/resultExtension", HFILL }},
    { &hf_h450_resultExtension_item,
      { "Item", "h450.resultExtension_item",
        FT_UINT32, BASE_DEC, VALS(h450_MixedExtension_vals), 0,
        "", HFILL }},
    { &hf_h450_cIGetCIPLOptArg_argumentExtension,
      { "argumentExtension", "h450.argumentExtension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CIGetCIPLOptArg/argumentExtension", HFILL }},
    { &hf_h450_ciProtectionLevel,
      { "ciProtectionLevel", "h450.ciProtectionLevel",
        FT_UINT32, BASE_DEC, VALS(h450_CIProtectionLevel_vals), 0,
        "CIGetCIPLRes/ciProtectionLevel", HFILL }},
    { &hf_h450_silentMonitoringPermitted,
      { "silentMonitoringPermitted", "h450.silentMonitoringPermitted",
        FT_NONE, BASE_NONE, NULL, 0,
        "CIGetCIPLRes/silentMonitoringPermitted", HFILL }},
    { &hf_h450_cIGetCIPLRes_resultExtension,
      { "resultExtension", "h450.resultExtension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CIGetCIPLRes/resultExtension", HFILL }},
    { &hf_h450_cIIsOptArg_argumentExtension,
      { "argumentExtension", "h450.argumentExtension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CIIsOptArg/argumentExtension", HFILL }},
    { &hf_h450_cIIsOptRes_resultExtension,
      { "resultExtension", "h450.resultExtension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CIIsOptRes/resultExtension", HFILL }},
    { &hf_h450_cIFrcRelArg_argumentExtension,
      { "argumentExtension", "h450.argumentExtension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CIFrcRelArg/argumentExtension", HFILL }},
    { &hf_h450_cIFrcRelOptRes_resultExtension,
      { "resultExtension", "h450.resultExtension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CIFrcRelOptRes/resultExtension", HFILL }},
    { &hf_h450_cIWobOptArg_argumentExtension,
      { "argumentExtension", "h450.argumentExtension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CIWobOptArg/argumentExtension", HFILL }},
    { &hf_h450_cIWobOptRes_resultExtension,
      { "resultExtension", "h450.resultExtension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CIWobOptRes/resultExtension", HFILL }},
    { &hf_h450_specificCall,
      { "specificCall", "h450.specificCall",
        FT_NONE, BASE_NONE, NULL, 0,
        "CISilentArg/specificCall", HFILL }},
    { &hf_h450_cISilentArg_argumentExtension,
      { "argumentExtension", "h450.argumentExtension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CISilentArg/argumentExtension", HFILL }},
    { &hf_h450_cISilentOptRes_resultExtension,
      { "resultExtension", "h450.resultExtension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CISilentOptRes/resultExtension", HFILL }},
    { &hf_h450_cINotificationArg_argumentExtension,
      { "argumentExtension", "h450.argumentExtension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CINotificationArg/argumentExtension", HFILL }},
    { &hf_h450_callIntrusionImpending,
      { "callIntrusionImpending", "h450.callIntrusionImpending",
        FT_NONE, BASE_NONE, NULL, 0,
        "CIStatusInformation/callIntrusionImpending", HFILL }},
    { &hf_h450_callIntruded,
      { "callIntruded", "h450.callIntruded",
        FT_NONE, BASE_NONE, NULL, 0,
        "CIStatusInformation/callIntruded", HFILL }},
    { &hf_h450_callIsolated,
      { "callIsolated", "h450.callIsolated",
        FT_NONE, BASE_NONE, NULL, 0,
        "CIStatusInformation/callIsolated", HFILL }},
    { &hf_h450_callForceReleased,
      { "callForceReleased", "h450.callForceReleased",
        FT_NONE, BASE_NONE, NULL, 0,
        "CIStatusInformation/callForceReleased", HFILL }},
    { &hf_h450_callIntrusionComplete,
      { "callIntrusionComplete", "h450.callIntrusionComplete",
        FT_NONE, BASE_NONE, NULL, 0,
        "CIStatusInformation/callIntrusionComplete", HFILL }},
    { &hf_h450_callIntrusionEnd,
      { "callIntrusionEnd", "h450.callIntrusionEnd",
        FT_NONE, BASE_NONE, NULL, 0,
        "CIStatusInformation/callIntrusionEnd", HFILL }},
    { &hf_h450_featureList,
      { "featureList", "h450.featureList",
        FT_NONE, BASE_NONE, NULL, 0,
        "CmnArg/featureList", HFILL }},
    { &hf_h450_featureValues,
      { "featureValues", "h450.featureValues",
        FT_NONE, BASE_NONE, NULL, 0,
        "CmnArg/featureValues", HFILL }},
    { &hf_h450_featureControl,
      { "featureControl", "h450.featureControl",
        FT_NONE, BASE_NONE, NULL, 0,
        "CmnArg/featureControl", HFILL }},
    { &hf_h450_cmnArg_extension,
      { "extension", "h450.extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CmnArg/extension", HFILL }},
    { &hf_h450_cmnRequestArg_extensionArg,
      { "extensionArg", "h450.extensionArg",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CmnRequestArg/extensionArg", HFILL }},
    { &hf_h450_ssCFreRoutingSupported,
      { "ssCFreRoutingSupported", "h450.ssCFreRoutingSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        "FeatureList/ssCFreRoutingSupported", HFILL }},
    { &hf_h450_ssCTreRoutingSupported,
      { "ssCTreRoutingSupported", "h450.ssCTreRoutingSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        "FeatureList/ssCTreRoutingSupported", HFILL }},
    { &hf_h450_ssCCBSPossible,
      { "ssCCBSPossible", "h450.ssCCBSPossible",
        FT_NONE, BASE_NONE, NULL, 0,
        "FeatureList/ssCCBSPossible", HFILL }},
    { &hf_h450_ssCCNRPossible,
      { "ssCCNRPossible", "h450.ssCCNRPossible",
        FT_NONE, BASE_NONE, NULL, 0,
        "FeatureList/ssCCNRPossible", HFILL }},
    { &hf_h450_ssCOSupported,
      { "ssCOSupported", "h450.ssCOSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        "FeatureList/ssCOSupported", HFILL }},
    { &hf_h450_ssCIForcedReleaseSupported,
      { "ssCIForcedReleaseSupported", "h450.ssCIForcedReleaseSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        "FeatureList/ssCIForcedReleaseSupported", HFILL }},
    { &hf_h450_ssCIIsolationSupported,
      { "ssCIIsolationSupported", "h450.ssCIIsolationSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        "FeatureList/ssCIIsolationSupported", HFILL }},
    { &hf_h450_ssCIWaitOnBusySupported,
      { "ssCIWaitOnBusySupported", "h450.ssCIWaitOnBusySupported",
        FT_NONE, BASE_NONE, NULL, 0,
        "FeatureList/ssCIWaitOnBusySupported", HFILL }},
    { &hf_h450_ssCISilentMonitoringSupported,
      { "ssCISilentMonitoringSupported", "h450.ssCISilentMonitoringSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        "FeatureList/ssCISilentMonitoringSupported", HFILL }},
    { &hf_h450_ssCIConferenceSupported,
      { "ssCIConferenceSupported", "h450.ssCIConferenceSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        "FeatureList/ssCIConferenceSupported", HFILL }},
    { &hf_h450_ssCHFarHoldSupported,
      { "ssCHFarHoldSupported", "h450.ssCHFarHoldSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        "FeatureList/ssCHFarHoldSupported", HFILL }},
    { &hf_h450_ssMWICallbackSupported,
      { "ssMWICallbackSupported", "h450.ssMWICallbackSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        "FeatureList/ssMWICallbackSupported", HFILL }},
    { &hf_h450_ssCPCallParkSupported,
      { "ssCPCallParkSupported", "h450.ssCPCallParkSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        "FeatureList/ssCPCallParkSupported", HFILL }},
    { &hf_h450_partyCategory,
      { "partyCategory", "h450.partyCategory",
        FT_UINT32, BASE_DEC, VALS(h450_PartyCategory_vals), 0,
        "FeatureValues/partyCategory", HFILL }},
    { &hf_h450_ssCIprotectionLevel,
      { "ssCIprotectionLevel", "h450.ssCIprotectionLevel",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FeatureValues/ssCIprotectionLevel", HFILL }},
    { &hf_h450_ssCHDoNotHold,
      { "ssCHDoNotHold", "h450.ssCHDoNotHold",
        FT_NONE, BASE_NONE, NULL, 0,
        "FeatureControl/ssCHDoNotHold", HFILL }},
    { &hf_h450_ssCTDoNotTransfer,
      { "ssCTDoNotTransfer", "h450.ssCTDoNotTransfer",
        FT_NONE, BASE_NONE, NULL, 0,
        "FeatureControl/ssCTDoNotTransfer", HFILL }},
    { &hf_h450_ssMWICallbackCall,
      { "ssMWICallbackCall", "h450.ssMWICallbackCall",
        FT_NONE, BASE_NONE, NULL, 0,
        "FeatureControl/ssMWICallbackCall", HFILL }},
    { &hf_h450_ssCISilentMonitorPermitted,
      { "ssCISilentMonitorPermitted", "h450.ssCISilentMonitorPermitted",
        FT_NONE, BASE_NONE, NULL, 0,
        "FeatureControl/ssCISilentMonitorPermitted", HFILL }},
    { &hf_h450_unspecified_extension,
      { "extension", "h450.extension",
        FT_NONE, BASE_NONE, NULL, 0,
        "Unspecified/extension", HFILL }},
    { &hf_h450_nonStandard,
      { "nonStandard", "h450.nonStandard",
        FT_NONE, BASE_NONE, NULL, 0,
        "Unspecified/nonStandard", HFILL }},
    { &hf_h450_extensionId,
      { "extensionId", "h450.extensionId",
        FT_OID, BASE_NONE, NULL, 0,
        "Extension/extensionId", HFILL }},
    { &hf_h450_extensionArgument,
      { "extensionArgument", "h450.extensionArgument",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Extension/extensionArgument", HFILL }},

/*--- End of included file: packet-h450-hfarr.c ---*/
#line 1035 "packet-h450-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	  &ett_h4501,
	  &ett_h4501_opcode,
	  &ett_h4501_result,
	  &ett_h4501_errorCode,

	  &ett_h4501_problem,
	  &ett_h4501_Reject,
	  &ett_h4501_ReturnError,
	  &ett_h4501_ReturnResult,
	  &ett_h4501_Invoke,
	  &ett_h4501_ROS,

/*--- Included file: packet-h450-ettarr.c ---*/
#line 1 "packet-h450-ettarr.c"
    &ett_h450_H4501SupplementaryService,
    &ett_h450_NetworkFacilityExtension,
    &ett_h450_EntityType,
    &ett_h450_InterpretationApdu,
    &ett_h450_ServiceApdus,
    &ett_h450_SEQUENCE_OF_ROSxxx,
    &ett_h450_PresentedAddressScreened,
    &ett_h450_PresentedAddressUnscreened,
    &ett_h450_PresentedNumberScreened,
    &ett_h450_PresentedNumberUnscreened,
    &ett_h450_AddressScreened,
    &ett_h450_NumberScreened,
    &ett_h450_Address,
    &ett_h450_EndpointAddress,
    &ett_h450_SEQUENCE_OF_AliasAddress,
    &ett_h450_PartySubaddress,
    &ett_h450_UserSpecifiedSubaddress,
    &ett_h450_DummyArg,
    &ett_h450_DummyRes,
    &ett_h450_CTInitiateArg,
    &ett_h450_ArgumentExtension,
    &ett_h450_CTSetupArg,
    &ett_h450_CTIdentifyRes,
    &ett_h450_T_resultExtension,
    &ett_h450_CTUpdateArg,
    &ett_h450_SubaddressTransferArg,
    &ett_h450_CTCompleteArg,
    &ett_h450_CTActiveArg,
    &ett_h450_ExtensionSeq,
    &ett_h450_ActivateDiversionQArg,
    &ett_h450_ActivateDiversionQArg_extension,
    &ett_h450_ActivateDiversionQRes,
    &ett_h450_DeactivateDiversionQArg,
    &ett_h450_DeactivateDiversionQArg_extension,
    &ett_h450_DeactivateDiversionQRes,
    &ett_h450_InterrogateDiversionQ,
    &ett_h450_InterrogateDiversionQ_extension,
    &ett_h450_CheckRestrictionArg,
    &ett_h450_CheckRestrictionArg_extension,
    &ett_h450_CheckRestrictionRes,
    &ett_h450_CallReroutingArg,
    &ett_h450_CallReroutingArg_extension,
    &ett_h450_CallReroutingRes,
    &ett_h450_DivertingLegInformation1Arg,
    &ett_h450_DivertingLegInformation1Arg_extension,
    &ett_h450_DivertingLegInformation2Arg,
    &ett_h450_DivertingLegInformation2Arg_extension,
    &ett_h450_DivertingLegInformation3Arg,
    &ett_h450_DivertingLegInformation3Arg_extension,
    &ett_h450_DivertingLegInformation4Arg,
    &ett_h450_DivertingLegInformation4Arg_extension,
    &ett_h450_CfnrDivertedLegFailedArg,
    &ett_h450_IntResultList,
    &ett_h450_IntResult,
    &ett_h450_IntResult_extension,
    &ett_h450_HoldNotificArg,
    &ett_h450_SEQUENCE_SIZE_0_255_OF_MixedExtension,
    &ett_h450_RetrieveNotificArg,
    &ett_h450_RemoteHoldArg,
    &ett_h450_RemoteHoldRes,
    &ett_h450_RemoteRetrieveArg,
    &ett_h450_RemoteRetrieveRes,
    &ett_h450_MixedExtension,
    &ett_h450_CpRequestArg,
    &ett_h450_CpRequestRes,
    &ett_h450_CpSetupArg,
    &ett_h450_CpSetupRes,
    &ett_h450_GroupIndicationOnArg,
    &ett_h450_GroupIndicationOnRes,
    &ett_h450_GroupIndicationOffArg,
    &ett_h450_GroupIndicationOffRes,
    &ett_h450_PickrequArg,
    &ett_h450_PickrequRes,
    &ett_h450_PickupArg,
    &ett_h450_PickupRes,
    &ett_h450_PickExeArg,
    &ett_h450_PickExeRes,
    &ett_h450_CpNotifyArg,
    &ett_h450_CpickupNotifyArg,
    &ett_h450_CallWaitingArg,
    &ett_h450_MWIActivateArg,
    &ett_h450_MwiDummyRes,
    &ett_h450_MWIDeactivateArg,
    &ett_h450_MWIInterrogateArg,
    &ett_h450_MWIInterrogateRes,
    &ett_h450_MWIInterrogateResElt,
    &ett_h450_MsgCentreId,
    &ett_h450_ExtensionArg,
    &ett_h450_NameArg,
    &ett_h450_Name,
    &ett_h450_NamePresentationAllowed,
    &ett_h450_NamePresentationRestricted,
    &ett_h450_CcRequestArg,
    &ett_h450_CcRequestRes,
    &ett_h450_CcArg,
    &ett_h450_CcShortArg,
    &ett_h450_CcLongArg,
    &ett_h450_CoReqOptArg,
    &ett_h450_RUAlertOptArg,
    &ett_h450_CfbOvrOptArg,
    &ett_h450_CIRequestArg,
    &ett_h450_CIRequestRes,
    &ett_h450_CIGetCIPLOptArg,
    &ett_h450_CIGetCIPLRes,
    &ett_h450_CIIsOptArg,
    &ett_h450_CIIsOptRes,
    &ett_h450_CIFrcRelArg,
    &ett_h450_CIFrcRelOptRes,
    &ett_h450_CIWobOptArg,
    &ett_h450_CIWobOptRes,
    &ett_h450_CISilentArg,
    &ett_h450_CISilentOptRes,
    &ett_h450_CINotificationArg,
    &ett_h450_CIStatusInformation,
    &ett_h450_CmnArg,
    &ett_h450_CmnRequestArg,
    &ett_h450_FeatureList,
    &ett_h450_FeatureValues,
    &ett_h450_FeatureControl,
    &ett_h450_Unspecified,
    &ett_h450_Extension,

/*--- End of included file: packet-h450-ettarr.c ---*/
#line 1051 "packet-h450-template.c"
  };


  /* Register protocol */
  proto_h4501 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_h4501, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

 
  register_dissector("h4501", dissect_h4501, proto_h4501);


}


/*--- proto_reg_handoff_h4501 ---------------------------------------*/
void
proto_reg_handoff_h4501(void)
{

	h4501_handle = find_dissector("h4501");

}
