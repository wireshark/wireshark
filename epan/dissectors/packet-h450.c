/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* .\packet-h450.c                                                            */
/* ../../tools/asn2eth.py -X -e -p h450 -c h450.cnf -s packet-h450-template h4501.asn */

/* Input file: packet-h450-template.c */

/* packet-h450.c
 * Routines for h450 packet dissection
 * Based on the previous h450 dissector by:
 * 2003  Graeme Reid (graeme.reid@norwoodsystems.com)
 * Copyright 2005, Anders Broman <anders.broman@ericsson.com>
 *
 * $Id$
 *
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
static int hf_h4502_CTInitiateArg = -1;
static int hf_h4502_CTSetupArg = -1;
static int hf_h4502_CTUpdateArg = -1;
static int hf_h4502_SubaddressTransferArg = -1;
static int hf_h4502_CTCompleteArg = -1;
static int hf_h4502_CTActiveArg = -1;

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

static int hf_h4501_Invoke = -1;
static int hf_h4501_ROS = -1;


/*--- Included file: packet-h450-hf.c ---*/

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
static int hf_h450_rosApdus = -1;                 /* SEQUNCE_OF_ROSxxx */
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
static int hf_h450_destinationAddress = -1;       /* SEQUNCE_OF_AliasAddress */
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
static int hf_h450_argumentExtension = -1;        /* ArgumentExtension */
static int hf_h450_transferringNumber = -1;       /* EndpointAddress */
static int hf_h450_resultExtension = -1;          /* T_resultExtension */
static int hf_h450_redirectionNumber = -1;        /* EndpointAddress */
static int hf_h450_redirectionInfo = -1;          /* BMPString_SIZE_1_128 */
static int hf_h450_basicCallInfoElements = -1;    /* H225InformationElement */
static int hf_h450_redirectionSubaddress = -1;    /* PartySubaddress */
static int hf_h450_endDesignation = -1;           /* EndDesignation */
static int hf_h450_callStatus = -1;               /* CallStatus */
static int hf_h450_connectedAddress = -1;         /* EndpointAddress */
static int hf_h450_connectedInfo = -1;            /* BMPString_SIZE_1_128 */
static int hf_h450_ExtensionSeq_item = -1;        /* Extensionxxx */
static int hf_h450_extensionArg = -1;             /* ExtensionArg */
static int hf_h450_ExtensionArg_item = -1;        /* MixedExtension */
static int hf_h450_extensionRes = -1;             /* SEQUNCE_SIZE_0_255_OF_MixedExtension */
static int hf_h450_extensionRes_item = -1;        /* MixedExtension */
static int hf_h450_extension = -1;                /* Extensionxxx */
static int hf_h450_servedUserNr = -1;             /* EndpointAddress */
static int hf_h450_basicService = -1;             /* BasicService */
static int hf_h450_msgCentreId = -1;              /* MsgCentreId */
static int hf_h450_nbOfMessages = -1;             /* NbOfMessages */
static int hf_h450_originatingNr = -1;            /* EndpointAddress */
static int hf_h450_timestamp = -1;                /* TimeStamp */
static int hf_h450_priority = -1;                 /* INTEGER_0_9 */
static int hf_h450_MwiDummyRes_item = -1;         /* MixedExtension */
static int hf_h450_callbackReq = -1;              /* BOOLEAN */
static int hf_h450_MWIInterrogateRes_item = -1;   /* MWIInterrogateResElt */
static int hf_h450_integer = -1;                  /* INTEGER_0_65535 */
static int hf_h450_mwipartyNumber = -1;           /* EndpointAddress */
static int hf_h450_numericString = -1;            /* NumericString_SIZE_1_10 */
static int hf_h450_name = -1;                     /* Name */
static int hf_h450_namePresentationAllowed = -1;  /* NamePresentationAllowed */
static int hf_h450_namePresentationRestricted = -1;  /* NamePresentationRestricted */
static int hf_h450_nameNotAvailable = -1;         /* NULL */
static int hf_h450_simpleName = -1;               /* SimpleName */
static int hf_h450_extendedName = -1;             /* ExtendedName */
static int hf_h450_restrictedNull = -1;           /* NULL */
static int hf_h450_extension1 = -1;               /* Extension */
static int hf_h450_nonStandard = -1;              /* NonStandardParameter */

/*--- End of included file: packet-h450-hf.c ---*/


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

static gint ett_h450_H4501SupplementaryService = -1;
static gint ett_h450_NetworkFacilityExtension = -1;
static gint ett_h450_EntityType = -1;
static gint ett_h450_InterpretationApdu = -1;
static gint ett_h450_ServiceApdus = -1;
static gint ett_h450_SEQUNCE_OF_ROSxxx = -1;
static gint ett_h450_PresentedAddressScreened = -1;
static gint ett_h450_PresentedAddressUnscreened = -1;
static gint ett_h450_PresentedNumberScreened = -1;
static gint ett_h450_PresentedNumberUnscreened = -1;
static gint ett_h450_AddressScreened = -1;
static gint ett_h450_NumberScreened = -1;
static gint ett_h450_Address = -1;
static gint ett_h450_EndpointAddress = -1;
static gint ett_h450_SEQUNCE_OF_AliasAddress = -1;
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
static gint ett_h450_HoldNotificArg = -1;
static gint ett_h450_ExtensionArg = -1;
static gint ett_h450_RetrieveNotificArg = -1;
static gint ett_h450_RemoteHoldArg = -1;
static gint ett_h450_RemoteHoldRes = -1;
static gint ett_h450_SEQUNCE_SIZE_0_255_OF_MixedExtension = -1;
static gint ett_h450_RemoteRetrieveArg = -1;
static gint ett_h450_RemoteRetrieveRes = -1;
static gint ett_h450_MixedExtension = -1;
static gint ett_h450_MWIActivateArg = -1;
static gint ett_h450_MwiDummyRes = -1;
static gint ett_h450_MWIDeactivateArg = -1;
static gint ett_h450_MWIInterrogateArg = -1;
static gint ett_h450_MWIInterrogateRes = -1;
static gint ett_h450_MWIInterrogateResElt = -1;
static gint ett_h450_MsgCentreId = -1;
static gint ett_h450_CallingName = -1;
static gint ett_h450_AlertingName = -1;
static gint ett_h450_ConnectedName = -1;
static gint ett_h450_BusyName = -1;
static gint ett_h450_Name = -1;
static gint ett_h450_NamePresentationAllowed = -1;
static gint ett_h450_NamePresentationRestricted = -1;
static gint ett_h450_Unspecified = -1;

/*--- End of included file: packet-h450-ett.c ---*/


/* Global variables */
static guint32 localOpcode;
static guint32 localErrorCode;
static char globalcode_oid_str[256];
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

	{  0, NULL }
};

static int dissect_h4501_argument(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int dissect_ros_ROSxxx(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_ind _U_);

static int
dissect_xxx_Extensionxxx(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_id){
	PER_NOT_DECODED_YET("H.450.1 ExtensionSeq");
   return offset;
}

static int
dissect_xxx_Extension(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_id){
	PER_NOT_DECODED_YET("H.450.1 ExtensionSeq");
   return offset;
}



/*--- Included file: packet-h450-fn.c ---*/

/*--- Fields for imported types ---*/

static int dissect_rosApdus_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ros_ROSxxx(tvb, offset, pinfo, tree, hf_h450_rosApdus_item);
}
static int dissect_numberUnscreened_presentationAllowedAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h225_PartyNumber(tvb, offset, pinfo, tree, hf_h450_numberUnscreened_presentationAllowedAddress);
}
static int dissect_numberUnscreened_presentationRestrictedAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h225_PartyNumber(tvb, offset, pinfo, tree, hf_h450_numberUnscreened_presentationRestrictedAddress);
}
static int dissect_partyNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h225_PartyNumber(tvb, offset, pinfo, tree, hf_h450_partyNumber);
}
static int dissect_screeningIndicator(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h225_ScreeningIndicator(tvb, offset, pinfo, tree, hf_h450_screeningIndicator);
}
static int dissect_destinationAddress_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h225_AliasAddress(tvb, offset, pinfo, tree, hf_h450_destinationAddress_item);
}
static int dissect_remoteExtensionAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h225_AliasAddress(tvb, offset, pinfo, tree, hf_h450_remoteExtensionAddress);
}
static int dissect_destinationAddressPresentationIndicator(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h225_PresentationIndicator(tvb, offset, pinfo, tree, hf_h450_destinationAddressPresentationIndicator);
}
static int dissect_destinationAddressScreeningIndicator(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h225_ScreeningIndicator(tvb, offset, pinfo, tree, hf_h450_destinationAddressScreeningIndicator);
}
static int dissect_remoteExtensionAddressPresentationIndicator(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h225_PresentationIndicator(tvb, offset, pinfo, tree, hf_h450_remoteExtensionAddressPresentationIndicator);
}
static int dissect_remoteExtensionAddressScreeningIndicator(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h225_ScreeningIndicator(tvb, offset, pinfo, tree, hf_h450_remoteExtensionAddressScreeningIndicator);
}
static int dissect_nonStandardData(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h225_NonStandardParameter(tvb, offset, pinfo, tree, hf_h450_nonStandardData);
}
static int dissect_ExtensionSeq_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_xxx_Extensionxxx(tvb, offset, pinfo, tree, hf_h450_ExtensionSeq_item);
}
static int dissect_extension(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_xxx_Extensionxxx(tvb, offset, pinfo, tree, hf_h450_extension);
}
static int dissect_extension1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_xxx_Extension(tvb, offset, pinfo, tree, hf_h450_extension1);
}
static int dissect_nonStandard(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h225_NonStandardParameter(tvb, offset, pinfo, tree, hf_h450_nonStandard);
}


static int
dissect_h450_NULL(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  { proto_item *ti_tmp;
  ti_tmp = proto_tree_add_item(tree, hf_index, tvb, offset>>8, 0, FALSE);
  proto_item_append_text(ti_tmp, ": NULL");
  }

  return offset;
}
static int dissect_endpoint(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, pinfo, tree, hf_h450_endpoint);
}
static int dissect_anyEntity(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, pinfo, tree, hf_h450_anyEntity);
}
static int dissect_discardAnyUnrecognizedInvokePdu(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, pinfo, tree, hf_h450_discardAnyUnrecognizedInvokePdu);
}
static int dissect_clearCallIfAnyInvokePduNotRecognized(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, pinfo, tree, hf_h450_clearCallIfAnyInvokePduNotRecognized);
}
static int dissect_rejectAnyUnrecognizedInvokePdu(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, pinfo, tree, hf_h450_rejectAnyUnrecognizedInvokePdu);
}
static int dissect_presentationRestricted(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, pinfo, tree, hf_h450_presentationRestricted);
}
static int dissect_numberNotAvailableDueToInterworking(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, pinfo, tree, hf_h450_numberNotAvailableDueToInterworking);
}
static int dissect_nameNotAvailable(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, pinfo, tree, hf_h450_nameNotAvailable);
}
static int dissect_restrictedNull(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_NULL(tvb, offset, pinfo, tree, hf_h450_restrictedNull);
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
dissect_h450_EntityType(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, pinfo, tree, hf_index,
                              ett_h450_EntityType, EntityType_choice, "EntityType",
                              NULL);

  return offset;
}
static int dissect_sourceEntity(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_EntityType(tvb, offset, pinfo, tree, hf_h450_sourceEntity);
}
static int dissect_destinationEntity(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_EntityType(tvb, offset, pinfo, tree, hf_h450_destinationEntity);
}


static int
dissect_h450_AddressInformation(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_h225_AliasAddress(tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_sourceEntityAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_AddressInformation(tvb, offset, pinfo, tree, hf_h450_sourceEntityAddress);
}
static int dissect_destinationEntityAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_AddressInformation(tvb, offset, pinfo, tree, hf_h450_destinationEntityAddress);
}

static const per_sequence_t NetworkFacilityExtension_sequence[] = {
  { "sourceEntity"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sourceEntity },
  { "sourceEntityAddress"         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sourceEntityAddress },
  { "destinationEntity"           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_destinationEntity },
  { "destinationEntityAddress"    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_destinationEntityAddress },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_NetworkFacilityExtension(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                ett_h450_NetworkFacilityExtension, NetworkFacilityExtension_sequence);

  return offset;
}
static int dissect_networkFacilityExtension(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_NetworkFacilityExtension(tvb, offset, pinfo, tree, hf_h450_networkFacilityExtension);
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
dissect_h450_InterpretationApdu(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, pinfo, tree, hf_index,
                              ett_h450_InterpretationApdu, InterpretationApdu_choice, "InterpretationApdu",
                              NULL);

  return offset;
}
static int dissect_interpretationApdu(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_InterpretationApdu(tvb, offset, pinfo, tree, hf_h450_interpretationApdu);
}


static int
dissect_h450_SEQUNCE_OF_ROSxxx(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_index,
                                   ett_h450_SEQUNCE_OF_ROSxxx, dissect_rosApdus_item);

  return offset;
}
static int dissect_rosApdus(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_SEQUNCE_OF_ROSxxx(tvb, offset, pinfo, tree, hf_h450_rosApdus);
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
dissect_h450_ServiceApdus(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, pinfo, tree, hf_index,
                              ett_h450_ServiceApdus, ServiceApdus_choice, "ServiceApdus",
                              NULL);

  return offset;
}
static int dissect_serviceApdu(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_ServiceApdus(tvb, offset, pinfo, tree, hf_h450_serviceApdu);
}

static const per_sequence_t H4501SupplementaryService_sequence[] = {
  { "networkFacilityExtension"    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_networkFacilityExtension },
  { "interpretationApdu"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_interpretationApdu },
  { "serviceApdu"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_serviceApdu },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_H4501SupplementaryService(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                ett_h450_H4501SupplementaryService, H4501SupplementaryService_sequence);

  return offset;
}


static int
dissect_h450_Notassignedlocalopcode(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, pinfo, tree, hf_index,
                                    -1, -1,
                                    NULL, NULL);

  return offset;
}


static int
dissect_h450_SubaddressInformation(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, pinfo, tree, hf_index,
                                    1, 20,
                                    NULL, NULL);

  return offset;
}
static int dissect_subaddressInformation(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_SubaddressInformation(tvb, offset, pinfo, tree, hf_h450_subaddressInformation);
}


static int
dissect_h450_BOOLEAN(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_boolean(tvb, offset, pinfo, tree, hf_index,
                               NULL, NULL);

  return offset;
}
static int dissect_oddCountIndicator(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_BOOLEAN(tvb, offset, pinfo, tree, hf_h450_oddCountIndicator);
}
static int dissect_callbackReq(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_BOOLEAN(tvb, offset, pinfo, tree, hf_h450_callbackReq);
}

static const per_sequence_t UserSpecifiedSubaddress_sequence[] = {
  { "subaddressInformation"       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_subaddressInformation },
  { "oddCountIndicator"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_oddCountIndicator },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_UserSpecifiedSubaddress(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                ett_h450_UserSpecifiedSubaddress, UserSpecifiedSubaddress_sequence);

  return offset;
}
static int dissect_userSpecifiedSubaddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_UserSpecifiedSubaddress(tvb, offset, pinfo, tree, hf_h450_userSpecifiedSubaddress);
}


static int
dissect_h450_NSAPSubaddress(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, pinfo, tree, hf_index,
                                    1, 20,
                                    NULL, NULL);

  return offset;
}
static int dissect_nsapSubaddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_NSAPSubaddress(tvb, offset, pinfo, tree, hf_h450_nsapSubaddress);
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
dissect_h450_PartySubaddress(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, pinfo, tree, hf_index,
                              ett_h450_PartySubaddress, PartySubaddress_choice, "PartySubaddress",
                              NULL);

  return offset;
}
static int dissect_partySubaddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_PartySubaddress(tvb, offset, pinfo, tree, hf_h450_partySubaddress);
}
static int dissect_redirectionSubaddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_PartySubaddress(tvb, offset, pinfo, tree, hf_h450_redirectionSubaddress);
}

static const per_sequence_t AddressScreened_sequence[] = {
  { "partyNumber"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_partyNumber },
  { "screeningIndicator"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_screeningIndicator },
  { "partySubaddress"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_partySubaddress },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_AddressScreened(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                ett_h450_AddressScreened, AddressScreened_sequence);

  return offset;
}
static int dissect_addressScreened_presentationAllowedAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_AddressScreened(tvb, offset, pinfo, tree, hf_h450_addressScreened_presentationAllowedAddress);
}
static int dissect_addressScreened_presentationRestrictedAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_AddressScreened(tvb, offset, pinfo, tree, hf_h450_addressScreened_presentationRestrictedAddress);
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
dissect_h450_PresentedAddressScreened(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, pinfo, tree, hf_index,
                              ett_h450_PresentedAddressScreened, PresentedAddressScreened_choice, "PresentedAddressScreened",
                              NULL);

  return offset;
}

static const per_sequence_t Address_sequence[] = {
  { "partyNumber"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_partyNumber },
  { "partySubaddress"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_partySubaddress },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_Address(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                ett_h450_Address, Address_sequence);

  return offset;
}
static int dissect_addressUnscreened_presentationAllowedAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_Address(tvb, offset, pinfo, tree, hf_h450_addressUnscreened_presentationAllowedAddress);
}
static int dissect_addressUnscreened_presentationRestrictedAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_Address(tvb, offset, pinfo, tree, hf_h450_addressUnscreened_presentationRestrictedAddress);
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
dissect_h450_PresentedAddressUnscreened(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, pinfo, tree, hf_index,
                              ett_h450_PresentedAddressUnscreened, PresentedAddressUnscreened_choice, "PresentedAddressUnscreened",
                              NULL);

  return offset;
}

static const per_sequence_t NumberScreened_sequence[] = {
  { "partyNumber"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_partyNumber },
  { "screeningIndicator"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_screeningIndicator },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_NumberScreened(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                ett_h450_NumberScreened, NumberScreened_sequence);

  return offset;
}
static int dissect_numberScreened_presentationAllowedAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_NumberScreened(tvb, offset, pinfo, tree, hf_h450_numberScreened_presentationAllowedAddress);
}
static int dissect_numberScreened_presentationRestrictedAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_NumberScreened(tvb, offset, pinfo, tree, hf_h450_numberScreened_presentationRestrictedAddress);
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
dissect_h450_PresentedNumberScreened(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, pinfo, tree, hf_index,
                              ett_h450_PresentedNumberScreened, PresentedNumberScreened_choice, "PresentedNumberScreened",
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
dissect_h450_PresentedNumberUnscreened(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, pinfo, tree, hf_index,
                              ett_h450_PresentedNumberUnscreened, PresentedNumberUnscreened_choice, "PresentedNumberUnscreened",
                              NULL);

  return offset;
}


static int
dissect_h450_SEQUNCE_OF_AliasAddress(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_index,
                                   ett_h450_SEQUNCE_OF_AliasAddress, dissect_destinationAddress_item);

  return offset;
}
static int dissect_destinationAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_SEQUNCE_OF_AliasAddress(tvb, offset, pinfo, tree, hf_h450_destinationAddress);
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
dissect_h450_EndpointAddress(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                ett_h450_EndpointAddress, EndpointAddress_sequence);

  return offset;
}
static int dissect_reroutingNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_EndpointAddress(tvb, offset, pinfo, tree, hf_h450_reroutingNumber);
}
static int dissect_transferringNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_EndpointAddress(tvb, offset, pinfo, tree, hf_h450_transferringNumber);
}
static int dissect_redirectionNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_EndpointAddress(tvb, offset, pinfo, tree, hf_h450_redirectionNumber);
}
static int dissect_connectedAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_EndpointAddress(tvb, offset, pinfo, tree, hf_h450_connectedAddress);
}
static int dissect_servedUserNr(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_EndpointAddress(tvb, offset, pinfo, tree, hf_h450_servedUserNr);
}
static int dissect_originatingNr(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_EndpointAddress(tvb, offset, pinfo, tree, hf_h450_originatingNr);
}
static int dissect_mwipartyNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_EndpointAddress(tvb, offset, pinfo, tree, hf_h450_mwipartyNumber);
}


static int
dissect_h450_PresentationAllowedIndicator(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_boolean(tvb, offset, pinfo, tree, hf_index,
                               NULL, NULL);

  return offset;
}


static int
dissect_h450_ExtensionSeq(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, pinfo, tree, hf_index,
                                   ett_h450_ExtensionSeq, dissect_ExtensionSeq_item);

  return offset;
}
static int dissect_extensionSeq(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_ExtensionSeq(tvb, offset, pinfo, tree, hf_h450_extensionSeq);
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
dissect_h450_DummyArg(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, pinfo, tree, hf_index,
                              ett_h450_DummyArg, DummyArg_choice, "DummyArg",
                              NULL);

  return offset;
}


static int
dissect_h450_CallTransferIdentify(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_h450_DummyArg(tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static int
dissect_h450_CallTransferAbandon(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_h450_DummyArg(tvb, offset, pinfo, tree, hf_index);

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
dissect_h450_DummyRes(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, pinfo, tree, hf_index,
                              ett_h450_DummyRes, DummyRes_choice, "DummyRes",
                              NULL);

  return offset;
}


static int
dissect_h450_CallTransferInitiate(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_h450_DummyRes(tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static int
dissect_h450_CallTransferSetup(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_h450_DummyRes(tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static int
dissect_h450_BMPString_SIZE_1_128(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_BMPString(tvb, offset, pinfo, tree, hf_index,
                                 1, 128);

  return offset;
}
static int dissect_redirectionInfo(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_BMPString_SIZE_1_128(tvb, offset, pinfo, tree, hf_h450_redirectionInfo);
}
static int dissect_connectedInfo(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_BMPString_SIZE_1_128(tvb, offset, pinfo, tree, hf_h450_connectedInfo);
}


static int
dissect_h450_H225InformationElement(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, pinfo, tree, hf_index,
                                    -1, -1,
                                    NULL, NULL);

  return offset;
}
static int dissect_basicCallInfoElements(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_H225InformationElement(tvb, offset, pinfo, tree, hf_h450_basicCallInfoElements);
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
dissect_h450_ArgumentExtension(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, pinfo, tree, hf_index,
                              ett_h450_ArgumentExtension, ArgumentExtension_choice, "ArgumentExtension",
                              NULL);

  return offset;
}
static int dissect_argumentExtension(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_ArgumentExtension(tvb, offset, pinfo, tree, hf_h450_argumentExtension);
}

static const per_sequence_t CTUpdateArg_sequence[] = {
  { "redirectionNumber"           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_redirectionNumber },
  { "redirectionInfo"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_redirectionInfo },
  { "basicCallInfoElements"       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_basicCallInfoElements },
  { "argumentExtension"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_argumentExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CTUpdateArg(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                ett_h450_CTUpdateArg, CTUpdateArg_sequence);

  return offset;
}


static int
dissect_h450_CallTransferUpdate(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_h450_CTUpdateArg(tvb, offset, pinfo, tree, hf_index);

  return offset;
}

static const per_sequence_t SubaddressTransferArg_sequence[] = {
  { "redirectionSubaddress"       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_redirectionSubaddress },
  { "argumentExtension"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_argumentExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_SubaddressTransferArg(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                ett_h450_SubaddressTransferArg, SubaddressTransferArg_sequence);

  return offset;
}


static int
dissect_h450_SubaddressTransfer(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_h450_SubaddressTransferArg(tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static const value_string h450_EndDesignation_vals[] = {
  {   0, "primaryEnd" },
  {   1, "secondaryEnd" },
  { 0, NULL }
};


static int
dissect_h450_EndDesignation(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                           0, 1, NULL, NULL, TRUE);

  return offset;
}
static int dissect_endDesignation(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_EndDesignation(tvb, offset, pinfo, tree, hf_h450_endDesignation);
}


static const value_string h450_CallStatus_vals[] = {
  {   0, "answered" },
  {   1, "alerting" },
  { 0, NULL }
};


static int
dissect_h450_CallStatus(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                           0, 1, NULL, NULL, TRUE);

  return offset;
}
static int dissect_callStatus(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_CallStatus(tvb, offset, pinfo, tree, hf_h450_callStatus);
}

static const per_sequence_t CTCompleteArg_sequence[] = {
  { "endDesignation"              , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_endDesignation },
  { "redirectionNumber"           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_redirectionNumber },
  { "basicCallInfoElements"       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_basicCallInfoElements },
  { "redirectionInfo"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_redirectionInfo },
  { "callStatus"                  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_callStatus },
  { "argumentExtension"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_argumentExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CTCompleteArg(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                ett_h450_CTCompleteArg, CTCompleteArg_sequence);

  return offset;
}


static int
dissect_h450_CallTransferComplete(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_h450_CTCompleteArg(tvb, offset, pinfo, tree, hf_index);

  return offset;
}

static const per_sequence_t CTActiveArg_sequence[] = {
  { "connectedAddress"            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_connectedAddress },
  { "basicCallInfoElements"       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_basicCallInfoElements },
  { "connectedInfo"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_connectedInfo },
  { "argumentExtension"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_argumentExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CTActiveArg(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                ett_h450_CTActiveArg, CTActiveArg_sequence);

  return offset;
}


static int
dissect_h450_CallTransferActive(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_h450_CTActiveArg(tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static int
dissect_h450_CallIdentity(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_NumericString(tvb, offset, pinfo, tree, hf_index,
                                     0, 4);

  return offset;
}
static int dissect_callIdentity(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_CallIdentity(tvb, offset, pinfo, tree, hf_h450_callIdentity);
}

static const per_sequence_t CTInitiateArg_sequence[] = {
  { "callIdentity"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_callIdentity },
  { "reroutingNumber"             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_reroutingNumber },
  { "argumentExtension"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_argumentExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CTInitiateArg(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                ett_h450_CTInitiateArg, CTInitiateArg_sequence);

  return offset;
}

static const per_sequence_t CTSetupArg_sequence[] = {
  { "callIdentity"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_callIdentity },
  { "transferringNumber"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_transferringNumber },
  { "argumentExtension"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_argumentExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CTSetupArg(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                ett_h450_CTSetupArg, CTSetupArg_sequence);

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
dissect_h450_T_resultExtension(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, pinfo, tree, hf_index,
                              ett_h450_T_resultExtension, T_resultExtension_choice, "T_resultExtension",
                              NULL);

  return offset;
}
static int dissect_resultExtension(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_T_resultExtension(tvb, offset, pinfo, tree, hf_h450_resultExtension);
}

static const per_sequence_t CTIdentifyRes_sequence[] = {
  { "callIdentity"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_callIdentity },
  { "reroutingNumber"             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_reroutingNumber },
  { "resultExtension"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_resultExtension },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CTIdentifyRes(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                ett_h450_CTIdentifyRes, CTIdentifyRes_sequence);

  return offset;
}


static const value_string h450_MixedExtension_vals[] = {
  {   0, "extension" },
  {   1, "nonStandardData" },
  { 0, NULL }
};

static const per_choice_t MixedExtension_choice[] = {
  {   0, "extension"                   , ASN1_NO_EXTENSIONS     , dissect_extension },
  {   1, "nonStandardData"             , ASN1_NO_EXTENSIONS     , dissect_nonStandardData },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_MixedExtension(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, pinfo, tree, hf_index,
                              ett_h450_MixedExtension, MixedExtension_choice, "MixedExtension",
                              NULL);

  return offset;
}
static int dissect_ExtensionArg_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_MixedExtension(tvb, offset, pinfo, tree, hf_h450_ExtensionArg_item);
}
static int dissect_extensionRes_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_MixedExtension(tvb, offset, pinfo, tree, hf_h450_extensionRes_item);
}
static int dissect_MwiDummyRes_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_MixedExtension(tvb, offset, pinfo, tree, hf_h450_MwiDummyRes_item);
}


static int
dissect_h450_ExtensionArg(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_index,
                                               ett_h450_ExtensionArg, dissect_ExtensionArg_item,
                                               0, 255);

  return offset;
}
static int dissect_extensionArg(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_ExtensionArg(tvb, offset, pinfo, tree, hf_h450_extensionArg);
}

static const per_sequence_t HoldNotificArg_sequence[] = {
  { "extensionArg"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_extensionArg },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_HoldNotificArg(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                ett_h450_HoldNotificArg, HoldNotificArg_sequence);

  return offset;
}


static int
dissect_h450_HoldNotific(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_h450_HoldNotificArg(tvb, offset, pinfo, tree, hf_index);

  return offset;
}

static const per_sequence_t RetrieveNotificArg_sequence[] = {
  { "extensionArg"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_extensionArg },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_RetrieveNotificArg(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                ett_h450_RetrieveNotificArg, RetrieveNotificArg_sequence);

  return offset;
}


static int
dissect_h450_RetrieveNotific(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_h450_RetrieveNotificArg(tvb, offset, pinfo, tree, hf_index);

  return offset;
}

static const per_sequence_t RemoteHoldArg_sequence[] = {
  { "extensionArg"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_extensionArg },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_RemoteHoldArg(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                ett_h450_RemoteHoldArg, RemoteHoldArg_sequence);

  return offset;
}


static int
dissect_h450_RemoteHold(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_h450_RemoteHoldArg(tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static int
dissect_h450_SEQUNCE_SIZE_0_255_OF_MixedExtension(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_index,
                                               ett_h450_SEQUNCE_SIZE_0_255_OF_MixedExtension, dissect_extensionRes_item,
                                               0, 255);

  return offset;
}
static int dissect_extensionRes(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_SEQUNCE_SIZE_0_255_OF_MixedExtension(tvb, offset, pinfo, tree, hf_h450_extensionRes);
}

static const per_sequence_t RemoteHoldRes_sequence[] = {
  { "extensionRes"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_extensionRes },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_RemoteHoldRes(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                ett_h450_RemoteHoldRes, RemoteHoldRes_sequence);

  return offset;
}

static const per_sequence_t RemoteRetrieveArg_sequence[] = {
  { "extensionArg"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_extensionArg },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_RemoteRetrieveArg(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                ett_h450_RemoteRetrieveArg, RemoteRetrieveArg_sequence);

  return offset;
}


static int
dissect_h450_RemoteRetrieve(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_h450_RemoteRetrieveArg(tvb, offset, pinfo, tree, hf_index);

  return offset;
}

static const per_sequence_t RemoteRetrieveRes_sequence[] = {
  { "extensionRes"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_extensionRes },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_RemoteRetrieveRes(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                ett_h450_RemoteRetrieveRes, RemoteRetrieveRes_sequence);

  return offset;
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


static int
dissect_h450_BasicService(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                           0, 75, NULL, NULL, FALSE);

  return offset;
}
static int dissect_basicService(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_BasicService(tvb, offset, pinfo, tree, hf_h450_basicService);
}



static int
dissect_h450_INTEGER_0_65535(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                           0U, 65535U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_integer(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_INTEGER_0_65535(tvb, offset, pinfo, tree, hf_h450_integer);
}


static int
dissect_h450_NumericString_SIZE_1_10(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_NumericString(tvb, offset, pinfo, tree, hf_index,
                                     1, 10);

  return offset;
}
static int dissect_numericString(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_NumericString_SIZE_1_10(tvb, offset, pinfo, tree, hf_h450_numericString);
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
dissect_h450_MsgCentreId(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, pinfo, tree, hf_index,
                              ett_h450_MsgCentreId, MsgCentreId_choice, "MsgCentreId",
                              NULL);

  return offset;
}
static int dissect_msgCentreId(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_MsgCentreId(tvb, offset, pinfo, tree, hf_h450_msgCentreId);
}



static int
dissect_h450_NbOfMessages(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                           0U, 65535U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_nbOfMessages(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_NbOfMessages(tvb, offset, pinfo, tree, hf_h450_nbOfMessages);
}


static int
dissect_h450_TimeStamp(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_VisibleString(tvb, offset, pinfo, tree, hf_index,
                                     12, 19);

  return offset;
}
static int dissect_timestamp(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_TimeStamp(tvb, offset, pinfo, tree, hf_h450_timestamp);
}



static int
dissect_h450_INTEGER_0_9(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                           0U, 9U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_priority(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_INTEGER_0_9(tvb, offset, pinfo, tree, hf_h450_priority);
}

static const per_sequence_t MWIActivateArg_sequence[] = {
  { "servedUserNr"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_servedUserNr },
  { "basicService"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_basicService },
  { "msgCentreId"                 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_msgCentreId },
  { "nbOfMessages"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nbOfMessages },
  { "originatingNr"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_originatingNr },
  { "timestamp"                   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_timestamp },
  { "priority"                    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_priority },
  { "extensionArg"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_extensionArg },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_MWIActivateArg(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                ett_h450_MWIActivateArg, MWIActivateArg_sequence);

  return offset;
}


static int
dissect_h450_MwiActivate(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_h450_MWIActivateArg(tvb, offset, pinfo, tree, hf_index);

  return offset;
}

static const per_sequence_t MWIDeactivateArg_sequence[] = {
  { "servedUserNr"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_servedUserNr },
  { "basicService"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_basicService },
  { "msgCentreId"                 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_msgCentreId },
  { "callbackReq"                 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_callbackReq },
  { "extensionArg"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_extensionArg },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_MWIDeactivateArg(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                ett_h450_MWIDeactivateArg, MWIDeactivateArg_sequence);

  return offset;
}


static int
dissect_h450_MwiDeactivate(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_h450_MWIDeactivateArg(tvb, offset, pinfo, tree, hf_index);

  return offset;
}

static const per_sequence_t MWIInterrogateArg_sequence[] = {
  { "servedUserNr"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_servedUserNr },
  { "basicService"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_basicService },
  { "msgCentreId"                 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_msgCentreId },
  { "callbackReq"                 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_callbackReq },
  { "extensionArg"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_extensionArg },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_MWIInterrogateArg(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                ett_h450_MWIInterrogateArg, MWIInterrogateArg_sequence);

  return offset;
}


static int
dissect_h450_MwiInterrogate(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_h450_MWIInterrogateArg(tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static int
dissect_h450_MwiDummyRes(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_index,
                                               ett_h450_MwiDummyRes, dissect_MwiDummyRes_item,
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
  { "extensionArg"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_extensionArg },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_MWIInterrogateResElt(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                ett_h450_MWIInterrogateResElt, MWIInterrogateResElt_sequence);

  return offset;
}
static int dissect_MWIInterrogateRes_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_MWIInterrogateResElt(tvb, offset, pinfo, tree, hf_h450_MWIInterrogateRes_item);
}


static int
dissect_h450_MWIInterrogateRes(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_index,
                                               ett_h450_MWIInterrogateRes, dissect_MWIInterrogateRes_item,
                                               1, 64);

  return offset;
}


static int
dissect_h450_SimpleName(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, pinfo, tree, hf_index,
                                    1, 50,
                                    NULL, NULL);

  return offset;
}
static int dissect_simpleName(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_SimpleName(tvb, offset, pinfo, tree, hf_h450_simpleName);
}


static int
dissect_h450_ExtendedName(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_BMPString(tvb, offset, pinfo, tree, hf_index,
                                 1, 256);

  return offset;
}
static int dissect_extendedName(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_ExtendedName(tvb, offset, pinfo, tree, hf_h450_extendedName);
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
dissect_h450_NamePresentationAllowed(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, pinfo, tree, hf_index,
                              ett_h450_NamePresentationAllowed, NamePresentationAllowed_choice, "NamePresentationAllowed",
                              NULL);

  return offset;
}
static int dissect_namePresentationAllowed(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_NamePresentationAllowed(tvb, offset, pinfo, tree, hf_h450_namePresentationAllowed);
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
dissect_h450_NamePresentationRestricted(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, pinfo, tree, hf_index,
                              ett_h450_NamePresentationRestricted, NamePresentationRestricted_choice, "NamePresentationRestricted",
                              NULL);

  return offset;
}
static int dissect_namePresentationRestricted(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_NamePresentationRestricted(tvb, offset, pinfo, tree, hf_h450_namePresentationRestricted);
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
dissect_h450_Name(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, pinfo, tree, hf_index,
                              ett_h450_Name, Name_choice, "Name",
                              NULL);

  return offset;
}
static int dissect_name(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_h450_Name(tvb, offset, pinfo, tree, hf_h450_name);
}

static const per_sequence_t CallingName_sequence[] = {
  { "name"                        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_name },
  { "extensionArg"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_extensionArg },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_CallingName(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                ett_h450_CallingName, CallingName_sequence);

  return offset;
}

static const per_sequence_t AlertingName_sequence[] = {
  { "name"                        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_name },
  { "extensionArg"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_extensionArg },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_AlertingName(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                ett_h450_AlertingName, AlertingName_sequence);

  return offset;
}

static const per_sequence_t ConnectedName_sequence[] = {
  { "name"                        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_name },
  { "extensionArg"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_extensionArg },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_ConnectedName(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                ett_h450_ConnectedName, ConnectedName_sequence);

  return offset;
}

static const per_sequence_t BusyName_sequence[] = {
  { "name"                        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_name },
  { "extensionArg"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_extensionArg },
  { NULL, 0, 0, NULL }
};

static int
dissect_h450_BusyName(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                ett_h450_BusyName, BusyName_sequence);

  return offset;
}


static const value_string h450_Unspecified_vals[] = {
  {   0, "extension" },
  {   1, "nonStandard" },
  { 0, NULL }
};

static const per_choice_t Unspecified_choice[] = {
  {   0, "extension"                   , ASN1_NO_EXTENSIONS     , dissect_extension1 },
  {   1, "nonStandard"                 , ASN1_NO_EXTENSIONS     , dissect_nonStandard },
  { 0, NULL, 0, NULL }
};

static int
dissect_h450_Unspecified(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, pinfo, tree, hf_index,
                              ett_h450_Unspecified, Unspecified_choice, "Unspecified",
                              NULL);

  return offset;
}


/*--- End of included file: packet-h450-fn.c ---*/


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
dissect_h4501_InvokeProblem(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_h4501_InvokeProblem, 0, 7, NULL, NULL, FALSE);
   return offset;
}


static const value_string ReturnResultProblem_vals[] = {
   {  0, "unrecognizedInvocation"},
   {  1, "resultResponseUnexpected"},
   {  2, "mistypedResult"},
   {  0, NULL }
};
static int
dissect_h4501_ReturnResultProblem(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_h4501_ReturnResultProblem, 0, 2, NULL, NULL, FALSE);
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
dissect_h4501_ReturnErrorProblem(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_h4501_ReturnErrorProblem, 0, 4, NULL, NULL, FALSE);
   return offset;
}

static const value_string GeneralProblem_vals[] = {
   {  0, "unrecognizedCompenent"},
   {  1, "mistypedCompenent"},
   {  2, "badlyStructuredCompenent"},
   {  0, NULL }
};
static int
dissect_h4501_GeneralProblem(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_h4501_GeneralProblem, 0, 2, NULL, NULL, FALSE);
   return offset;
}
static int
dissect_h4501_ReturnResult_result(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   tvbuff_t *result_tvb;
   guint32 result_offset=0;
   guint32 result_len=0;

   offset=dissect_per_octet_string(tvb, offset, pinfo, tree, -1, -1, -1, &result_offset, &result_len);

   if(result_len){
      result_tvb = tvb_new_subset(tvb, result_offset, result_len, result_len);

      switch (localOpcode) {
      case CallTransferIdentify:
         dissect_h450_CTIdentifyRes(result_tvb, 0, pinfo, tree, hf_h4502_CTIdentifyRes);
         break;

      case CallTransferInitiate:
      case CallTransferSetup:
         dissect_h450_DummyRes(result_tvb, 0, pinfo , tree, hf_h4502_DummyRes);
         break;
	case RemoteRetrieve:
         dissect_h450_RemoteRetrieveRes(result_tvb, 0, pinfo , tree, hf_h4504_RemoteRetrieveRes);
         break;
	case MWIActivate:
		dissect_h450_MwiDummyRes(result_tvb, 0, pinfo , tree, hf_h4507_MwiDummyRes);
		break;
	case MWIDeactivate:
		dissect_h450_MwiDummyRes(result_tvb, 0, pinfo , tree, hf_h4507_MwiDummyRes);
		break;
	case MWIInterrogate:
		dissect_h450_MWIInterrogateRes(result_tvb, 0, pinfo , tree, hf_h4507_MWIInterrogateRes);
		break;

      default:
PER_NOT_DECODED_YET("Unrecognized H.450.x return result");
         break;
      }
   }

   return offset;
}

static int
dissect_h4501_localOpcode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_integer(tvb, offset, pinfo, tree, hf_h4501_localOpcode, &localOpcode, NULL);
   is_globalcode = FALSE;
	return offset;
}


static int
dissect_h4501_globalCode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	offset=dissect_per_object_identifier(tvb, offset, pinfo, tree, hf_h4501_globalCode, globalcode_oid_str);
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
dissect_h4501_opcode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h4501_opcode, ett_h4501_opcode, opcode_choice, "Opcode", NULL);
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
dissect_h4501_result(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h4501_result, ett_h4501_result, result_sequence);
   return offset;
}

static int
dissect_h4501_parameter(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   /* TODO - decode return error parameter based on localErrorCode */
   offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h4501_parameter, -1, -1, NULL, NULL);
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
dissect_h4501_localErrorCode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_integer(tvb, offset, pinfo, tree, hf_h4501_localErrorCode, &localErrorCode, NULL);
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
dissect_h4501_errorCode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h4501_errorCode, ett_h4501_errorCode, errorCode_choice, "errorCode", NULL);
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
dissect_h4501_problem(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h4501_problem, ett_h4501_problem, problem_choice, "problem", NULL);
   return offset;
}
static int
dissect_h4501_constrained_invokeId(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_h4501_constrained_invokeId, 0, 65535, NULL, NULL, FALSE);
	return offset;
}


static int
dissect_h4501_invokeId(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_integer(tvb, offset, pinfo, tree, hf_h4501_invokeId, NULL, NULL);
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
dissect_h4501_Reject(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h4501_Reject, ett_h4501_Reject, Reject_sequence);
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
dissect_h4501_ReturnError(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h4501_ReturnError, ett_h4501_ReturnError, ReturnError_sequence);
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
dissect_h4501_ReturnResult(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h4501_ReturnResult, ett_h4501_ReturnResult, ReturnResult_sequence);
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
dissect_h4501_Invoke(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_sequence(tvb, offset, pinfo, tree, hf_h4501_Invoke, ett_h4501_Invoke, Invoke_sequence);
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
dissect_h4501_ROS(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h4501_ROS, ett_h4501_ROS, ROS_choice, "ROS", NULL);
   return offset;
}

static int
dissect_h4501_argument(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   tvbuff_t *argument_tvb;
   guint32 argument_offset=0;
   guint32 argument_len=0;

  if ( is_globalcode ){
	  /* TODO call oid dissector
	   * call_ber_oid_callback isn't realy apropriate ?
	   */
	  offset = dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h4501_globalargument, -1, -1, NULL, NULL);
	  is_globalcode = FALSE;
	  return offset;

  }

   offset=dissect_per_octet_string(tvb, offset, pinfo, tree, -1, -1, -1, &argument_offset, &argument_len);

   if(argument_len){
      argument_tvb = tvb_new_subset(tvb, argument_offset, argument_len, argument_len);


      switch (localOpcode) {
		  case CallTransferIdentify:  /* Localvalue 7 */
	      case CallTransferAbandon:   /* Localvalue 8 */
			 dissect_h450_DummyArg(argument_tvb, 0, pinfo , tree, hf_h4502_DummyArg);
			 break;

		   case CallTransferInitiate:  /* Localvalue 9 */
	         dissect_h450_CTInitiateArg(argument_tvb, 0, pinfo , tree, hf_h4502_CTInitiateArg);
	         break;

	      case CallTransferSetup:		/* Localvalue 10 */
	         dissect_h450_CTSetupArg(argument_tvb, 0, pinfo , tree, hf_h4502_CTSetupArg);
	         break;

	      case CallTransferUpdate:		/* Localvalue 13 */
	         dissect_h450_CTUpdateArg(argument_tvb, 0, pinfo , tree, hf_h4502_CTUpdateArg);
	         break;

		  case SubaddressTransfer:		/* Localvalue 14 */
	         dissect_h450_SubaddressTransfer(argument_tvb, 0, pinfo , tree, hf_h4502_SubaddressTransferArg);
	         break;

	      case CallTransferComplete:	/* Localvalue 12 */
	         dissect_h450_CTCompleteArg(argument_tvb, 0, pinfo , tree, hf_h4502_CTCompleteArg);
	         break;

	      case CallTransferActive:		/* Localvalue 11 */
	         dissect_h450_CTActiveArg(argument_tvb, 0, pinfo , tree, hf_h4502_CTActiveArg);
		     break;
		  /* H.450.4 */
	      case HoldNotific:				/* Localvalue 101 */
			   dissect_h450_HoldNotificArg(argument_tvb, 0, pinfo , tree, hf_h4504_HoldNotificArg);
		     break;
	      case RetrieveNotific:			/* Localvalue 102 */
			   dissect_h450_RetrieveNotificArg(argument_tvb, 0, pinfo , tree, hf_h4504_RetrieveNotificArg);
		     break;
	      case RemoteHold:				/* Localvalue 103 */
			   dissect_h450_RemoteHoldArg(argument_tvb, 0, pinfo , tree, hf_h4504_RemoteHoldArg);
		     break;
	      case RemoteRetrieve:			/* Localvalue 104 */
			   dissect_h450_RemoteRetrieveArg(argument_tvb, 0, pinfo , tree, hf_h4504_RemoteRetrieveArg);
		     break;
		  /* H.450.7 Message Waiting Indication  */
		  case MWIActivate:				/* Localvalue 80 */
			   dissect_h450_MWIActivateArg(argument_tvb, 0, pinfo , tree, hf_h4507_MWIActivateArg);
		     break;
		  case MWIDeactivate:			/* Localvalue 81 */
			   dissect_h450_MWIDeactivateArg(argument_tvb, 0, pinfo , tree, hf_h4507_MWIDeactivateArg);
		     break;
		  case MWIInterrogate:			/* Localvalue 82 */
			   dissect_h450_MWIInterrogateArg(argument_tvb, 0, pinfo , tree, hf_h4507_MWIInterrogateArg);
		     break;

		  /* H.450.8 */
		  case NIcallingName:			/* Localvalue 0 */
			  dissect_h450_CallingName(argument_tvb, 0, pinfo , tree, hf_h4508_CallingNameArg);
			  break;
		  case NIalertingName:			/* Localvalue 1 */
			  dissect_h450_AlertingName(argument_tvb, 0, pinfo , tree, hf_h4508_AlertingNameArg);
			  break;
		  case NIconnectedName:			/* Localvalue 2 */
			  dissect_h450_ConnectedName(argument_tvb, 0, pinfo , tree, hf_h4508_ConnectedNameArg);
			  break;
		  case NIbusyName:			/* Localvalue 3 */
			  dissect_h450_BusyName(argument_tvb, 0, pinfo , tree, hf_h4508_BusyNameArg);
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
dissect_ros_ROSxxx(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_ind _U_){

	offset = dissect_h4501_ROS(tvb, offset, pinfo, tree);
	return offset;

}
static int
dissect_h4501(tvbuff_t *tvb, packet_info *pinfo, proto_tree* tree)
{
   proto_item *it;
   proto_tree *tr;
   guint32 offset=0;

   it=proto_tree_add_protocol_format(tree, proto_h4501, tvb, 0, tvb_length(tvb), "H.450.1");
   tr=proto_item_add_subtree(it, ett_h4501);

   dissect_h450_H4501SupplementaryService(tvb, offset, pinfo, tr, hf_h4501);
   return offset;

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

   { &hf_h4502_CTActiveArg,
      { "CTActiveArg", "h4502.CTActiveArg", FT_NONE, BASE_NONE,
      NULL, 0, "CTActiveArg sequence of", HFILL }},
   { &hf_h4502_CTCompleteArg,
      { "CTCompleteArg", "h4502.CTCompleteArg", FT_NONE, BASE_NONE,
      NULL, 0, "CTCompleteArg sequence of", HFILL }},
   { &hf_h4502_CTIdentifyRes,
      { "CTIdentifyRes", "h4502.CTIdentifyRes", FT_NONE, BASE_NONE,
      NULL, 0, "CTIdentifyRes sequence of", HFILL }},
   { &hf_h4502_DummyRes,
      { "DummyRes", "h4502.DummyRes", FT_UINT32, BASE_DEC,
      VALS(h450_DummyRes_vals), 0, "DummyRes Choice", HFILL }},
   { &hf_h4502_DummyArg,
      { "DummyArg", "h4502.DummyArg", FT_UINT32, BASE_DEC,
      VALS(h450_DummyArg_vals), 0, "DummyArg choice", HFILL }},
   { &hf_h4502_CTInitiateArg,
      { "CTInitiateArg", "h4502.CTInitiateArg", FT_NONE, BASE_NONE,
      NULL, 0, "CTInitiateArg sequence of", HFILL }},
   { &hf_h4502_CTSetupArg,
      { "CTSetupArg", "h4502.CTSetupArg", FT_NONE, BASE_NONE,
      NULL, 0, "CTSetupArg sequence of", HFILL }},
   { &hf_h4502_CTUpdateArg,
      { "CTUpdateArg", "h4502.CTUpdateArg", FT_NONE, BASE_NONE,
      NULL, 0, "CTUpdateArg sequence of", HFILL }},
   { &hf_h4502_SubaddressTransferArg,
      { "SubaddressTransferArg", "h4502.SubaddressTransferArg", FT_NONE, BASE_NONE,
      NULL, 0, "SubaddressTransferArg sequence of", HFILL }},

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


/*--- Included file: packet-h450-hfarr.c ---*/

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
        FT_NONE, BASE_NONE, NULL, 0,
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
        FT_NONE, BASE_NONE, NULL, 0,
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
        FT_NONE, BASE_NONE, NULL, 0,
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
    { &hf_h450_argumentExtension,
      { "argumentExtension", "h450.argumentExtension",
        FT_UINT32, BASE_DEC, VALS(h450_ArgumentExtension_vals), 0,
        "", HFILL }},
    { &hf_h450_transferringNumber,
      { "transferringNumber", "h450.transferringNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        "CTSetupArg/transferringNumber", HFILL }},
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
    { &hf_h450_redirectionSubaddress,
      { "redirectionSubaddress", "h450.redirectionSubaddress",
        FT_UINT32, BASE_DEC, VALS(h450_PartySubaddress_vals), 0,
        "SubaddressTransferArg/redirectionSubaddress", HFILL }},
    { &hf_h450_endDesignation,
      { "endDesignation", "h450.endDesignation",
        FT_UINT32, BASE_DEC, VALS(h450_EndDesignation_vals), 0,
        "CTCompleteArg/endDesignation", HFILL }},
    { &hf_h450_callStatus,
      { "callStatus", "h450.callStatus",
        FT_UINT32, BASE_DEC, VALS(h450_CallStatus_vals), 0,
        "CTCompleteArg/callStatus", HFILL }},
    { &hf_h450_connectedAddress,
      { "connectedAddress", "h450.connectedAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "CTActiveArg/connectedAddress", HFILL }},
    { &hf_h450_connectedInfo,
      { "connectedInfo", "h450.connectedInfo",
        FT_STRING, BASE_NONE, NULL, 0,
        "CTActiveArg/connectedInfo", HFILL }},
    { &hf_h450_ExtensionSeq_item,
      { "Item", "h450.ExtensionSeq_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ExtensionSeq/_item", HFILL }},
    { &hf_h450_extensionArg,
      { "extensionArg", "h450.extensionArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h450_ExtensionArg_item,
      { "Item", "h450.ExtensionArg_item",
        FT_UINT32, BASE_DEC, VALS(h450_MixedExtension_vals), 0,
        "ExtensionArg/_item", HFILL }},
    { &hf_h450_extensionRes,
      { "extensionRes", "h450.extensionRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h450_extensionRes_item,
      { "Item", "h450.extensionRes_item",
        FT_UINT32, BASE_DEC, VALS(h450_MixedExtension_vals), 0,
        "", HFILL }},
    { &hf_h450_extension,
      { "extension", "h450.extension",
        FT_NONE, BASE_NONE, NULL, 0,
        "MixedExtension/extension", HFILL }},
    { &hf_h450_servedUserNr,
      { "servedUserNr", "h450.servedUserNr",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h450_basicService,
      { "basicService", "h450.basicService",
        FT_UINT32, BASE_DEC, VALS(h450_BasicService_vals), 0,
        "", HFILL }},
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
    { &hf_h450_MwiDummyRes_item,
      { "Item", "h450.MwiDummyRes_item",
        FT_UINT32, BASE_DEC, VALS(h450_MixedExtension_vals), 0,
        "MwiDummyRes/_item", HFILL }},
    { &hf_h450_callbackReq,
      { "callbackReq", "h450.callbackReq",
        FT_BOOLEAN, 8, NULL, 0,
        "", HFILL }},
    { &hf_h450_MWIInterrogateRes_item,
      { "Item", "h450.MWIInterrogateRes_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "MWIInterrogateRes/_item", HFILL }},
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
    { &hf_h450_name,
      { "name", "h450.name",
        FT_UINT32, BASE_DEC, VALS(h450_Name_vals), 0,
        "", HFILL }},
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
    { &hf_h450_extension1,
      { "extension", "h450.extension",
        FT_NONE, BASE_NONE, NULL, 0,
        "Unspecified/extension", HFILL }},
    { &hf_h450_nonStandard,
      { "nonStandard", "h450.nonStandard",
        FT_NONE, BASE_NONE, NULL, 0,
        "Unspecified/nonStandard", HFILL }},

/*--- End of included file: packet-h450-hfarr.c ---*/

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

    &ett_h450_H4501SupplementaryService,
    &ett_h450_NetworkFacilityExtension,
    &ett_h450_EntityType,
    &ett_h450_InterpretationApdu,
    &ett_h450_ServiceApdus,
    &ett_h450_SEQUNCE_OF_ROSxxx,
    &ett_h450_PresentedAddressScreened,
    &ett_h450_PresentedAddressUnscreened,
    &ett_h450_PresentedNumberScreened,
    &ett_h450_PresentedNumberUnscreened,
    &ett_h450_AddressScreened,
    &ett_h450_NumberScreened,
    &ett_h450_Address,
    &ett_h450_EndpointAddress,
    &ett_h450_SEQUNCE_OF_AliasAddress,
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
    &ett_h450_HoldNotificArg,
    &ett_h450_ExtensionArg,
    &ett_h450_RetrieveNotificArg,
    &ett_h450_RemoteHoldArg,
    &ett_h450_RemoteHoldRes,
    &ett_h450_SEQUNCE_SIZE_0_255_OF_MixedExtension,
    &ett_h450_RemoteRetrieveArg,
    &ett_h450_RemoteRetrieveRes,
    &ett_h450_MixedExtension,
    &ett_h450_MWIActivateArg,
    &ett_h450_MwiDummyRes,
    &ett_h450_MWIDeactivateArg,
    &ett_h450_MWIInterrogateArg,
    &ett_h450_MWIInterrogateRes,
    &ett_h450_MWIInterrogateResElt,
    &ett_h450_MsgCentreId,
    &ett_h450_CallingName,
    &ett_h450_AlertingName,
    &ett_h450_ConnectedName,
    &ett_h450_BusyName,
    &ett_h450_Name,
    &ett_h450_NamePresentationAllowed,
    &ett_h450_NamePresentationRestricted,
    &ett_h450_Unspecified,

/*--- End of included file: packet-h450-ettarr.c ---*/

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




