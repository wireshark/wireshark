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
static int hf_h4502_CTInitiateArg = -1;
static int hf_h4502_CTSetupArg = -1;
static int hf_h4502_CTUpdateArg = -1;
static int hf_h4502_SubaddressTransferArg = -1;
static int hf_h4502_CTCompleteArg = -1;
static int hf_h4502_CTActiveArg = -1;

static int hf_h4503ActivateDiversionQArg = -1;
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

#include "packet-h450-hf.c"

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

#include "packet-h450-ett.c"

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
/* H.450.12 Common Information Operations constants */
   { CmnRequest,				"CmnRequest"},
   { CmnInform,					"CmnInform"},
	{  0, NULL }
};

static int dissect_h4501_argument(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree);
static int dissect_ros_ROSxxx(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_ind _U_);



#include "packet-h450-fn.c"

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
   tvbuff_t *result_tvb = NULL;

   offset=dissect_per_octet_string(tvb, offset, pinfo, tree, -1, -1, -1, &result_tvb);

   if(tvb_length(result_tvb)){
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
   offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h4501_opcode, ett_h4501_opcode, opcode_choice, NULL);
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
   offset=dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h4501_parameter, -1, -1, NULL);
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
   offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h4501_errorCode, ett_h4501_errorCode, errorCode_choice, NULL);
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
   offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h4501_problem, ett_h4501_problem, problem_choice, NULL);
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
   offset=dissect_per_choice(tvb, offset, pinfo, tree, hf_h4501_ROS, ett_h4501_ROS, ROS_choice, NULL);
   return offset;
}

static int
dissect_h4501_argument(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
   tvbuff_t *argument_tvb = NULL;

  if ( is_globalcode ){
	  /* TODO call oid dissector
	   * call_ber_oid_callback isn't realy apropriate ?
	   */
	  offset = dissect_per_octet_string(tvb, offset, pinfo, tree, hf_h4501_globalargument, -1, -1, NULL);
	  is_globalcode = FALSE;
	  return offset;

  }

   offset=dissect_per_octet_string(tvb, offset, pinfo, tree, -1, -1, -1, &argument_tvb);

   if(tvb_length(argument_tvb)){
      switch (localOpcode) {
		  /* h450.2 */
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
		  /* h450.3*/

		  case ActivateDiversionQ:          /* Localvalue 15 */
	         dissect_h450_ActivateDiversionQArg(argument_tvb, 0, pinfo , tree, hf_h4503ActivateDiversionQArg);
		     break;
		  case DeactivateDiversionQ:        /* Localvalue 16 */
	         dissect_h450_DeactivateDiversionQArg(argument_tvb, 0, pinfo , tree, hf_h4503DeactivateDiversionQArg);
		     break;
		  case InterrogateDiversionQ:       /* Localvalue 17 */
	         dissect_h450_InterrogateDiversionQ(argument_tvb, 0, pinfo , tree, hf_h4503InterrogateDiversionQ);
		     break;
		  case CheckRestriction:            /* Localvalue 18 */
	         dissect_h450_CheckRestrictionArg(argument_tvb, 0, pinfo , tree, hf_h4503CheckRestrictionArg);
		     break;
		  case CallRerouting:               /* Localvalue 19 */
	         dissect_h450_CallReroutingArg(argument_tvb, 0, pinfo , tree, hf_h4503CallReroutingArg);
		     break;
		  case DivertingLegInformation1:    /* Localvalue 20 */
	         dissect_h450_DivertingLegInformation1Arg(argument_tvb, 0, pinfo , tree, hf_h4503DivertingLegInformation1Arg);
		     break;
		  case DivertingLegInformation2:   /* Localvalue 21 */
	         dissect_h450_DivertingLegInformation2Arg(argument_tvb, 0, pinfo , tree, hf_h4503DivertingLegInformation2Arg);
		     break;
		  case DivertingLegInformation3:   /* Localvalue 22 */
	         dissect_h450_DivertingLegInformation3Arg(argument_tvb, 0, pinfo , tree, hf_h4503DivertingLegInformation3Arg);
		     break;
		  case DivertingLegInformation4:    /* Localvalue 100 */
	         dissect_h450_DivertingLegInformation4Arg(argument_tvb, 0, pinfo , tree, hf_h4503DivertingLegInformation4Arg);
		     break;
		  case CfnrDivertedLegFailed:       /* Localvalue 23 */
	         dissect_h450_CfnrDivertedLegFailedArg(argument_tvb, 0, pinfo , tree, hf_h4503CfnrDivertedLegFailedArg);
		     break;
		  /* H.450.4 Call Hold */
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
			   dissect_h450_MWIActivateArg(argument_tvb, 0, pinfo , tree, hf_h4507_MWIActivateArg);
		     break;
		  case MWIDeactivate:			/* Localvalue 81 */
			   dissect_h450_MWIDeactivateArg(argument_tvb, 0, pinfo , tree, hf_h4507_MWIDeactivateArg);
		     break;
		  case MWIInterrogate:			/* Localvalue 82 */
			   dissect_h450_MWIInterrogateArg(argument_tvb, 0, pinfo , tree, hf_h4507_MWIInterrogateArg);
		     break;

		  /* H.450.8 Name Identification */
		  case NIcallingName:			/* Localvalue 0 */
			  dissect_h450_NameArg(argument_tvb, 0, pinfo , tree, hf_h4508_CallingNameArg);
			  break;
		  case NIalertingName:			/* Localvalue 1 */
			  dissect_h450_NameArg(argument_tvb, 0, pinfo , tree, hf_h4508_AlertingNameArg);
			  break;
		  case NIconnectedName:			/* Localvalue 2 */
			  dissect_h450_NameArg(argument_tvb, 0, pinfo , tree, hf_h4508_ConnectedNameArg);
			  break;
		  case NIbusyName:			/* Localvalue 3 */
			  dissect_h450_NameArg(argument_tvb, 0, pinfo , tree, hf_h4508_BusyNameArg);
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
			  dissect_h450_CmnRequestArg(argument_tvb, 0, pinfo , tree, hf_h45012_CmnRequest);
			  break;
		  case CmnInform:					/* Localvalue 85 */
			  dissect_h450_CmnArg(argument_tvb, 0, pinfo , tree, hf_h45012_CmnInform);
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
static void
dissect_h4501(tvbuff_t *tvb, packet_info *pinfo, proto_tree* tree)
{
   proto_item *it;
   proto_tree *tr;
   guint32 offset=0;

   it=proto_tree_add_protocol_format(tree, proto_h4501, tvb, 0, -1, "H.450.1");
   tr=proto_item_add_subtree(it, ett_h4501);

   dissect_h450_H4501SupplementaryService(tvb, offset, pinfo, tr, hf_h4501);
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

   { &hf_h4503ActivateDiversionQArg,
      { "ActivateDiversionQArg", "h4503.ActivateDiversionQArg", FT_NONE, BASE_NONE,
      NULL, 0, "ActivateDiversionQArg sequence of", HFILL }},
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

#include "packet-h450-hfarr.c"
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
#include "packet-h450-ettarr.c"
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
