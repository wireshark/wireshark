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
 * ITU Q.1218
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
#include "packet-isup.h"

#define PNAME  "Intelligent Network Application Protocol"
#define PSNAME "INAP"
#define PFNAME "inap"

/* Initialize the protocol and registered fields */
int proto_inap = -1;
static int hf_inap_invokeCmd = -1;             /* Opcode */
static int hf_inap_invokeid = -1;              /* INTEGER */
static int hf_inap_linkedid = -1;              /* INTEGER */
static int hf_inap_absent = -1;                /* NULL */
static int hf_inap_invokeId = -1;              /* InvokeId */
static int hf_inap_invoke = -1;                /* InvokePDU */
static int hf_inap_ReturnError = -1;           /* InvokePDU */
static int hf_inap_returnResult = -1;          /* InvokePDU */
static int hf_inap_returnResult_result = -1;
static int hf_inap_getPassword = -1;  
static int hf_inap_currentPassword = -1;  
static int hf_inap_genproblem = -1;
#include "packet-inap-hf.c"

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
#include "packet-inap-ett.c"

static int  dissect_invokeCmd(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);

#include "packet-inap-fn.c"


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



static guint32 opcode=0;

static int
dissect_inap_Opcode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_index, &opcode);

  if (check_col(pinfo->cinfo, COL_INFO)){
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(opcode, inap_opr_code_strings, "Unknown Inap (%u)"));
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

static int dissect_invokeData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  switch(opcode){
  case 0: /*InitialDP*/
    offset=dissect_inap_InitialDP(FALSE, tvb, offset, pinfo, tree, hf_inap_InitialDP_PDU);
    break;
  case 1: /*1 OriginationAttemptAuthorized */
    offset=dissect_inap_OriginationAttemptAuthorizedArg(FALSE, tvb, offset, pinfo, tree, hf_inap_OriginationAttemptAuthorizedArg_PDU);
    break;
  case 2: /*2 CollectedInformation */
    offset=dissect_inap_CollectedInformationArg(FALSE, tvb, offset, pinfo, tree, hf_inap_CollectedInformationArg_PDU);
    break;
  case 3: /*3 AnalysedInformation */
    offset=dissect_inap_AnalysedInformationArg(FALSE, tvb, offset, pinfo, tree, hf_inap_AnalysedInformationArg_PDU);
    break;
  case 4: /*4 RouteSelectFailure */
    offset=dissect_inap_RouteSelectFailureArg(FALSE, tvb, offset, pinfo, tree, hf_inap_RouteSelectFailureArg_PDU);
    break;
  case 5: /*5 oCalledPartyBusy */
    offset=dissect_inap_OCalledPartyBusyArg(FALSE, tvb, offset, pinfo, tree, hf_inap_OCalledPartyBusyArg_PDU);
    break;	 
  case 6: /*6 oNoAnswer */
    offset=dissect_inap_ONoAnswer(FALSE, tvb, offset, pinfo, tree, hf_inap_ONoAnswer_PDU);
    break;
  case 7: /*7 oAnswer */
    offset=dissect_inap_OAnswerArg(FALSE, tvb, offset, pinfo, tree, hf_inap_OAnswerArg_PDU);
    break;
  case 8: /*8 oDisconnect */
    offset=dissect_inap_ODisconnectArg(FALSE, tvb, offset, pinfo, tree, hf_inap_ODisconnectArg_PDU);
    break;
  case 9: /*9 TermAttemptAuthorized */
    offset=dissect_inap_TermAttemptAuthorizedArg(FALSE, tvb, offset, pinfo, tree, hf_inap_TermAttemptAuthorizedArg_PDU);
    break;
  case 10: /*10 tBusy */
    offset=dissect_inap_TBusyArg(FALSE, tvb, offset, pinfo, tree, hf_inap_TBusyArg_PDU);
    break;
  case 11: /*11 tNoAnswer */
    offset=dissect_inap_TNoAnswerArg(FALSE, tvb, offset, pinfo, tree, hf_inap_TNoAnswerArg_PDU);
    break;
  case 12: /*12 tAnswer */
    offset=dissect_inap_TAnswerArg(FALSE, tvb, offset, pinfo, tree, hf_inap_TAnswerArg_PDU);
    break;
  case 13: /*13 tDisconnect */
    offset=dissect_inap_TDisconnectArg(FALSE, tvb, offset, pinfo, tree, hf_inap_TDisconnectArg_PDU);
    break;
  case 14: /*14 oMidCall */
    offset=dissect_inap_MidCallArg(FALSE, tvb, offset, pinfo, tree, hf_inap_MidCallArg_PDU);
    break;
  case 15: /*15 tMidCall */
    offset=dissect_inap_MidCallArg(FALSE, tvb, offset, pinfo, tree, hf_inap_MidCallArg_PDU);
    break;
  case  16: /*AssistRequestInstructions*/
    offset=dissect_inap_AssistRequestInstructionsArg(FALSE, tvb, offset, pinfo, tree, hf_inap_AssistRequestInstructionsArg_PDU);
    break;
  case  17: /*EstablishTemporaryConnection*/
    offset=dissect_inap_EstablishTemporaryConnectionArg(FALSE, tvb, offset, pinfo, tree, hf_inap_EstablishTemporaryConnectionArg_PDU);
    break;
  case  18: /*DisconnectForwardConnections*/
    proto_tree_add_text(tree, tvb, offset, -1, "Disconnect Forward Connection");
    break;
  case  19: /*ConnectToResource*/
    offset=dissect_inap_ConnectToResourceArg(FALSE, tvb, offset, pinfo, tree, hf_inap_ConnectToResourceArg_PDU);
    break;
  case  20: /*Connect*/
    offset=dissect_inap_ConnectArg(FALSE, tvb, offset, pinfo, tree,hf_inap_ConnectArg_PDU);
    break;	
  case  21: /* 21 HoldCallInNetwork */
    offset=dissect_inap_HoldCallInNetworkArg(FALSE, tvb, offset, pinfo, tree,hf_inap_HoldCallInNetworkArg_PDU);
    break;

   case 22: /*ReleaseCall*/
    offset=dissect_inap_ReleaseCallArg(FALSE, tvb, offset, pinfo, tree,hf_inap_ReleaseCallArg_PDU);
    break;
    case 23: /*InitialDP*/
    offset=dissect_inap_RequestReportBCSMEventArg(FALSE, tvb, offset, pinfo, tree, hf_inap_RequestReportBCSMEventArg_PDU);
    break;
  case  24: /*EventReportBCSM*/
    offset=dissect_inap_EventReportBCSMArg(FALSE, tvb, offset, pinfo, tree, hf_inap_EventReportBCSMArg_PDU);
    break;
  case  25: /*25, "RequestNotificationChargingEvent */
    offset=dissect_inap_RequestNotificationChargingEvent(FALSE, tvb, offset, pinfo, tree, hf_inap_RequestNotificationChargingEvent_PDU);
    break;
  case  26: /*26, "EventNotificationCharging */
    offset=dissect_inap_EventNotificationChargingArg(FALSE, tvb, offset, pinfo, tree, hf_inap_EventNotificationChargingArg_PDU);
    break;
  case  27: /*27, "CollectInformation */
    offset=dissect_inap_CollectInformationArg(FALSE, tvb, offset, pinfo, tree, hf_inap_CollectInformationArg_PDU);
    break;
  case  28: /*28, "AnalyseInformation */
    offset=dissect_inap_AnalyseInformationArg(FALSE, tvb, offset, pinfo, tree, hf_inap_AnalyseInformationArg_PDU);
    break;
  case  29: /*29, "SelectRoute */
    offset=dissect_inap_SelectRouteArg(FALSE, tvb, offset, pinfo, tree, hf_inap_SelectRouteArg_PDU);
    break;
  case  30: /*30, "SelectFacility */
    offset=dissect_inap_SelectFacilityArg(FALSE, tvb, offset, pinfo, tree, hf_inap_SelectFacilityArg_PDU);
    break;
	/*31, "Continue */
  case  32: /*32, InitiateCallAttempt*/
    offset=dissect_inap_InitiateCallAttemptArg(FALSE, tvb, offset, pinfo, tree, hf_inap_InitiateCallAttemptArg_PDU);
    break;
  case 33: /*ResetTimer*/
    offset=dissect_inap_ResetTimerArg(FALSE, tvb, offset, pinfo, tree, hf_inap_ResetTimerArg_PDU);
    break;
  case 34: /*FurnishChargingInformation*/
    offset=dissect_inap_FurnishChargingInformationArg(FALSE, tvb, offset, pinfo, tree, hf_inap_FurnishChargingInformationArg_PDU);
    break;
  case 35: /*35, ApplyCharging */
    offset=dissect_inap_ApplyChargingArg(FALSE, tvb, offset, pinfo, tree, hf_inap_ApplyChargingArg_PDU);
    break;	
  case 36: /*36, "ApplyChargingReport */
    offset=dissect_inap_ApplyChargingReportArg(FALSE, tvb, offset, pinfo, tree, hf_inap_ApplyChargingReportArg_PDU);
    break;
  case 37: /*37, "RequestCurrentStatusReport */
    offset=dissect_inap_RequestCurrentStatusReportArg(FALSE, tvb, offset, pinfo, tree, hf_inap_RequestCurrentStatusReportArg_PDU);
    break;
  case 38:/*38, "RequestEveryStatusChangeReport */
    offset=dissect_inap_RequestEveryStatusChangeReportArg(FALSE, tvb, offset, pinfo, tree, hf_inap_RequestEveryStatusChangeReportArg_PDU);
    break;
  case 39:/*39, "RequestFirstStatusMatchReport */
    offset=dissect_inap_RequestFirstStatusMatchReportArg(FALSE, tvb, offset, pinfo, tree, hf_inap_RequestFirstStatusMatchReportArg_PDU);
    break;
  case 40:/*40, "StatusReport */
    offset=dissect_inap_StatusReportArg(FALSE, tvb, offset, pinfo, tree, hf_inap_StatusReportArg_PDU);
    break;
  case 41:/*41, "CallGap */
    offset=dissect_inap_CallGapArg(FALSE, tvb, offset, pinfo, tree, hf_inap_CallGapArg_PDU);
    break;
  case 42:/*42, "ActivateServiceFiltering */
    offset=dissect_inap_ActivateServiceFilteringArg(FALSE, tvb, offset, pinfo, tree, hf_inap_ActivateServiceFilteringArg_PDU);
    break;
  case 43:/*43, "ServiceFilteringResponse */
    offset=dissect_inap_ServiceFilteringResponseArg(FALSE, tvb, offset, pinfo, tree, hf_inap_ServiceFilteringResponseArg_PDU);
    break;    
  case  44: /*CallInformationReport*/
    offset=dissect_inap_CallInformationReportArg(FALSE, tvb, offset, pinfo, tree, hf_inap_CallInformationReportArg_PDU);
    break;
  case  45: /*CallInformationRequest*/
    offset=dissect_inap_CallInformationRequestArg(FALSE, tvb, offset, pinfo, tree, hf_inap_CallInformationRequestArg_PDU);
    break;
  case 47: /*PlayAnnouncement*/
    offset=dissect_inap_PlayAnnouncementArg(FALSE, tvb, offset, pinfo, tree, hf_inap_PlayAnnouncementArg_PDU);
    break;
  case 48: /*PromptAndCollectUserInformation*/
    offset=dissect_inap_PromptAndCollectUserInformationArg(FALSE, tvb, offset, pinfo, tree, hf_inap_PromptAndCollectUserInformationArg_PDU);
    break;
  case 49: /* 49 SpecializedResourceReport */
    offset=dissect_inap_SpecializedResourceReportArg(FALSE, tvb, offset, pinfo, tree, hf_inap_SpecializedResourceReportArg_PDU);
    break;
  case  53: /*Cancel*/
    offset=dissect_inap_CancelArg(FALSE, tvb, offset, pinfo, tree, hf_inap_CancelArg_PDU);
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
static int dissect_returnResultData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  switch(opcode){
   case 37: /*requestCurrentStatusReport*/
    offset=dissect_inap_RequestCurrentStatusReportResultArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
   case 48: /*PromptAndCollectUserInformation*/
    offset=dissect_inap_ReceivedInformationArg(FALSE, tvb, offset, pinfo, tree, -1);
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
static int dissect_linkedID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
	return dissect_ber_integer(TRUE, pinfo, tree, tvb, offset, hf_inap_linkedid, NULL);
}


static const ber_sequence_t InvokePDU_sequence[] = {
  { BER_CLASS_UNI, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_invokeId },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_linkedID_impl },
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
/*
  if (check_col(pinfo->cinfo, COL_INFO)){
    col_prepend_fstr(pinfo->cinfo, COL_INFO, val_to_str(opcode, inap_opr_code_strings, "Unknown INAP (%u)"));
  }
*/
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
        { &hf_inap_linkedid,
      { "linkedid", "inap.linkedid",
        FT_INT32, BASE_DEC, NULL, 0,
        "LinkedId/linkedid", HFILL }},

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
     

#include "packet-inap-hfarr.c"
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
#include "packet-inap-ettarr.c"
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



