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
#include <epan/oids.h>
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

#include "packet-inap-hf.c"

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
#include "packet-inap-ett.c"

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
	{23, "RequestReportBCSMEvent"},
	{24, "EventReportBCSM"},
	{25, "RequestNotificationChargingEvent"},
	{26, "EventNotificationCharging"},
	{27, "CollectInformation"},
	{28, "AnalyseInformation"},
	{29, "SelectRoute"},
	{30, "SelectFacility"},
	{31, "Continue"},
	{32, "InitiateCallAttempt"},
	{33, "ResetTimer"},
	{34, "FurnishChargingInformation"},
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
	{47, "PlayAnnouncement"},
	{48, "PromptAndCollectUserInformation"},
	{49, "SpecializedResourceReport"},
	{53, "Cancel"},
	{54, "CancelStatusReportRequest"},
	{55, "ActivityTest"},
	{80, "FacilitySelectedAndAvailable"},
	{81, "OriginationAttempt"},
	{82, "TerminationAttempt"},
	{83, "OAbandon"},
	{84, "OSuspended"},
	{85, "TSuspended"},
	{87, "AuthorizeTermination"},
	{88, "ContinueWithArgument"},
	{89, "CreateCallSegmentAssociation "},
	{90, "DisconnectLeg"},
	{91, "MergeCallSegments"},
	{92, "MoveCallSegments"},
	{93, "MoveLeg"},
	{94, "Reconnect"},
	{95, "SplitLeg"},
	{96, "EntityReleased"},
	{97, "ManageTriggerData"},
	{98, "requestReportUTSI"},
	{99,"ReceivedInformation"}, /*???????*/
	{100, "sendSTUI"},
	{101, "reportUTSI"},
	{102, "sendFacilityInformation"},
	{103, "requestReportFacilityEvent"},
	{104, "eventReportFacility"},
	{107, "promptAndReceiveMessage"},
	{108, "scriptInformation"},
	{109, "scriptEvent"},
	{110, "scriptRun"},
	{111, "scriptClose"},
	{135, "createOrRemoveTriggerData"},
	{136, "setServiceProfile"},
	{139, "srfCallGap"},
	{145, "CallFiltering"},
	{146, "monitorRouteRequest"},
	{147, "monitorRouteReport"},
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

#include "packet-inap-fn.c"
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
    offset=dissect_inap_InitialDPArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 1: /*1 OriginationAttemptAuthorized */
    offset=dissect_inap_OriginationAttemptAuthorizedArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 2: /*2 CollectedInformation */
    offset=dissect_inap_CollectedInformationArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 3: /*3 AnalysedInformation */
    offset=dissect_inap_AnalysedInformationArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 4: /*4 RouteSelectFailure */
    offset=dissect_inap_RouteSelectFailureArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 5: /*5 oCalledPartyBusy */
    offset=dissect_inap_OCalledPartyBusyArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 6: /*6 oNoAnswer */
    offset=dissect_inap_ONoAnswerArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 7: /*7 oAnswer */
    offset=dissect_inap_OAnswerArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 8: /*8 oDisconnect */
    offset=dissect_inap_ODisconnectArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 9: /*9 TermAttemptAuthorized */
    offset=dissect_inap_TermAttemptAuthorizedArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 10: /*10 tBusy */
    offset=dissect_inap_TBusyArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 11: /*11 tNoAnswer */
    offset=dissect_inap_TNoAnswerArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 12: /*12 tAnswer */
    offset=dissect_inap_TAnswerArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 13: /*13 tDisconnect */
    offset=dissect_inap_TDisconnectArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 14: /*14 oMidCall */
    offset=dissect_inap_MidCallArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 15: /*15 tMidCall */
    offset=dissect_inap_MidCallArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  16: /*AssistRequestInstructions*/
    offset=dissect_inap_AssistRequestInstructionsArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  17: /*EstablishTemporaryConnection*/
    offset=dissect_inap_EstablishTemporaryConnectionArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  18: /*DisconnectForwardConnections*/
    proto_tree_add_text(tree, tvb, offset, -1, "Disconnect Forward Connection");
    break;
  case  19: /*ConnectToResource*/
    offset=dissect_inap_ConnectToResourceArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  20: /*Connect*/
    offset=dissect_inap_ConnectArg(FALSE, tvb, offset, actx, tree,-1);
    break;
  case  21: /* 21 HoldCallInNetwork */
    offset=dissect_inap_HoldCallInNetworkArg(FALSE, tvb, offset, actx, tree,-1);
    break;

   case 22: /*ReleaseCall*/
    offset=dissect_inap_ReleaseCallArg(FALSE, tvb, offset, actx, tree,-1);
    break;
    case 23: /*InitialDP*/
    offset=dissect_inap_RequestReportBCSMEventArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  24: /*EventReportBCSM*/
    offset=dissect_inap_EventReportBCSMArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  25: /*25, "RequestNotificationChargingEvent */
    offset=dissect_inap_RequestNotificationChargingEventArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  26: /*26, "EventNotificationCharging */
    offset=dissect_inap_EventNotificationChargingArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  27: /*27, "CollectInformation */
    offset=dissect_inap_CollectInformationArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  28: /*28, "AnalyseInformation */
    offset=dissect_inap_AnalyseInformationArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  29: /*29, "SelectRoute */
    offset=dissect_inap_SelectRouteArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  30: /*30, "SelectFacility */
    offset=dissect_inap_SelectFacilityArg(FALSE, tvb, offset, actx, tree, -1);
    break;
	/*31, "Continue */
  case  32: /*32, InitiateCallAttempt*/
    offset=dissect_inap_InitiateCallAttemptArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 33: /*ResetTimer*/
    offset=dissect_inap_ResetTimerArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 34: /*FurnishChargingInformation*/
    offset=dissect_inap_FurnishChargingInformationArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 35: /*35, ApplyCharging */
    offset=dissect_inap_ApplyChargingArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 36: /*36, "ApplyChargingReport */
    offset=dissect_inap_ApplyChargingReportArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 37: /*37, "RequestCurrentStatusReport */
    offset=dissect_inap_RequestCurrentStatusReportArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 38:/*38, "RequestEveryStatusChangeReport */
    offset=dissect_inap_RequestEveryStatusChangeReportArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 39:/*39, "RequestFirstStatusMatchReport */
    offset=dissect_inap_RequestFirstStatusMatchReportArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 40:/*40, "StatusReport */
    offset=dissect_inap_StatusReportArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 41:/*41, "CallGap */
    offset=dissect_inap_CallGapArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 42:/*42, "ActivateServiceFiltering */
    offset=dissect_inap_ActivateServiceFilteringArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 43:/*43, "ServiceFilteringResponse */
    offset=dissect_inap_ServiceFilteringResponseArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  44: /*CallInformationReport*/
    offset=dissect_inap_CallInformationReportArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  45: /*CallInformationRequest*/
    offset=dissect_inap_CallInformationRequestArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 47: /*PlayAnnouncement*/
    offset=dissect_inap_PlayAnnouncementArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 48: /*PromptAndCollectUserInformation*/
    offset=dissect_inap_PromptAndCollectUserInformationArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 49: /* 49 SpecializedResourceReport */
    offset=dissect_inap_SpecializedResourceReportArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  53: /*Cancel*/
    offset=dissect_inap_CancelArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  80: /*FacilitySelectedAndAvailable*/
	offset = dissect_inap_FacilitySelectedAndAvailableArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  81: /*OriginationAttempt*/
	offset = dissect_inap_OriginationAttemptArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  82: /*TerminationAttempt*/
	offset = dissect_inap_TerminationAttemptArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  83: /*OAbandon*/
	offset =dissect_inap_OAbandonArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  84: /*OSuspended*/
	offset = dissect_inap_OSuspendedArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  85: /*TSuspended*/
	offset = dissect_inap_TSuspendedArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  87: /*AuthorizeTermination*/
	offset = dissect_inap_AuthorizeTerminationArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  88: /*continueWithArgument*/
    offset=dissect_inap_ContinueWithArgumentArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  89: /*CreateCallSegmentAssociation */
	offset = dissect_inap_CreateCallSegmentAssociationArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  90: /*DisconnectLeg*/
	offset = dissect_inap_DisconnectLegArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  91: /*MergeCallSegments*/
	offset = dissect_inap_MergeCallSegmentsArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  92: /*MoveCallSegments*/
	offset = dissect_inap_MoveCallSegmentsArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  93: /*MoveLeg*/
	offset = dissect_inap_MoveLegArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  94: /*Reconnect*/
	offset = dissect_inap_ReconnectArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  95: /*SplitLeg*/
	offset = dissect_inap_SplitLegArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  96: /*EntityReleased*/
	offset = dissect_inap_EntityReleasedArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  97: /*ManageTriggerData*/
	offset = dissect_inap_ManageTriggerDataArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  98: /*requestReportUTSI*/
	offset = dissect_inap_RequestReportUTSIArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  99: /* ReceivedInformation - ???????*/
	offset = dissect_inap_ReceivedInformationArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  100: /*sendSTUI*/
	offset = dissect_inap_SendSTUIArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  101: /*reportUTSI*/
	offset = dissect_inap_ReportUTSIArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  102: /*sendFacilityInformation*/
	offset = dissect_inap_SendFacilityInformationArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  103: /*requestReportFacilityEvent*/
	offset = dissect_inap_RequestReportFacilityEventArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  104: /*eventReportFacility*/
	offset = dissect_inap_EventReportFacilityArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  107: /*promptAndReceiveMessage*/
	offset = dissect_inap_PromptAndReceiveMessageArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  108: /*scriptInformation*/
	offset = dissect_inap_ScriptInformationArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  109: /*scriptEvent*/
	offset = dissect_inap_ScriptEventArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  110: /*scriptRun*/
	offset = dissect_inap_ScriptRunArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  111: /*scriptClose*/
	offset = dissect_inap_ScriptCloseArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  135: /*createOrRemoveTriggerData*/
	offset = dissect_inap_CreateOrRemoveTriggerDataArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  139: /*srfCallGap*/
	offset = dissect_inap_SRFCallGapArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  136: /*setServiceProfile*/
	offset = dissect_inap_SetServiceProfileArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  145: /*CallFiltering*/
	offset = dissect_inap_CallFilteringArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  146: /*monitorRouteRequest*/
	offset = dissect_inap_MonitorRouteRequestArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  147: /*monitorRouteReport*/
	offset = dissect_inap_MonitorRouteReportArg(FALSE, tvb, offset, actx, tree, -1);
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
    dissect_INAP_Component_PDU(tvb, pinfo, tree);


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

    if (!inap_prefs_initialized) {
	    inap_prefs_initialized = TRUE;

	    inap_handle = create_dissector_handle(dissect_inap, proto_inap);
	    oid_add_from_string("Core-INAP-CS1-Codes","0.4.0.1.1.0.3.0");
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



#include "packet-inap-hfarr.c"
  };






  /* List of subtrees */
  static gint *ett[] = {
    &ett_inap,
	&ett_inapisup_parameter,
#include "packet-inap-ettarr.c"
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



