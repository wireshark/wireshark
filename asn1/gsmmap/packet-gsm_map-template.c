/* packet-gsm_map-template.c
 * Routines for GSM MobileApplication packet dissection
 * Copyright 2004, Anders Broman <anders.broman@ericsson.com>
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
 * References: ETSI TS 129 002
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/tap.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-gsm_map.h"

#define PNAME  "GSM_MobileAPplication"
#define PSNAME "GSM_MAP"
#define PFNAME "gsm_map"

/* Initialize the protocol and registered fields */
int proto_gsm_map = -1;
static int hf_gsm_map_invokeCmd = -1;             /* Opcode */
static int hf_gsm_map_invokeid = -1;              /* INTEGER */
static int hf_gsm_map_absent = -1;                /* NULL */
static int hf_gsm_map_invokeId = -1;              /* InvokeId */
static int hf_gsm_map_invoke = -1;                /* InvokePDU */
static int hf_gsm_map_returnResult = -1;                /* InvokePDU */
static int hf_gsm_map_returnResult_result = -1;
static int hf_gsm_map_getPassword = -1;  
static int hf_gsm_map_currentPassword = -1;  
#include "packet-gsm_map-hf.c"

/* Initialize the subtree pointers */
static gint ett_gsm_map = -1;
static gint ett_gsm_map_InvokeId = -1;
static gint ett_gsm_map_InvokePDU = -1;
static gint ett_gsm_map_ReturnResultPDU = -1;
static gint ett_gsm_map_ReturnResult_result = -1;
static gint ett_gsm_map_GSMMAPPDU = -1;
static int gsm_map_tap = -1;
#include "packet-gsm_map-ett.c"

static dissector_table_t	sms_dissector_table;	/* SMS TPDU */

static int  dissect_invokeCmd(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);

#include "packet-gsm_map-fn.c"

/* Stuff included from the "old" packet-gsm_map.c for tapping purposes */
static gchar *
my_match_strval(guint32 val, const value_string *vs, gint *idx)
{
    gint	i = 0;

    while (vs[i].strptr) {
	if (vs[i].value == val)
	{
	    *idx = i;
	    return(vs[i].strptr);
	}

	i++;
    }

    *idx = -1;
    return(NULL);
}
/* End includes from old" packet-gsm_map.c */

const value_string gsm_map_opr_code_strings[] = {
  {   2, "updateLocation" },
  {   3, "cancelLocation" },
  {   4, "provideRoamingNumber" },
  {   6, "resumeCallHandling" },
  {   7, "insertSubscriberData" },
  {   8, "deleteSubscriberData" },
  {   9, "sendParameters" },					/* map-ac infoRetrieval (14) version1 (1)*/
  {  10, "registerSS" },
  {  11, "eraseSS" },
  {  12, "activateSS" },
  {  13, "deactivateSS" },
  {  14, "interrogateSS" },
  {  17, "registerPassword" },
  {  18, "getPassword" },
  {  19, "processUnstructuredSS-Data" },		/* map-ac networkFunctionalSs (18) version1 (1) */
  {  22, "sendRoutingInfo" },
  {  23, "updateGprsLocation" },
  {  24, "sendRoutingInfoForGprs" },
  {  25, "failureReport" },
  {  26, "noteMsPresentForGprs" },
  {  28, "performHandover" },					/* map-ac handoverControl (11) version1 (1)*/
  {  29, "sendEndSignal" },
  {  30, "performSubsequentHandover" },			/* map-ac handoverControl (11) version1 (1) */
  {  31, "provideSIWFSNumber" },
  {  32, "sIWFSSignallingModify" },
  {  33, "processAccessSignalling" },
  {  34, "forwardAccessSignalling" },
  {  35, "noteInternalHandover" },				/* map-ac handoverControl (11) version1 (1) */
  {  37, "reset" },
  {  38, "forwardCheckSS-Indication" },
  {  39, "prepareGroupCall" },
  {  40, "sendGroupCallEndSignal" },
  {  41, "processGroupCallSignalling" },
  {  42, "forwardGroupCallSignalling" },
  {  43, "checkIMEI" },
  {  44, "mt-forwardSM" },
  {  45, "sendRoutingInfoForSM" },
  {  46, "mo-forwardSM" },
  {  47, "reportSM-DeliveryStatus" },
  {  48, "noteSubscriberPresent" },				/* map-ac mwdMngt (24) version1 (1) */
  {  49, "alertServiceCentreWithoutResult" },	/* map-ac shortMsgAlert (23) version1 (1) */
  {  50, "activateTraceMode" },
  {  51, "deactivateTraceMode" },
  {  52, "traceSubscriberActivity" },			/* map-ac handoverControl (11) version1 (1) */
  {  54, "beginSubscriberActivity" },			/* map-ac networkFunctionalSs (18) version1 (1) */
  {  55, "sendIdentification" },
  {  56, "sendAuthenticationInfo" },
  {  57, "restoreData" },
  {  58, "sendIMSI" },
  {  59, "processUnstructuredSS-Request" },
  {  60, "unstructuredSS-Request" },
  {  61, "unstructuredSS-Notify" },
  {  63, "informServiceCentre" },
  {  64, "alertServiceCentre" },
  {  66, "readyForSM" },
  {  67, "purgeMS" },
  {  68, "prepareHandover" },
  {  69, "prepareSubsequentHandover" },
  {  70, "provideSubscriberInfo" },
  {  71, "anyTimeInterrogation" },
  {  72, "ss-InvocationNotification" },
  {  73, "setReportingState" },
  {  74, "statusReport" },
  {  75, "remoteUserFree" },
  {  76, "registerCC-Entry" },
  {  77, "eraseCC-Entry" },
  {  83, "provideSubscriberLocation" },
  {  85, "sendRoutingInfoForLCS" },
  {  86, "subscriberLocationReport" },
  { 0, NULL }
};

static guint32 opcode=0;

static int
dissect_gsm_map_Opcode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_integer(pinfo, tree, tvb, offset, hf_index, &opcode);

  if (check_col(pinfo->cinfo, COL_INFO)){
    col_set_str(pinfo->cinfo, COL_INFO, val_to_str(opcode, gsm_map_opr_code_strings, "Unknown GSM-MAP (%u)"));
  }

  return offset;
}

static int dissect_invokeData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  switch(opcode){
  case  2: /*updateLocation*/
    offset=dissect_gsm_map_UpdateLocationArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case  3: /*cancelLocation*/
    offset=dissect_gsm_map_CancelLocationArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case  4: /*provideRoamingNumber*/
    offset=dissect_gsm_map_ProvideRoamingNumberArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case  6: /*resumeCallHandling*/
    offset=dissect_gsm_map_ResumeCallHandlingArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case  7: /*insertSubscriberData*/
    offset=dissect_gsm_map_InsertSubscriberDataArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case  8: /*deleteSubscriberData*/
    offset=dissect_gsm_map_DeleteSubscriberDataArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
	/* TODO find out why this isn't in the ASN1 file
  case  9: sendParameters
    offset=dissect_gsm_map_DeleteSubscriberDataArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
	*/
  case  10: /*registerSS*/
    offset=dissect_gsm_map_RegisterSS_Arg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case  11: /*eraseSS*/
    offset=dissect_gsm_map_Ss_ForBS(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 12: /*activateSS*/
    offset=dissect_gsm_map_Ss_ForBS(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 13: /*deactivateSS*/
    offset=dissect_gsm_map_Ss_ForBS(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 14: /*interrogateSS*/
    offset=dissect_gsm_map_Ss_ForBS(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 17: /*registerPassword*/
    offset=dissect_gsm_map_Ss_Code(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ss_Code);
    break;
  case 18: /*getPassword*/
    offset=dissect_gsm_map_GetPasswordArg(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_getPassword);
    break;
  case 22: /*sendRoutingInfo*/
    offset=dissect_gsm_map_SendRoutingInfoForGprsArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 23: /*updateGprsLocation*/
    offset=dissect_gsm_map_UpdateGprsLocationArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 24: /*sendRoutingInfoForGprs*/
    offset=dissect_gsm_map_SendRoutingInfoForGprsArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 25: /*failureReport*/
    offset=dissect_gsm_map_FailureReportArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 26: /*noteMsPresentForGprs*/
    offset=dissect_gsm_map_NoteMsPresentForGprsArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 29: /*sendEndSignal*/
    offset=dissect_gsm_map_Bss_APDU(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 31: /*provideSIWFSNumbe*/
    offset=dissect_gsm_map_ProvideSIWFSNumberArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 32: /*sIWFSSignallingModify*/
    offset=dissect_gsm_map_SIWFSSignallingModifyArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 33: /*processAccessSignalling*/
    offset=dissect_gsm_map_Bss_APDU(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 34: /*forwardAccessSignalling*/
    offset=dissect_gsm_map_Bss_APDU(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 37: /*reset*/
    offset=dissect_gsm_map_ResetArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 38: /*forwardCheckSS-Indication*/
    return offset;
    break;
  case 39: /*prepareGroupCall*/
    offset=dissect_gsm_map_PrepareGroupCallArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 40: /*sendGroupCallEndSignal*/
    dissect_gsm_map_SendGroupCallEndSignalArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 42: /*processGroupCallSignalling*/
    offset=dissect_gsm_map_ProcessGroupCallSignallingArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 43: /*checkIMEI*/
    offset=dissect_gsm_map_CheckIMEIArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 44: /*mt-forwardSM*/
    offset=dissect_gsm_map_CheckIMEIArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 45: /*sendRoutingInfoForSM*/
    offset=dissect_gsm_map_RoutingInfoForSMRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 46: /*mo-forwardSM*/
    offset=dissect_gsm_map_Mo_forwardSM_Arg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 47: /*reportSM-DeliveryStatus*/
    offset=dissect_gsm_map_ReportSM_DeliveryStatusArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 50: /*activateTraceMode*/
    offset=dissect_gsm_map_ActivateTraceModeArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 51: /*deactivateTraceMode*/
    offset=dissect_gsm_map_DeactivateTraceModeArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 55: /*sendIdentification*/
    offset=dissect_gsm_map_Tmsi(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 56: /*sendAuthenticationInfo*/
	offset=dissect_gsm_map_SendAuthenticationInfoArg(FALSE, tvb, offset, pinfo, tree, -1);
	break;
  case 57: /*restoreData*/
	offset=dissect_gsm_map_RestoreDataArg(FALSE, tvb, offset, pinfo, tree, -1);
	break;
  case 58: /*sendIMSI*/
	offset=dissect_gsm_map_Msisdn(FALSE, tvb, offset, pinfo, tree, -1);
	break;
  case 59: /*processUnstructuredSS-Request*/
    offset=dissect_gsm_map_Ussd_Arg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 60: /*unstructuredSS-Request*/
    offset=dissect_gsm_map_Ussd_Arg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 61: /*unstructuredSS-Notify*/
    offset=dissect_gsm_map_Ussd_Arg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 63: /*informServiceCentre*/
    offset=dissect_gsm_map_InformServiceCentreArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 64: /*alertServiceCentre*/
    offset=dissect_gsm_map_AlertServiceCentreArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 66: /*readyForSM*/
    offset=dissect_gsm_map_ReadyForSM_Arg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 67: /*purgeMS*/
    offset=dissect_gsm_map_PurgeMS_Arg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 68: /*prepareHandover*/
    offset=dissect_gsm_map_PrepareHO_Arg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 69: /*prepareSubsequentHandover*/
    offset=dissect_gsm_map_PrepareSubsequentHO_Arg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 70: /*provideSubscriberInfo*/
    offset=dissect_gsm_map_ProvideSubscriberInfoArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 71: /*anyTimeInterrogation*/
    offset=dissect_gsm_map_AnyTimeInterrogationArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 72: /*ss-InvocationNotificatio*/
    offset=dissect_gsm_map_Ss_InvocationNotificationArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 73: /*setReportingState*/
    offset=dissect_gsm_map_SetReportingStateArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 74: /*statusReport*/
    offset=dissect_gsm_map_StatusReportArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 75: /*remoteUserFree*/
    offset=dissect_gsm_map_RemoteUserFreeArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 76: /*registerCC-Entry*/
    offset=dissect_gsm_map_RegisterCC_EntryArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 77: /*eraseCC-Entry*/
    offset=dissect_gsm_map_EraseCC_EntryArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 83: /*provideSubscriberLocation*/
    offset=dissect_gsm_map_ProvideSubscriberLocation_Arg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 85: /*sendRoutingInfoForLCS*/
    offset=dissect_gsm_map_RoutingInfoForLCS_Arg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 86: /*subscriberLocationReport*/
    offset=dissect_gsm_map_SubscriberLocationReport_Arg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  default:
    proto_tree_add_text(tree, tvb, offset, -1, "Unknown invokeData blob");
  }
  return offset;
}


static int dissect_returnResultData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  switch(opcode){
  case  2: /*updateLocation*/
    offset=dissect_gsm_map_UpdateLocationRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case  3: /*cancelLocation*/
    offset=dissect_gsm_map_CancelLocationRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case  4: /*provideRoamingNumber*/
    offset=dissect_gsm_map_ProvideRoamingNumberRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case  6: /*resumeCallHandling*/
    offset=dissect_gsm_map_ResumeCallHandlingRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case  7: /*insertSubscriberData*/
    offset=dissect_gsm_map_InsertSubscriberDataRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case  8: /*deleteSubscriberData*/
    offset=dissect_gsm_map_DeleteSubscriberDataRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
	/* TODO find out why this isn't in the ASN1 file
  case  9: sendParameters
    offset=dissect_gsm_map_DeleteSubscriberDataArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
	*/
  case  10: /*registerSS*/
    offset=dissect_gsm_map_Ss_Info(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case  11: /*eraseSS*/
    offset=dissect_gsm_map_Ss_Info(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 12: /*activateSS*/
    offset=dissect_gsm_map_Ss_Info(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 13: /*deactivateSS*/
    offset=dissect_gsm_map_Ss_Info(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 14: /*interrogateSS*/
    offset=dissect_gsm_map_Ss_Info(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 17: /*registerPassword*/
    offset=dissect_gsm_map_NewPassword(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ss_Code);
    break;
  case 18: /*getPassword*/
    offset=dissect_gsm_map_CurrentPassword(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_currentPassword);
    break;
  case 22: /*sendRoutingInfo*/
    offset=dissect_gsm_map_SendRoutingInfoForGprsRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 23: /*updateGprsLocation*/
    offset=dissect_gsm_map_UpdateGprsLocationRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 24: /*sendRoutingInfoForGprs*/
    offset=dissect_gsm_map_SendRoutingInfoForGprsRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 25: /*failureReport*/
    offset=dissect_gsm_map_FailureReportRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 26: /*noteMsPresentForGprs*/
    offset=dissect_gsm_map_NoteMsPresentForGprsRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 29: /*sendEndSignal*/
	  /* Taken from MAP-MobileServiceOperations{ 0 identified-organization (4) etsi (0) mobileDomain 
	   * (0) gsm-Network (1) modules (3) map-MobileServiceOperations (5) version9 (9) }
	   */
    offset=dissect_gsm_map_ExtensionContainer(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 31: /*provideSIWFSNumbe*/
    offset=dissect_gsm_map_ProvideSIWFSNumberRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 32: /*provideSIWFSNumbe*/
    offset=dissect_gsm_map_SIWFSSignallingModifyRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 39: /*prepareGroupCall*/
    offset=dissect_gsm_map_PrepareGroupCallRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 40: /*sendGroupCallEndSignal*/
    dissect_gsm_map_SendGroupCallEndSignalRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 43: /*checkIMEI*/
    offset=dissect_gsm_map_EquipmentStatus(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 45: /*sendRoutingInfoForSM*/
    offset=dissect_gsm_map_RoutingInfoForSMRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 46: /*mo-forwardSM*/
    offset=dissect_gsm_map_Mo_forwardSM_Res(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 48: /*reportSM-DeliveryStatus*/
    offset=dissect_gsm_map_ReportSM_DeliveryStatusArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 50: /*activateTraceMode*/
    offset=dissect_gsm_map_ActivateTraceModeRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 51: /*deactivateTraceMode*/
    offset=dissect_gsm_map_DeactivateTraceModeRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 55: /*sendIdentification*/
    offset=dissect_gsm_map_SendIdentificationRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 57: /*restoreData*/
	offset=dissect_gsm_map_RestoreDataRes(FALSE, tvb, offset, pinfo, tree, -1);
	break;
  case 58: /*sendIMSI*/
	offset=dissect_gsm_map_Imsi(FALSE, tvb, offset, pinfo, tree, -1);
	break;
  case 59: /*unstructuredSS-Request*/
    offset=dissect_gsm_map_Ussd_Res(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 60: /*unstructuredSS-Request*/
    offset=dissect_gsm_map_Ussd_Res(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 61: /*unstructuredSS-Notify*/
    /* TRUE ? */
    proto_tree_add_text(tree, tvb, offset, -1, "Unknown returnResultData blob");
    break;
  case 66: /*readyForSM*/
    offset=dissect_gsm_map_ReadyForSM_Res(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 67: /*purgeMS*/
    offset=dissect_gsm_map_PurgeMS_Res(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 68: /*prepareHandover*/
    offset=dissect_gsm_map_PrepareHO_Res(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 69: /*prepareSubsequentHandover*/
     offset=dissect_gsm_map_Bss_APDU(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 70: /*provideSubscriberInfo*/
    offset=dissect_gsm_map_ProvideSubscriberInfoRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 71: /*anyTimeInterrogation*/
    offset=dissect_gsm_map_AnyTimeInterrogationRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 72: /*ss-InvocationNotificatio*/
    offset=dissect_gsm_map_Ss_InvocationNotificationRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 73: /*setReportingState*/
    offset=dissect_gsm_map_SetReportingStateRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 74: /*statusReport*/
    offset=dissect_gsm_map_StatusReportRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 75: /*remoteUserFree*/
    offset=dissect_gsm_map_RemoteUserFreeRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 76: /*registerCC-Entry*/
    offset=dissect_gsm_map_RegisterCC_EntryRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 77: /*eraseCC-Entry*/
    offset=dissect_gsm_map_EraseCC_EntryRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 83: /*provideSubscriberLocation*/
    offset=dissect_gsm_map_ProvideSubscriberLocation_Res(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 85: /*sendRoutingInfoForLCS*/
    offset=dissect_gsm_map_RoutingInfoForLCS_Arg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 86: /*subscriberLocationReport*/
    offset=dissect_gsm_map_SubscriberLocationReport_Res(FALSE, tvb, offset, pinfo, tree, -1);
    break;
 default:
    proto_tree_add_text(tree, tvb, offset, -1, "Unknown returnResultData blob");
  }
  return offset;
}

static int 
dissect_invokeCmd(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Opcode(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_invokeCmd);
}

static int dissect_invokeid(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ber_integer(pinfo, tree, tvb, offset, hf_gsm_map_invokeid, NULL);
}


static const value_string InvokeId_vals[] = {
  {   0, "invokeid" },
  {   1, "absent" },
  { 0, NULL }
};

static int dissect_absent(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_absent);
}


static const ber_choice InvokeId_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_invokeid },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_absent },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_InvokeId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              InvokeId_choice, hf_index, ett_gsm_map_InvokeId);

  return offset;
}
static int dissect_invokeId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_InvokeId(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_invokeId);
}

static const ber_sequence InvokePDU_sequence[] = {
  { BER_CLASS_UNI, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_invokeId },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_invokeCmd },
  { BER_CLASS_UNI, -1/*depends on Cmd*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_invokeData },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_InvokePDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                InvokePDU_sequence, hf_index, ett_gsm_map_InvokePDU);

  return offset;
}
static int dissect_invoke_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_InvokePDU(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_invoke);
}

static const ber_sequence ReturnResult_result_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_invokeCmd },
  { BER_CLASS_UNI, -1/*depends on Cmd*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_returnResultData },
  { 0, 0, 0, NULL }
};
static int
dissect_returnResult_result(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  offset = dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset,
                                ReturnResult_result_sequence, hf_gsm_map_returnResult_result, ett_gsm_map_ReturnResult_result);

  return offset;
}

static const ber_sequence ReturnResultPDU_sequence[] = {
  { BER_CLASS_UNI, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_invokeId },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_returnResult_result },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_returnResultPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                ReturnResultPDU_sequence, hf_index, ett_gsm_map_ReturnResultPDU);

  return offset;
}
static int dissect_returnResult_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_returnResultPDU(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_returnResult);
}

static const value_string GSMMAPPDU_vals[] = {
  {   1, "invoke" },
  {   2, "returnResult" },
  {   3, "returnError" },
  {   4, "reject" },
  { 0, NULL }
};

static const ber_choice GSMMAPPDU_choice[] = {
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_invoke_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_returnResult_impl },
#ifdef REMOVED
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_returnError_impl },
  {   4, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_reject_impl },
#endif
  { 0, 0, 0, 0, NULL }
};

static guint8 gsmmap_pdu_type = 0;
static guint8 gsm_map_pdu_size = 0;

static int
dissect_gsm_map_GSMMAPPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {

  gsmmap_pdu_type = tvb_get_guint8(tvb, offset)&0x0f;
  /* Get the length and add 2 */
  gsm_map_pdu_size = tvb_get_guint8(tvb, offset+1)+2;

  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              GSMMAPPDU_choice, hf_index, ett_gsm_map_GSMMAPPDU);

  if (check_col(pinfo->cinfo, COL_INFO)){
    col_prepend_fstr(pinfo->cinfo, COL_INFO, val_to_str(opcode, gsm_map_opr_code_strings, "Unknown GSM-MAP (%u)"));
  }

  return offset;
}




static void
dissect_gsm_map(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
    proto_item		*item=NULL;
    proto_tree		*tree=NULL;
	/* Used for gsm_map TAP */
	static			gsm_map_tap_rec_t tap_rec;
	gint			op_idx;
    gchar			*str = NULL;


    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "GSM MAP");
    }

    /* create display subtree for the protocol */
    if(parent_tree){
       item = proto_tree_add_item(parent_tree, proto_gsm_map, tvb, 0, -1, FALSE);
       tree = proto_item_add_subtree(item, ett_gsm_map);
    }

    dissect_gsm_map_GSMMAPPDU(FALSE, tvb, 0, pinfo, tree, -1);
	str = my_match_strval(opcode, gsm_map_opr_code_strings, &op_idx);

	tap_rec.invoke = FALSE;
	if ( gsmmap_pdu_type  == 1 )
		tap_rec.invoke = TRUE;
	tap_rec.opr_code_idx = op_idx;
	tap_rec.size = gsm_map_pdu_size;
	tap_queue_packet(gsm_map_tap, pinfo, &tap_rec);
	


}

static const value_string ssCode_vals[] = {
  { 0x00, "allSS - all SS" },
  { 0x10 ,"allLineIdentificationSS - all line identification SS" },
  { 0x11 ,"clip - calling line identification presentation" },
  { 0x12 ,"clir - calling line identification restriction" },
  { 0x13 ,"colp - connected line identification presentation" },
  { 0x14 ,"colr - connected line identification restriction" },
  { 0x15 ,"mci - malicious call identification" },
  { 0x18 ,"allNameIdentificationSS - all name indentification SS" },
  { 0x19 ,"cnap - calling name presentation" },
  { 0x20 ,"allForwardingSS - all forwarding SS" },
  { 0x21 ,"cfu - call forwarding unconditional" },
  { 0x28 ,"allCondForwardingSS - all conditional forwarding SS" },
  { 0x29 ,"cfb - call forwarding busy" },
  { 0x2a ,"cfnry - call forwarding on no reply" },
  { 0x2b ,"cfnrc - call forwarding on mobile subscriber not reachable" },
  { 0x24 ,"cd - call deflection" },
  { 0x30 ,"allCallOfferingSS - all call offering SS includes also all forwarding SS" },
  { 0x31 ,"ect - explicit call transfer" },
  { 0x32 ,"mah - mobile access hunting" },
  { 0x40 ,"allCallCompletionSS - all Call completion SS" },
  { 0x41 ,"cw - call waiting" },
  { 0x42 ,"hold - call hold" },
  { 0x43 ,"ccbs-A - completion of call to busy subscribers, originating side" },
  { 0x44 ,"ccbs-B - completion of call to busy subscribers, destination side" },
  { 0x45 ,"mc - multicall" },
  { 0x50 ,"allMultiPartySS - all multiparty SS" },
  { 0x51 ,"multiPTY - multiparty" },
  { 0x60 ,"allCommunityOfInterestSS - all community of interest SS" },
  { 0x61 ,"cug - closed user group" },
  { 0x70 ,"allChargingSS - all charging SS" },
  { 0x71 ,"aoci - advice of charge information" },
  { 0x72 ,"aocc - advice of charge charging" },
  { 0x80 ,"allAdditionalInfoTransferSS - all additional information transfer SS" },
  { 0x81 ,"uus1 - UUS1 user-to-user signalling" },
  { 0x82 ,"uus2 - UUS2 user-to-user signalling" },
  { 0x83 ,"uus3 - UUS3 user-to-user signalling" },
  { 0x90 ,"allCallRestrictionSS - all Callrestriction SS" },
  { 0x91 ,"barringOfOutgoingCalls" },
  { 0x92 ,"baoc - barring of all outgoing calls" },
  { 0x93 ,"boic - barring of outgoing international calls" },
  { 0x94 ,"boicExHC - barring of outgoing international calls except those directed to the home PLMN" },
  { 0x99 ,"barringOfIncomingCalls" },
  { 0x9a ,"baic - barring of all incoming calls" },
  { 0x9b ,"bicRoam - barring of incoming calls when roaming outside home PLMN Country" },
  { 0xf0 ,"allPLMN-specificSS" },
  { 0xa0 ,"allCallPrioritySS - all call priority SS" },
  { 0xa1 ,"emlpp - enhanced Multilevel Precedence Pre-emption (EMLPP) service" },
  { 0xb0 ,"allLCSPrivacyException - all LCS Privacy Exception Classes" },
  { 0xb1 ,"universal - allow location by any LCS client" },
  { 0xb2 ,"callrelated - allow location by any value added LCS client to which a call is established from the target MS" },
  { 0xb3 ,"callunrelated - allow location by designated external value added LCS clients" },
  { 0xb4 ,"plmnoperator - allow location by designated PLMN operator LCS clients" },
  { 0xc0 ,"allMOLR-SS - all Mobile Originating Location Request Classes" },
  { 0xc1 ,"basicSelfLocation - allow an MS to request its own location" },
  { 0xc2 ,"autonomousSelfLocation - allow an MS to perform self location without interaction with the PLMN for a predetermined period of time" },
  { 0xc3 ,"transferToThirdParty - allow an MS to request transfer of its location to another LCS client" },

  { 0xf1 ,"plmn-specificSS-1" },
  { 0xf2 ,"plmn-specificSS-2" },
  { 0xf3 ,"plmn-specificSS-3" },
  { 0xf4 ,"plmn-specificSS-4" },
  { 0xf5 ,"plmn-specificSS-5" },
  { 0xf6 ,"plmn-specificSS-6" },
  { 0xf7 ,"plmn-specificSS-7" },
  { 0xf8 ,"plmn-specificSS-8" },
  { 0xf9 ,"plmn-specificSS-9" },
  { 0xfa ,"plmn-specificSS-a" },
  { 0xfb ,"plmn-specificSS-b" },
  { 0xfc ,"plmn-specificSS-c" },
  { 0xfd ,"plmn-specificSS-d" },
  { 0xfe ,"plmn-specificSS-e" },
  { 0xff ,"plmn-specificSS-f" },
  { 0, NULL }
};

static const value_string Teleservice_vals[] = {
{0x00, "allTeleservices" },
{0x10, "allSpeechTransmissionServices" },
{0x11, "telephony" },
{0x12, "emergencyCalls" },
{0x20, "allShortMessageServices" },
{0x21, "shortMessageMT-PP" },
{0x22, "shortMessageMO-PP" },
{0x60, "allFacsimileTransmissionServices" },
{0x61, "facsimileGroup3AndAlterSpeech" },
{0x62, "automaticFacsimileGroup3" },
{0x63, "facsimileGroup4" },

{0x70, "allDataTeleservices" },
{0x80, "allTeleservices-ExeptSMS" },

{0x90, "allVoiceGroupCallServices" },
{0x91, "voiceGroupCall" },
{0x92, "voiceBroadcastCall" },

{0xd0, "allPLMN-specificTS" },
{0xd1, "plmn-specificTS-1" },
{0xd2, "plmn-specificTS-2" },
{0xd3, "plmn-specificTS-3" },
{0xd4, "plmn-specificTS-4" },
{0xd5, "plmn-specificTS-5" },
{0xd6, "plmn-specificTS-6" },
{0xd7, "plmn-specificTS-7" },
{0xd8, "plmn-specificTS-8" },
{0xd9, "plmn-specificTS-9" },
{0xda, "plmn-specificTS-A" },
{0xdb, "plmn-specificTS-B" },
{0xdc, "plmn-specificTS-C" },
{0xdd, "plmn-specificTS-D" },
{0xde, "plmn-specificTS-E" },
{0xdf, "plmn-specificTS-F" },
  { 0, NULL }
};

/*--- proto_register_gsm_map -------------------------------------------*/
void proto_register_gsm_map(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_gsm_map_invokeCmd,
      { "invokeCmd", "gsm_map.invokeCmd",
        FT_UINT32, BASE_DEC, VALS(gsm_map_opr_code_strings), 0,
        "InvokePDU/invokeCmd", HFILL }},
    { &hf_gsm_map_invokeid,
      { "invokeid", "gsm_map.invokeid",
        FT_INT32, BASE_DEC, NULL, 0,
        "InvokeId/invokeid", HFILL }},
    { &hf_gsm_map_absent,
      { "absent", "gsm_map.absent",
        FT_NONE, BASE_NONE, NULL, 0,
        "InvokeId/absent", HFILL }},
    { &hf_gsm_map_invokeId,
      { "invokeId", "gsm_map.invokeId",
        FT_UINT32, BASE_DEC, VALS(InvokeId_vals), 0,
        "InvokePDU/invokeId", HFILL }},
    { &hf_gsm_map_currentPassword,
      { "currentPassword", "gsm_map.currentPassword",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_invoke,
      { "invoke", "gsm_map.invoke",
        FT_NONE, BASE_NONE, NULL, 0,
        "GSMMAPPDU/invoke", HFILL }},
    { &hf_gsm_map_returnResult,
      { "returnResult", "gsm_map.returnResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "GSMMAPPDU/returnResult", HFILL }},
    { &hf_gsm_map_getPassword,
      { "Password", "gsm_map.password",
        FT_UINT8, BASE_DEC, VALS(GetPasswordArg_vals), 0,
        "Password", HFILL }},


#include "packet-gsm_map-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_gsm_map,
    &ett_gsm_map_InvokeId,
    &ett_gsm_map_InvokePDU,
    &ett_gsm_map_ReturnResultPDU,
    &ett_gsm_map_ReturnResult_result,
    &ett_gsm_map_GSMMAPPDU,
#include "packet-gsm_map-ettarr.c"
  };

  /* Register protocol */
  proto_gsm_map = proto_register_protocol(PNAME, PSNAME, PFNAME);
/*XXX  register_dissector("gsm_map", dissect_gsm_map, proto_gsm_map);*/
  /* Register fields and subtrees */
  proto_register_field_array(proto_gsm_map, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  sms_dissector_table =
	register_dissector_table("gsm_map.sms_tpdu", "GSM SMS TPDU",
	FT_UINT8, BASE_DEC);

  gsm_map_tap = register_tap("gsm_map");

}


/*--- proto_reg_handoff_gsm_map ---------------------------------------*/
void proto_reg_handoff_gsm_map(void) {
    dissector_handle_t	map_handle;

    map_handle = create_dissector_handle(dissect_gsm_map, proto_gsm_map);
    dissector_add("tcap.itu_ssn", 6, map_handle);
    dissector_add("tcap.itu_ssn", 7, map_handle);
    dissector_add("tcap.itu_ssn", 8, map_handle);
    dissector_add("tcap.itu_ssn", 9, map_handle);
}
