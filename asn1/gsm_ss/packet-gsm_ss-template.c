/* packet-gsm_ss-template.c
 * Routines for GSM Supplementary Services dissection
 * Copyright 2005, Anders Broman <anders.broman@ericsson.com>
 * Based on the dissector by:
 * Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 *
 * Title		3GPP			Other
 *
 *   Reference [1]
 *   Mobile radio Layer 3 supplementary service specification;
 *   Formats and coding
 *   (3GPP TS 24.080 version )
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
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/tap.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-gsm_ss.h"
#include "packet-gsm_map.h"

#define PNAME  "GSM_SS"
#define PSNAME "GSM_SS"
#define PFNAME "gsm_ss"

const value_string gsm_ss_err_code_strings[] = {
    { 1,	"Unknown Subscriber" },
    { 3,	"Unknown MSC" },
    { 5,	"Unidentified Subscriber" },
    { 6,	"Absent Subscriber SM" },
    { 7,	"Unknown Equipment" },
    { 8,	"Roaming Not Allowed" },
    { 9,	"Illegal Subscriber" },
    { 10,	"Bearer Service Not Provisioned" },
    { 11,	"Teleservice Not Provisioned" },
    { 12,	"Illegal Equipment" },
    { 13,	"Call Barred" },
    { 14,	"Forwarding Violation" },
    { 15,	"CUG Reject" },
    { 16,	"Illegal SS Operation" },
    { 17,	"SS Error Status" },
    { 18,	"SS Not Available" },
    { 19,	"SS Subscription Violation" },
    { 20,	"SS Incompatibility" },
    { 21,	"Facility Not Supported" },
    { 25,	"No Handover Number Available" },
    { 26,	"Subsequent Handover Failure" },
    { 27,	"Absent Subscriber" },
    { 28,	"Incompatible Terminal" },
    { 29,	"Short Term Denial" },
    { 30,	"Long Term Denial" },
    { 31,	"Subscriber Busy For MT SMS" },
    { 32,	"SM Delivery Failure" },
    { 33,	"Message Waiting List Full" },
    { 34,	"System Failure" },
    { 35,	"Data Missing" },
    { 36,	"Unexpected Data Value" },
    { 37,	"PW Registration Failure" },
    { 38,	"Negative PW Check" },
    { 39,	"No Roaming Number Available" },
    { 40,	"Tracing Buffer Full" },
    { 42,	"Target Cell Outside Group Call Area" },
    { 43,	"Number Of PW Attempts Violation" },
    { 44,	"Number Changed" },
    { 45,	"Busy Subscriber" },
    { 46,	"No Subscriber Reply" },
    { 47,	"Forwarding Failed" },
    { 48,	"OR Not Allowed" },
    { 49,	"ATI Not Allowed" },
    { 50,	"No Group Call Number Available" },
    { 51,	"Resource Limitation" },
    { 52,	"Unauthorized Requesting Network" },
    { 53,	"Unauthorized LCS Client" },
    { 54,	"Position Method Failure" },
    { 58,	"Unknown Or Unreachable LCS Client" },
    { 59,	"MM Event Not Supported" },
    { 60,	"ATSI Not Allowed" },
    { 61,	"ATM Not Allowed" },
    { 62,	"Information Not Available" },
    { 71,	"Unknown Alphabet" },
    { 72,	"USSD Busy" },
    { 120,	"Nbr Sb Exceeded" },
    { 121,	"Rejected By User" },
    { 122,	"Rejected By Network" },
    { 123,	"Deflection To Served Subscriber" },
    { 124,	"Special Service Code" },
    { 125,	"Invalid Deflected To Number" },
    { 126,	"Max Number Of MPTY Participants Exceeded" },
    { 127,	"Resources Not Available" },
    { 0, NULL }
};

const value_string gsm_ss_opr_code_strings[] = {
    { 10,	"Register SS" },
    { 11,	"Erase SS" },
    { 12,	"Activate SS" },
    { 13,	"Deactivate SS" },
    { 14,	"Interrogate SS" },
    { 16,	"Notify SS" },
    { 17,	"Register Password" },
    { 18,	"Get Password" },
    { 19,	"Process Unstructured SS Data" },
    { 38,	"Forward Check SS Indication" },
    { 59,	"Process Unstructured SS Request" },
    { 60,	"Unstructured SS Request" },
    { 61,	"Unstructured SS Notify" },
    { 77,	"Erase CC Entry" },
    { 112,	"lcs-AreaEventCancellation" },
    { 113,	"lcs-AreaEventReport" },
    { 114,	"LCS-AreaEventRequest" },
    { 115,	"LCS MOLR" },
    { 116,	"LCS Location Notification" },
    { 117,	"Call Deflection" },
    { 118,	"User User Service" },
    { 119,	"Access Register CC Entry" },
    { 120,	"Forward CUG Info" },
    { 121,	"Split MPTY" },
    { 122,	"Retrieve MPTY" },
    { 123,	"Hold MPTY" },
    { 124,	"Build MPTY" },
    { 125,	"Forward Charge Advice" },
    { 126,	"Explicit CT" },

    { 0, NULL }
};

/* Initialize the protocol and registered fields */
int proto_gsm_ss = -1;

static int hf_gsm_ss_getPassword = -1;
static int hf_gsm_ss_currentPassword = -1;
static int hf_gsm_ss_SS_Code = -1;
#include "packet-gsm_ss-hf.c"

/* Initialize the subtree pointers */
#include "packet-gsm_ss-ett.c"

static dissector_table_t	sms_dissector_table;	/* SMS TPDU */

#include "packet-gsm_ss-fn.c"


int
gsm_ss_dissect(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset,guint32 opcode, gint comp_type_tag)
{
	switch (comp_type_tag){
		case 1: /* invoke */
			switch (opcode){
				case 10: /* Register SS -- imports operations from MAP-SupplementaryServiceOperations*/
					offset=dissect_gsm_map_RegisterSS_Arg(FALSE, tvb, offset, pinfo, tree, -1);
					break;
				case 11: /* Erase SS -- imports operations from MAP-SupplementaryServiceOperations*/
					offset=dissect_gsm_map_SS_ForBS_Code(FALSE, tvb, offset, pinfo, tree, -1);
					break;
				case 12: /* Activate SS -- imports operations from MAP-SupplementaryServiceOperations*/
					offset=dissect_gsm_map_SS_ForBS_Code(FALSE, tvb, offset, pinfo, tree, -1);
					break;
				case 13: /*Deactivate SS -- imports operations from MAP-SupplementaryServiceOperations*/
					offset=dissect_gsm_map_SS_ForBS_Code(FALSE, tvb, offset, pinfo, tree, -1);
					break;
				case 14: /*Interrogate SS -- imports operations from MAP-SupplementaryServiceOperations*/
					offset=dissect_gsm_map_SS_ForBS_Code(FALSE, tvb, offset, pinfo, tree, -1);
					break;
				case 16: /*Notify SS */
					offset = dissect_notifySS(pinfo, tree, tvb, offset);
					break;
				case 17: /*Register Password -- imports operations from MAP-SupplementaryServiceOperations*/
					offset=dissect_gsm_map_SS_Code(FALSE, tvb, offset, pinfo, tree, -1);
					break;
				case 18: /*Get Password -- imports operations from MAP-SupplementaryServiceOperations*/
					 offset=dissect_gsm_map_GetPasswordArg(FALSE, tvb, offset, pinfo, tree, hf_gsm_ss_getPassword);
					break;
				case 19: /*Process Unstructured SS Data */
					offset = dissect_processUnstructuredSS_Data(pinfo, tree, tvb, offset);
					break;
				case 38: /*Forward Check SS Indication -- imports operation from MAP-MobileServiceOperations*/
					break;
				case 59: /*Process Unstructured SS Request -- imports operations from MAP-SupplementaryServiceOperations*/
					 offset=dissect_gsm_map_Ussd_Arg(FALSE, tvb, offset, pinfo, tree, -1);
					break;
				case 60: /*Unstructured SS Request -- imports operations from MAP-SupplementaryServiceOperations*/
					offset=dissect_gsm_map_Ussd_Arg(FALSE, tvb, offset, pinfo, tree, -1);
					break;
				case 61: /*Unstructured SS Notify -- imports operations from MAP-SupplementaryServiceOperations*/
					offset=dissect_gsm_map_Ussd_Arg(FALSE, tvb, offset, pinfo, tree, -1);
					break;
				case 77: /*Erase CC Entry -- imports operations from MAP-SupplementaryServiceOperations*/
					offset=dissect_gsm_map_EraseCC_EntryArg(FALSE, tvb, offset, pinfo, tree, -1);
					break;
				case 112: /*lcs-AreaEventCancellation */
					offset = dissect_lcs_AreaEventCancellation(pinfo, tree, tvb, offset);
					break;
				case 113: /*lcs-AreaEventReport */
					offset = dissect_lcs_AreaEventReport(pinfo, tree, tvb, offset);
					break;
				case 114: /*LCS-AreaEventRequest */
					offset = dissect_lcs_AreaEventRequest(pinfo, tree, tvb, offset);
					break;
				case 115: /*LCS MOLR */
					offset = dissect_lcs_MOLR(pinfo, tree, tvb, offset);
					break;
				case 116: /*LCS Location Notification */
					offset = dissect_lcs_LocationNotification(pinfo, tree, tvb,offset);
					break;
				case 117: /*Call Deflection */
					offset = dissect_callDeflection(pinfo, tree, tvb,offset);
					break;
				case 118: /*User User Service */
					offset = dissect_gsm_ss_UserUserServiceArg(FALSE, tvb, offset, pinfo, tree, -1);
					break;
				case 119: /* Access Register CC Entry */
					offset = dissect_gsm_ss_AccessRegisterCCEntryArg(FALSE, tvb, offset, pinfo, tree, -1);
					break;
				case 120: /*Forward CUG Info */
					offset = dissect_forwardCUG_Info(pinfo, tree, tvb,offset);
					break;
				case 121: /*Split MPTY */
					break;
				case 122: /*Retrieve MPTY */
					break;
				case 123: /*Hold MPTY */
					break;
				case 124: /*Build MPTY */
					break;
				case 125: /*Forward Charge Advice */
					dissect_forwardChargeAdvice(pinfo, tree, tvb,offset);
					break;
				case 126: /*Explicit CT */
					break;
				default:
					break;
				}
			break;
		case 2: /* returnResultLast */
			switch (opcode){
				case  10: /*registerSS*/
				    offset=dissect_gsm_map_SS_Info(FALSE, tvb, offset, pinfo, tree, -1);
				    break;
				case  11: /*eraseSS*/
					offset=dissect_gsm_map_SS_Info(FALSE, tvb, offset, pinfo, tree, -1);
					break;
				case 12: /*activateSS*/
					offset=dissect_gsm_map_SS_Info(FALSE, tvb, offset, pinfo, tree, -1);
					break;
				case 13: /*deactivateSS*/
					offset=dissect_gsm_map_SS_Info(FALSE, tvb, offset, pinfo, tree, -1);
					break;
				case 14: /*interrogateSS*/
					offset=dissect_gsm_map_InterrogateSS_Res(FALSE, tvb, offset, pinfo, tree, -1);
					break;
				case 16: /*Notify SS */
					break;
				case 17: /*Register Password -- imports operations from MAP-SupplementaryServiceOperations*/
				    offset=dissect_gsm_map_NewPassword(FALSE, tvb, offset, pinfo, tree, hf_gsm_ss_SS_Code);
					break;
				case 18: /*Get Password -- imports operations from MAP-SupplementaryServiceOperations*/
					offset=dissect_gsm_map_CurrentPassword(FALSE, tvb, offset, pinfo, tree, hf_gsm_ss_currentPassword);
					break;
				case 19: /*Process Unstructured SS Data */
					offset=dissect_gsm_ss_SS_UserData(FALSE, tvb, offset, pinfo, tree, -1);
					break;
				case 38: /*Forward Check SS Indication -- imports operation from MAP-MobileServiceOperations*/
					break;
				case 59: /*Process Unstructured SS Request -- imports operations from MAP-SupplementaryServiceOperations*/
					 offset=dissect_gsm_map_Ussd_Res(FALSE, tvb, offset, pinfo, tree, -1);
					break;
				case 60: /*Unstructured SS Request -- imports operations from MAP-SupplementaryServiceOperations*/
					offset=dissect_gsm_map_Ussd_Res(FALSE, tvb, offset, pinfo, tree, -1);
					break;
				case 61: /*Unstructured SS Notify -- imports operations from MAP-SupplementaryServiceOperations*/
					offset=dissect_gsm_map_Ussd_Res(FALSE, tvb, offset, pinfo, tree, -1);
					break;
				case 77: /*Erase CC Entry -- imports operations from MAP-SupplementaryServiceOperations*/
					offset=dissect_gsm_map_EraseCC_EntryRes(FALSE, tvb, offset, pinfo, tree, -1);
					break;
				case 112: /*lcs-AreaEventCancellation */
					break;
				case 113: /*lcs-AreaEventReport */
					break;
				case 114: /*LCS-AreaEventRequest */
					break;
				case 115: /*LCS MOLR */
					offset=dissect_gsm_ss_LCS_MOLRRes(FALSE, tvb, offset, pinfo, tree, -1);
					break;
				case 116: /*LCS Location Notification */
					offset=dissect_gsm_ss_LocationNotificationRes(FALSE, tvb, offset, pinfo, tree, -1);
					break;
				case 117: /*Call Deflection */
					break;
				case 118: /*User User Service */
					break;
				case 119: /* Access Register CC Entry */
				    offset=dissect_gsm_map_RegisterCC_EntryRes(FALSE, tvb, offset, pinfo, tree, -1);
					break;
				case 120: /*Forward CUG Info */
					break;
				case 121: /*Split MPTY */
					break;
				case 122: /*Retrieve MPTY */
					break;
				case 123: /*Hold MPTY */
					break;
				case 124: /*Build MPTY */
					break;
				case 125: /*Forward Charge Advice */
					break;
				case 126: /*Explicit CT */
					break;
				default:
					break;
			}
			break;
		case 3: /* returnError */
			break;
		case 4: /* reject */
			break;
		default:
			break;
	}
	return offset;
}

static void
dissect_gsm_ss(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

}

/*--- proto_reg_handoff_gsm_ss ---------------------------------------
This proto is called directly from packet-gsm_a and needs to know component type */
void proto_reg_handoff_gsm_ss(void) {
    dissector_handle_t	gsm_ss_handle;

    gsm_ss_handle = create_dissector_handle(dissect_gsm_ss, proto_gsm_ss);


}

/*--- proto_register_gsm_ss -------------------------------------------*/
void proto_register_gsm_ss(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_gsm_ss_getPassword,
      { "Password", "gsm_ss.password",
        FT_UINT8, BASE_DEC, VALS(gsm_map_GetPasswordArg_vals), 0,
        "Password", HFILL }},
    { &hf_gsm_ss_currentPassword,
      { "currentPassword", "gsm_ss.currentPassword",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_ss_SS_Code,
      { "ss-Code", "gsm_ss.ss_Code",
        FT_UINT8, BASE_DEC, VALS(ssCode_vals), 0,
        "", HFILL }},

#include "packet-gsm_ss-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
#include "packet-gsm_ss-ettarr.c"
  };

  /* Register protocol */
  proto_gsm_ss = proto_register_protocol(PNAME, PSNAME, PFNAME); 
/*XXX  register_dissector("gsm_ss", dissect_gsm_ss, proto_gsm_ss);*/
  /* Register fields and subtrees */
  proto_register_field_array(proto_gsm_ss, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));


}


