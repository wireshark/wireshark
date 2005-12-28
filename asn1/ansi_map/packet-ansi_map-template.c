/* packet-ansi_map.c
 * Routines for ANSI 41 Mobile Application Part (IS41 MAP) dissection
 * Specications from 3GPP2 (www.3gpp2.org)
 * Based on the dissector by :
 * Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 *
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
 * Credit to Tomas Kukosa for developing the asn2eth compiler.
 *
 * Title		3GPP2			Other
 *
 *   Cellular Radiotelecommunications Intersystem Operations
 *			3GPP2 N.S0005-0 v 1.0		ANSI/TIA/EIA-41-D 
 *
 *   Network Support for MDN-Based Message Centers
 *			3GPP2 N.S0024-0 v1.0	IS-841
 *
 *   Enhanced International Calling
 *			3GPP2 N.S0027		IS-875
 *
 *   ANSI-41-D Miscellaneous Enhancements Revision 0
 *			3GPP2 N.S0015		PN-3590 (ANSI-41-E)
 *
 *   Authentication Enhancements
 *			3GPP2 N.S0014-0 v1.0	IS-778
 *
 *	 DCCH (Clarification of Audit Order with Forced 
 *         Re-Registration in pre-TIA/EIA-136-A Implementation 
 *			3GPP2 A.S0017-B			IS-730
 *
 *   UIM
 *			3GPP2 N.S0003
 *
 *   WIN Phase 2
 *			3GPP2 N.S0004-0 v1.0	IS-848
 *
 */ 

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/tap.h>
#include <epan/emem.h>

#include <stdio.h>
#include <string.h>

#include "packet-ansi_map.h"
#include "packet-ansi_a.h"
#include "packet-gsm_map.h"
#include "packet-ber.h"
#include "packet-tcap.h"

#define PNAME  "ANSI Mobile Application Part"
#define PSNAME "ANSI MAP"
#define PFNAME "ansi_map"

static dissector_handle_t ansi_map_handle=NULL;

/* Initialize the protocol and registered fields */
static int ansi_map_tap = -1;
static int proto_ansi_map = -1;

static int hf_ansi_map_op_code_fam = -1;
static int hf_ansi_map_op_code = -1;
static int hf_ansi_map_type_of_digits = -1;
static int hf_ansi_map_na = -1;
static int hf_ansi_map_pi = -1;
static int hf_ansi_map_navail = -1;
static int hf_ansi_map_si = -1;
static int hf_ansi_map_digits_enc = -1;
static int hf_ansi_map_np = -1;
static int hf_ansi_map_nr_digits = -1;
static int hf_ansi_map_bcd_digits = -1;

#include "packet-ansi_map-hf.c"

/* Initialize the subtree pointers */
static gint ett_ansi_map = -1;
#include "packet-ansi_map-ett.c"

/* Global variables */
static dissector_handle_t data_handle=NULL;
static dissector_table_t is637_tele_id_dissector_table; /* IS-637 Teleservice ID */
static dissector_table_t is683_dissector_table; /* IS-683-A (OTA) */
static dissector_table_t is801_dissector_table; /* IS-801 (PLD) */
static packet_info *g_pinfo;
static proto_tree *g_tree;
static gint32 ansi_map_sms_tele_id = -1;
static gboolean is683_ota;
static gboolean is801_pld;
static gboolean ansi_map_is_invoke;
static guint32 OperationCode;


/* value strings */
const value_string ansi_map_opr_code_strings[] = {
    { 1,	"Handoff Measurement Request" },
    { 2,	"Facilities Directive" },
    { 3,	"Mobile On Channel" },
    { 4,	"Handoff Back" },
    { 5,	"Facilities Release" },
    { 6,	"Qualification Request" },
    { 7,	"Qualification Directive" },
    { 8,	"Blocking" },
    { 9,	"Unblocking" },
    { 10,	"Reset Circuit" },
    { 11,	"Trunk Test" },
    { 12,	"Trunk Test Disconnect" },
    { 13,	"Registration Notification" },
    { 14,	"Registration Cancellation" },
    { 15,	"Location Request" },
    { 16,	"Routing Request" },
    { 17,	"Feature Request" },
    { 18,	"Reserved 18 (Service Profile Request, IS-41-C)" },
    { 19,	"Reserved 19 (Service Profile Directive, IS-41-C)" },
    { 20,	"Unreliable Roamer Data Directive" },
    { 21,	"Reserved 21 (Call Data Request, IS-41-C)" },
    { 22,	"MS Inactive" },
    { 23,	"Transfer To Number Request" },
    { 24,	"Redirection Request" },
    { 25,	"Handoff To Third" },
    { 26,	"Flash Request" },
    { 27,	"Authentication Directive" },
    { 28,	"Authentication Request" },
    { 29,	"Base Station Challenge" },
    { 30,	"Authentication Failure Report" },
    { 31,	"Count Request" },
    { 32,	"Inter System Page" },
    { 33,	"Unsolicited Response" },
    { 34,	"Bulk Deregistration" },
    { 35,	"Handoff Measurement Request 2" },
    { 36,	"Facilities Directive 2" },
    { 37,	"Handoff Back 2" },
    { 38,	"Handoff To Third 2" },
    { 39,	"Authentication Directive Forward" },
    { 40,	"Authentication Status Report" },
    { 41,	"Reserved 41" },
    { 42,	"Information Directive" },
    { 43,	"Information Forward" },
    { 44,	"Inter System Answer" },
    { 45,	"Inter System Page 2" },
    { 46,	"Inter System Setup" },
    { 47,	"Origination Request" },
    { 48,	"Random Variable Request" },
    { 49,	"Redirection Directive" },
    { 50,	"Remote User Interaction Directive" },
    { 51,	"SMS Delivery Backward" },
    { 52,	"SMS Delivery Forward" },
    { 53,	"SMS Delivery Point to Point" },
    { 54,	"SMS Notification" },
    { 55,	"SMS Request" },
    { 56,	"OTASP Request" },
    { 57,	"Information Backward" },
    { 58,	"Change Facilities" },
    { 59,	"Change Service" },
    { 60,	"Parameter Request" },
    { 61,	"TMSI Directive" },
    { 62,	"Reserved 62" },
    { 63,	"Service Request" },
    { 64,	"Analyzed Information Request" },
    { 65,	"Connection Failure Report" },
    { 66,	"Connect Resource" },
    { 67,	"Disconnect Resource" },
    { 68,	"Facility Selected and Available" },
    { 69,	"Instruction Request" },
    { 70,	"Modify" },
    { 71,	"Reset Timer" },
    { 72,	"Search" },
    { 73,	"Seize Resource" },
    { 74,	"SRF Directive" },
    { 75,	"T Busy" },
    { 76,	"T NoAnswer" },
    { 77,	"Release" },
    { 78,	"SMS Delivery Point to Point Ack" },
    { 79,	"Message Directive" },
    { 80,	"Bulk Disconnection" },
    { 81,	"Call Control Directive" },
    { 82,	"O Answer" },
    { 83,	"O Disconnect" },
    { 84,	"Call Recovery Report" },
    { 85,	"T Answer" },
    { 86,	"T Disconnect" },
    { 87,	"Unreliable Call Data" },
    { 88,	"O CalledPartyBusy" },
    { 89,	"O NoAnswer" },
    { 90,	"Position Request" },
    { 91,	"Position Request Forward" },
    { 92,	"Call Termination Report" },
    { 93,	"Geo Position Directive" },
    { 94,	"Geo Position Request" },
    { 95,	"Inter System Position Request" },
    { 96,	"Inter System Position Request Forward" },
    { 97,	"ACG Directive" },
    { 98,	"Roamer Database Verification Request" },
    { 99,	"Add Service" },
    { 100,	"Drop Service" },
    { 0, NULL },
};
/*
 * 6.5.2.2 ActionCode
 * Table 114 ActionCode value
 */
static const value_string ansi_map_ActionCode_vals[] = {
  {   0, "Not used" },
  {   1, "Continue processing" },
  {   2, "Disconnect call" },
  {   3, "Disconnect call leg" },
  {   4, "Conference Calling Drop Last Party" },
  {   5, "Bridge call leg(s) to conference call" },
  {   6, "Drop call leg on busy or routing failure" },
  {   7, "Disconnect all call legs" },
  { 0, NULL }
};

static int dissect_invokeData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_returnData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);

typedef struct dgt_set_t
{
    unsigned char out[15];
}
dgt_set_t;

static dgt_set_t Dgt_tbcd = {
    {
  /*  0   1   2   3   4   5   6   7   8   9   a   b   c   d   e */
     '0','1','2','3','4','5','6','7','8','9','?','B','C','*','#'
    }
};
/* Assumes the rest of the tvb contains the digits to be turned into a string 
 */
static char*
unpack_digits2(tvbuff_t *tvb, int offset,dgt_set_t *dgt){

	int length;
	guint8 octet;
	int i=0;
	char *digit_str;

	length = tvb_length(tvb);
	if (length < offset)
		return "";
	digit_str = ep_alloc((length - offset)*2+1);

	while ( offset < length ){

		octet = tvb_get_guint8(tvb,offset);
		digit_str[i] = dgt->out[octet & 0x0f]; 
		i++;

		/*
		 * unpack second value in byte
		 */
		octet = octet >> 4;

		if (octet == 0x0f)	/* odd number bytes - hit filler */
			break;

		digit_str[i] = dgt->out[octet & 0x0f]; 
		i++;
		offset++;

	}
	digit_str[i]= '\0';
	return digit_str;
}



/* Type of Digits (octet 1, bits A-H) */
static const value_string ansi_map_type_of_digits_vals[] = {
  {   0, "Not Used" },
  {   1, "Dialed Number or Called Party Number" },
  {   2, "Calling Party Number" },
  {   3, "Caller Interaction" },
  {   4, "Routing Number" },
  {   5, "Billing Number" },
  {   6, "Destination Number" },
  {   7, "LATA" },
  {   8, "Carrier" },
  { 0, NULL }
};
/* Nature of Number (octet 2, bits A-H )*/
static const true_false_string ansi_map_na_bool_val  = {
  "International",
  "National"
};
static const true_false_string ansi_map_pi_bool_val  = {
  "Presentation Restricted",
  "Presentation Allowed"
};
static const true_false_string ansi_map_navail_bool_val  = {
  "Number is not available",
  "Number is available"
};
static const true_false_string ansi_map_si_bool_val  = {
  "User provided, screening passed",
  "User provided, not screened"
};
static const value_string ansi_map_si_vals[]  = {
    {   0, "User provided, not screened"},
    {   1, "User provided, screening passed"},
    {   2, "User provided, screening failed"},
    {   3, "Network provided"},
	{ 0, NULL }
};
/* Encoding (octet 3, bits A-D) */
static const value_string ansi_map_digits_enc_vals[]  = {
    {   0, "Not used"},
    {   1, "BCD"},
    {   2, "IA5"},
    {   3, "Octet string"},
	{	0, NULL }
};
/* Numbering Plan (octet 3, bits E-H) */
static const value_string ansi_map_np_vals[]  = {
    {   0, "Unknown or not applicable"},
    {   1, "ISDN Numbering"},
    {   2, "Telephony Numbering (ITU-T Rec. E.164,E.163)"},
    {   3, "Data Numbering (ITU-T Rec. X.121)"},
    {   4, "Telex Numbering (ITU-T Rec. F.69)"},
    {   5, "Maritime Mobile Numbering"},
    {   6, "Land Mobile Numbering (ITU-T Rec. E.212)"},
    {   7, "Private Numbering Plan"},
    {   13, "ANSI SS7 Point Code (PC) and Subsystem Number (SSN)"},
    {   14, "Internet Protocol (IP) Address."},
    {   15, "Reserved for extension"},
	{	0, NULL }
};


static void 
dissect_ansi_map_digits_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){
	
	guint8 octet;
	int offset = 0;
	char		*digit_str;

	/* Octet 1 */
	proto_tree_add_item(tree, hf_ansi_map_type_of_digits, tvb, offset, 1, FALSE);
	offset++;
	/* Octet 2 */
	proto_tree_add_item(tree, hf_ansi_map_si, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_ansi_map_navail, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_ansi_map_pi, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_ansi_map_na, tvb, offset, 1, FALSE);
	offset++;
	/* Octet 3 */
	octet = tvb_get_guint8(tvb,offset);
	proto_tree_add_item(tree, hf_ansi_map_np, tvb, offset, 1, FALSE);
	proto_tree_add_item(tree, hf_ansi_map_digits_enc, tvb, offset, 1, FALSE);
	offset++;
	/* Octet 4 - */
	switch(octet>>4){
	case 0:/* Unknown or not applicable */
	case 1:/* ISDN Numbering (not used in this Standard). */
	case 3:/* Data Numbering (ITU-T Rec. X.121) (not used in this Standard). */
	case 4:/* Telex Numbering (ITU-T Rec. F.69) (not used in this Standard). */
	case 5:/* Maritime Mobile Numbering (not used in this Standard). */
		proto_tree_add_text(tree, tvb, offset, -1, "This Number plan should not have been used");
		break;
	case 2:/* Telephony Numbering (ITU-T Rec. E.164,E.163). */
	case 6:/* Land Mobile Numbering (ITU-T Rec. E.212) */
	case 7:/* Private Numbering Plan */
		if ((octet&0xf) == 1){
			/* BCD Coding */
			proto_tree_add_item(tree, hf_ansi_map_nr_digits, tvb, offset, 1, FALSE);
			offset++;
			digit_str = unpack_digits(tvb, offset);
			proto_tree_add_string(tree, hf_ansi_map_bcd_digits, tvb, offset, -1, digit_str);
		}
		break;
	case 13:/* ANSI SS7 Point Code (PC) and Subsystem Number (SSN). */
		break;
	case 14:/* Internet Protocol (IP) Address. */
		break;
	default:
		proto_tree_add_text(tree, tvb, offset, -1, "This Number plan should not have been used");
		break;
	}

}

/*- 6.5.2.ac (N.S0007-0 v 1.0) ControlChannelMode */
static const value_string ansi_map_ControlChannelMode_vals[]  = {
    {   0, "Unknown"},
    {   1, "MS is in Analog CC Mode"},
    {   2, "MS is in Digital CC Mode"},
    {   3, "MS is in NAMPS CC Mode"},
	{	0, NULL }
};

/* 6.5.2.bp-1 ServiceRedirectionCause value */
static const value_string ansi_map_ServiceRedirectionCause_vals[]  = {
    {   0, "Not used"},
    {   1, "NormalRegistration"},
    {   2, "SystemNotFound"},
    {   3, "ProtocolMismatch"},
    {   4, "RegistrationRejection"},
    {   5, "WrongSID"},
    {   6, "WrongNID"},
	{	0, NULL }
};
#include "packet-ansi_map-fn.c"

static int dissect_invokeData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {


  switch(OperationCode & 0x00ff){
   case 1: /*Handoff Measurement Request*/
	   offset = dissect_ansi_map_HandoffMeasurementRequest(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case 2: /*Facilities Directive*/
	   offset = dissect_ansi_map_FacilitiesDirective(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case 3: /*Mobile On Channel*/
	   proto_tree_add_text(tree, tvb, offset, -1, "Unknown invokeData blob");
	   break;
   case 4: /*Handoff Back*/
	   offset = dissect_ansi_map_HandoffBack(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case 5: /*Facilities Release*/
	   offset = dissect_ansi_map_FacilitiesRelease(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case 6: /*Qualification Request*/
	   offset = dissect_ansi_map_QualificationRequest(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case 7: /*Qualification Directive*/
	   offset = dissect_ansi_map_QualificationDirective(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case 8: /*Blocking*/
	   offset = dissect_ansi_map_Blocking(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case 9: /*Unblocking*/
	   offset = dissect_ansi_map_Unblocking(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case 10: /*Reset Circuit*/
	   offset = dissect_ansi_map_ResetCircuit(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case 11: /*Trunk Test*/
	   offset = dissect_ansi_map_TrunkTest(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case 12: /*Trunk Test Disconnect*/
	  offset = dissect_ansi_map_TrunkTestDisconnect(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
   case  13: /*Registration Notification*/
	  offset = dissect_ansi_map_RegistrationNotification(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
   case  14: /*Registration Cancellation*/
	   offset = dissect_ansi_map_RegistrationCancellation(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
   case  15: /*Location Request*/
	   offset = dissect_ansi_map_LocationRequest(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  16: /*Routing Request*/
	   offset = dissect_ansi_map_RoutingRequest(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  17: /*Feature Request*/
	   offset = dissect_ansi_map_FeatureRequest(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  18: /*Reserved 18 (Service Profile Request, IS-41-C)*/
	   proto_tree_add_text(tree, tvb, offset, -1, "Unknown invokeData blob(18 (Service Profile Request, IS-41-C)");
	   break;
   case  19: /*Reserved 19 (Service Profile Directive, IS-41-C)*/
	   proto_tree_add_text(tree, tvb, offset, -1, "Unknown invokeData blob(19 Service Profile Directive, IS-41-C)");
	   break;
   case  20: /*Unreliable Roamer Data Directive*/
	   offset = dissect_ansi_map_UnreliableRoamerDataDirective(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  21: /*Reserved 21 (Call Data Request, IS-41-C)*/
	   proto_tree_add_text(tree, tvb, offset, -1, "Unknown invokeData blob(Reserved 21 (Call Data Request, IS-41-C)");
	   break;
   case  22: /*MS Inactive*/
	   offset = dissect_ansi_map_MSInactive(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  23: /*Transfer To Number Request*/
	   offset = dissect_ansi_map_TransferToNumberRequest(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  24: /*Redirection Request*/
	   offset = dissect_ansi_map_RedirectionRequest(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  25: /*Handoff To Third*/
	   offset = dissect_ansi_map_HandoffToThird(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  26: /*Flash Request*/
	   offset = dissect_ansi_map_FlashRequest(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  27: /*Authentication Directive*/
	   offset = dissect_ansi_map_AuthenticationDirective(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  28: /*Authentication Request*/
	   offset = dissect_ansi_map_AuthenticationRequest(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  29: /*Base Station Challenge*/
	   offset = dissect_ansi_map_BaseStationChallenge(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  30: /*Authentication Failure Report*/
	   offset = dissect_ansi_map_AuthenticationFailureReport(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  31: /*Count Request*/
	   offset = dissect_ansi_map_CountRequest(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  32: /*Inter System Page*/
	   offset = dissect_ansi_map_InterSystemPage(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  33: /*Unsolicited Response*/
	   offset = dissect_ansi_map_UnsolicitedResponse(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  34: /*Bulk Deregistration*/
	   offset = dissect_ansi_map_BulkDeregistration(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  35: /*Handoff Measurement Request 2*/
	   offset = dissect_ansi_map_HandoffMeasurementRequest2(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  36: /*Facilities Directive 2*/
	   offset = dissect_ansi_map_FacilitiesDirective2(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  37: /*Handoff Back 2*/
	   offset = dissect_ansi_map_HandoffBack2(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  38: /*Handoff To Third 2*/
	   offset = dissect_ansi_map_HandoffToThird2(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  39: /*Authentication Directive Forward*/
	   offset = dissect_ansi_map_AuthenticationDirectiveForward(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  40: /*Authentication Status Report*/
	   offset = dissect_ansi_map_AuthenticationStatusReport(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  41: /*Reserved 41*/
	   proto_tree_add_text(tree, tvb, offset, -1, "Reserved 41, Unknown invokeData blob");
	   break;
   case  42: /*Information Directive*/
	   offset = dissect_ansi_map_InformationDirective(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  43: /*Information Forward*/
	   offset = dissect_ansi_map_InformationForward(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  44: /*Inter System Answer*/
	   offset = dissect_ansi_map_InterSystemAnswer(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  45: /*Inter System Page 2*/
	   offset = dissect_ansi_map_InterSystemPage2(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  46: /*Inter System Setup*/
	   offset = dissect_ansi_map_InterSystemSetup(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
  case  47: /*OriginationRequest*/
	  offset = dissect_ansi_map_OriginationRequest(TRUE, tvb, offset, pinfo, tree, hf_ansi_map_OriginationRequest_PDU);
	  break;
  case  48: /*Random Variable Request*/
	  offset = dissect_ansi_map_RandomVariableRequest(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  49: /*Redirection Directive*/
	  offset = dissect_ansi_map_RedirectionDirective(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  50: /*Remote User Interaction Directive*/
	  offset = dissect_ansi_map_RemoteUserInteractionDirective(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  51: /*SMS Delivery Backward*/
	  offset = dissect_ansi_map_SMSDeliveryBackward(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  52: /*SMS Delivery Forward*/
	  offset = dissect_ansi_map_SMSDeliveryForward(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  53: /*SMS Delivery Point to Point*/
	  offset = dissect_ansi_map_SMSDeliveryPointToPoint(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  54: /*SMS Notification*/
	  offset = dissect_ansi_map_SMSNotification(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  55: /*SMS Request*/
	  offset = dissect_ansi_map_SMSRequest(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
	  /* End N.S0005*/
	  /* N.S0010-0 v 1.0 */
  case  56: /*OTASP Request*/
	  offset = offset;
	  break;
  case  57: /*Information Backward*/
	  offset = offset;
	  break;
	  /*  N.S0008-0 v 1.0 */
  case  58: /*Change Facilities*/
	  offset = offset;
	  break;
  case  59: /*Change Service*/
	  offset = offset;
	  break;
	  /* End N.S0008-0 v 1.0 */	
  case  60: /*Parameter Request*/
	  offset = offset;
	  break;
  case  61: /*TMSI Directive*/
	  offset = offset;
	  break;
	  /*End  N.S0010-0 v 1.0 */
  case  62: /*Reserved 62*/
	  offset = offset;
	  break;
  case  63: /*Service Request*/
	  offset = dissect_ansi_map_ServiceRequest(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
	  /* N.S0013 */
  case  64: /*Analyzed Information Request*/
	  offset = dissect_ansi_map_AnalyzedInformation(TRUE, tvb, offset, pinfo, tree, -1);;
	  break;
  case  65: /*Connection Failure Report*/
	  offset = offset;
	  break;
  case  66: /*Connect Resource*/
	  offset = offset;
	  break;
  case  67: /*Disconnect Resource*/
	  /* No data */
	  break;
  case  68: /*Facility Selected and Available*/
	  offset = dissect_ansi_map_FacilitySelectedAndAvailable(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  69: /*Instruction Request*/
	  /* No data */
	  break;
  case  70: /*Modify*/
	  offset = offset;
	  break;
  case  71: /*Reset Timer*/
	  offset = offset;
	  break;
  case  72: /*Search*/
	  offset = offset;
	  break;
  case  73: /*Seize Resource*/
	  offset = offset;
	  break;
  case  74: /*SRF Directive*/
	  offset = dissect_ansi_map_SRFDirective(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  75: /*T Busy*/
	  offset = dissect_ansi_map_TBusy(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  76: /*T NoAnswer*/
	  offset = dissect_ansi_map_TNoAnswer(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
	  /*END N.S0013 */
  case  77: /*Release*/
	  offset = offset;
	  break;
  case  78: /*SMS Delivery Point to Point Ack*/
	  offset = offset;
	  break;
	  /* N.S0024*/
  case  79: /*Message Directive*/
	  offset = dissect_ansi_map_MessageDirective(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
	  /*END N.S0024*/
	  /* N.S0018 PN-4287*/
  case  80: /*Bulk Disconnection*/
	  offset = dissect_ansi_map_BulkDisconnection(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  81: /*Call Control Directive*/
	  offset = dissect_ansi_map_CallControlDirective(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  82: /*O Answer*/
	  offset = dissect_ansi_map_OAnswer(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  83: /*O Disconnect*/
	  offset = dissect_ansi_map_ODisconnect(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  84: /*Call Recovery Report*/
	  offset = dissect_ansi_map_CallRecoveryReport(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  85: /*T Answer*/
	  offset = dissect_ansi_map_TAnswer(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  86: /*T Disconnect*/
	  offset = dissect_ansi_map_TDisconnect(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  87: /*Unreliable Call Data*/
	  offset = dissect_ansi_map_UnreliableCallData(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
	  /* N.S0018 PN-4287*/
	  /*N.S0004 */
  case  88: /*O CalledPartyBusy*/
	  offset = dissect_ansi_map_OCalledPartyBusy(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  89: /*O NoAnswer*/
	  offset = dissect_ansi_map_ONoAnswer(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  90: /*Position Request*/
	  offset = dissect_ansi_map_PositionRequest(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  91: /*Position Request Forward*/
	  offset = dissect_ansi_map_PositionRequestForward(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
	   /*END N.S0004 */
  case  92: /*Call Termination Report*/
	  offset = offset;
	  break;
  case  93: /*Geo Position Directive*/
	  offset = offset;
	  break;
  case  94: /*Geo Position Request*/
	  offset = offset;
	  break;
  case  95: /*Inter System Position Request*/
	  offset = offset;
	  break;
  case  96: /*Inter System Position Request Forward*/
	  offset = offset;
	  break;
  case  97: /*ACG Directive*/
	  offset = offset;
	  break;
  case  98: /*Roamer Database Verification Request*/
	  offset = offset;
	  break;
	  /* N.S0029 */
  case  99: /*Add Service*/
	  offset = offset;
	  break;
  case  100: /*Drop Service*/
	  offset = offset;
	  break;
	  /*End N.S0029 */
  default:
	  proto_tree_add_text(tree, tvb, offset, -1, "Unknown invokeData blob");
	  break;
  }

  return offset;

 }

static int dissect_returnData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {


  switch(OperationCode & 0x00ff){
   case 2: /*Facilities Directive*/
	   offset = dissect_ansi_map_FacilitiesDirectiveRes(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case 4: /*Handoff Back*/
	   offset = dissect_ansi_map_HandoffBackRes(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case 6: /*Qualification Request*/
	   offset = dissect_ansi_map_QualificationRequestRes(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case 13: /*Registration Notification*/
	  offset = dissect_ansi_map_RegistrationNotificationRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
   case  23: /*Transfer To Number Request*/
	   offset = dissect_ansi_map_TransferToNumberRequestRes(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  25: /*Handoff To Third*/
	   offset = dissect_ansi_map_HandoffToThirdRes(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  27: /*Authentication Directive*/
	   offset = dissect_ansi_map_AuthenticationDirectiveRes(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  30: /*Authentication Failure Report*/
	   offset = dissect_ansi_map_AuthenticationFailureReportRes(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  31: /*Count Request*/
	   offset = dissect_ansi_map_CountRequestRes(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  33: /*Unsolicited Response*/
	   offset = dissect_ansi_map_UnsolicitedResponseRes(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  37: /*Handoff Back 2*/
	   offset = dissect_ansi_map_HandoffBack2Res(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  38: /*Handoff To Third 2*/
	   offset = dissect_ansi_map_HandoffToThird2Res(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  40: /*Authentication Status Report*/
	   offset = dissect_ansi_map_AuthenticationStatusReportRes(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  43: /*Information Forward*/
	   offset = dissect_ansi_map_InformationForwardRes(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
   case  46: /*Inter System Setup*/
	   offset = dissect_ansi_map_InterSystemSetupRes(TRUE, tvb, offset, pinfo, tree, -1);
	   break;
  case  47: /*OriginationRequest*/
	  offset = dissect_ansi_map_OriginationRequestRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  50: /*Remote User Interaction Directive*/
	  offset = dissect_ansi_map_RemoteUserInteractionDirectiveRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  51: /*SMS Delivery Backward*/
	  offset = dissect_ansi_map_SMSDeliveryBackwardRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  52: /*SMS Delivery Forward*/
	  offset = dissect_ansi_map_SMSDeliveryForwardRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  53: /*SMS Delivery Point to Point*/
	  offset = dissect_ansi_map_SMSDeliveryPointToPointRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  54: /*SMS Notification*/
	  offset = dissect_ansi_map_SMSNotificationRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  55: /*SMS Request*/
	  offset = dissect_ansi_map_SMSRequestRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  63: /*Service Request*/
	  offset = dissect_ansi_map_ServiceRequestRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  68: /*Facility Selected and Available*/
	  offset = dissect_ansi_map_FacilitySelectedAndAvailableRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  75: /*T Busy*/
	  offset = dissect_ansi_map_TBusyRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  76: /*T NoAnswer*/
	  offset = dissect_ansi_map_TNoAnswerRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  83: /*O Disconnect*/
	  offset = dissect_ansi_map_ODisconnectRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  86: /*T Disconnect*/
	  offset = dissect_ansi_map_TDisconnectRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  88: /*O CalledPartyBusy*/
	  offset = dissect_ansi_map_OCalledPartyBusyRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
   case  89: /*O NoAnswer*/
	  offset = dissect_ansi_map_ONoAnswerRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  90: /*Position Request*/
	  offset = dissect_ansi_map_PositionRequestRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  91: /*Position Request Forward*/
	  offset = dissect_ansi_map_PositionRequestForwardRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
 default:
	  proto_tree_add_text(tree, tvb, offset, -1, "Unknown invokeData blob");
	  break;
  }

  return offset;

 }

static void
dissect_ansi_map(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ansi_map_item;
    proto_tree *ansi_map_tree = NULL;
    int        offset = 0;

    g_pinfo = pinfo;

    /*
     * Make entry in the Protocol column on summary display
     */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "ANSI MAP");
    }

    /* In the interest of speed, if "tree" is NULL, don't do any work not
     * necessary to generate protocol tree items.
     */
    if (tree)
    {
	g_tree = tree;

	/*
	 * create the ansi_map protocol tree
	 */
	ansi_map_item =
	    proto_tree_add_item(tree, proto_ansi_map, tvb, 0, -1, FALSE);

	ansi_map_tree =
	    proto_item_add_subtree(ansi_map_item, ett_ansi_map);



	ansi_map_is_invoke = FALSE;
	is683_ota = FALSE;
	is801_pld = FALSE;
	dissect_ansi_map_ComponentPDU(FALSE, tvb, offset, pinfo, ansi_map_tree, -1);

    }
}

/*--- proto_register_ansi_map -------------------------------------------*/
void proto_register_ansi_map(void) {

  /* List of fields */
    static hf_register_info hf[] = {

    { &hf_ansi_map_op_code_fam,
      { "Operation Code Family", "ansi_map.op_code_fam",
        FT_UINT8, BASE_DEC, NULL, 0,
        "Operation Code Family", HFILL }},
    { &hf_ansi_map_op_code,
      { "Operation Code", "ansi_map.op_code",
        FT_UINT8, BASE_DEC, VALS(ansi_map_opr_code_strings), 0x0,
        "Operation Code", HFILL }},
	{ &hf_ansi_map_type_of_digits,
      { "Type of Digits", "ansi_map.type_of_digits",
        FT_UINT8, BASE_DEC, VALS(ansi_map_type_of_digits_vals), 0x0,
        "Type of Digits", HFILL }},
	{ &hf_ansi_map_na,
      { "Nature of Number", "ansi_map.na",
        FT_BOOLEAN, 8, TFS(&ansi_map_na_bool_val),0x01,
        "Nature of Number", HFILL }},
	{ &hf_ansi_map_pi,
      { "Presentation Indication", "ansi_map.type_of_pi",
        FT_BOOLEAN, 8, TFS(&ansi_map_pi_bool_val),0x02,
        "Presentation Indication", HFILL }},
	{ &hf_ansi_map_navail,
      { "Numer available indication", "ansi_map.navail",
        FT_BOOLEAN, 8, TFS(&ansi_map_navail_bool_val),0x04,
        "Numer available indication", HFILL }},
	{ &hf_ansi_map_si,
      { "Screening indication", "ansi_map.si",
        FT_UINT8, BASE_DEC, VALS(ansi_map_si_vals), 0x30,
        "Screening indication", HFILL }},
	{ &hf_ansi_map_digits_enc,
      { "Encoding", "ansi_map.enc",
        FT_UINT8, BASE_DEC, VALS(ansi_map_digits_enc_vals), 0x0f,
        "Encoding", HFILL }},
	{ &hf_ansi_map_np,
      { "Numbering Plan", "ansi_map.np",
        FT_UINT8, BASE_DEC, VALS(ansi_map_np_vals), 0xf0,
        "Numbering Plan", HFILL }},
	{ &hf_ansi_map_nr_digits,
      { "Number of Digits", "ansi_map.nr_digits",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        "Number of Digits", HFILL }},
	{ &hf_ansi_map_bcd_digits,
      { "BCD digits", "gsm_map.bcd_digits",
        FT_STRING, BASE_NONE, NULL, 0,
        "BCD digits", HFILL }},
#include "packet-ansi_map-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	  &ett_ansi_map,
#include "packet-ansi_map-ettarr.c"
  };


  /* Register protocol */
  proto_ansi_map = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_ansi_map, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

 
  register_dissector("ansi_map", dissect_ansi_map, proto_ansi_map);

  is637_tele_id_dissector_table =
	  register_dissector_table("ansi_map.tele_id", "IS-637 Teleservice ID",
	    FT_UINT8, BASE_DEC);

  is683_dissector_table =
	register_dissector_table("ansi_map.ota", "IS-683-A (OTA)",
	    FT_UINT8, BASE_DEC);

  is801_dissector_table =
	register_dissector_table("ansi_map.pld", "IS-801 (PLD)",
	    FT_UINT8, BASE_DEC);

  ansi_map_tap = register_tap("ansi_map");

}


/*--- proto_reg_handoff_ansi_map ---------------------------------------*/
void
proto_reg_handoff_ansi_map(void)
{

    ansi_map_handle = create_dissector_handle(dissect_ansi_map, proto_ansi_map);

	add_ansi_tcap_subdissector(5, ansi_map_handle); 
    add_ansi_tcap_subdissector(6, ansi_map_handle); 
    add_ansi_tcap_subdissector(7, ansi_map_handle); 
    add_ansi_tcap_subdissector(8, ansi_map_handle); 
    add_ansi_tcap_subdissector(9 , ansi_map_handle); 
    add_ansi_tcap_subdissector(10 , ansi_map_handle); 
    add_ansi_tcap_subdissector(11 , ansi_map_handle); 
    add_ansi_tcap_subdissector(12 , ansi_map_handle); 
    add_ansi_tcap_subdissector(13 , ansi_map_handle); 
    add_ansi_tcap_subdissector(14 , ansi_map_handle); 
    

    data_handle = find_dissector("data");

}


