/* packet-ansi_map.c
 * Routines for ANSI 41 Mobile Application Part (IS41 MAP) dissection
 * Specications from 3GPP2 (www.3gpp2.org)
 * Based on the dissector by :
 * Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 *
 * Copyright 2005, Anders Broman <anders.broman@ericsson.com>
 *
 * $Id:$
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
 *   Features In CDMA
 *			3GPP2 N.S0010-0 v1.0	IS-735
 *
 *   OTASP and OTAPA
 *			3GPP2 N.S0011-0 v1.0	IS-725-A
 *
 *   Circuit Mode Services
 *			3GPP2 N.S0008-0 v1.0	IS-737
 *	XXX SecondInterMSCCircuitID not implemented, parameter ID conflicts with ISLP Information!
 *
 *   IMSI
 *			3GPP2 N.S0009-0 v1.0	IS-751
 *
 *   WIN Phase 1
 *			3GPP2 N.S0013-0 v1.0	IS-771
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
 *   TIA/EIA-41-D Pre-Paid Charging
 *			3GPP2 N.S0018-0 v1.0	IS-826
 *
 *   User Selective Call Forwarding
 *			3GPP2 N.S0021-0 v1.0	IS-838
 *
 *
 *   Answer Hold
 *			3GPP2 N.S0022-0 v1.0	IS-837
 *
 *   UIM
 *			3GPP2 N.S0003
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
static int hf_ansi_map_trans_cap_prof = -1;
static int hf_ansi_map_trans_cap_busy = -1;
static int hf_ansi_map_trans_cap_ann = -1;
static int hf_ansi_map_trans_cap_rui = -1;
static int hf_ansi_map_trans_cap_spini = -1;
static int hf_ansi_map_trans_cap_uzci = -1;
static int hf_ansi_map_trans_cap_ndss = -1;
static int hf_ansi_map_trans_cap_nami = -1;
static int hf_ansi_trans_cap_multerm = -1;
static int hf_ansi_trans_cap_tl = -1;
static int hf_ansi_map_MarketID = -1;
static int hf_ansi_map_swno = -1;
static int hf_ansi_map_idno = -1;
static int hf_ansi_map_segcount = -1;
static int hf_ansi_map_originationtriggers_all = -1;
static int hf_ansi_map_originationtriggers_local = -1;
static int hf_ansi_map_originationtriggers_ilata = -1;
static int hf_ansi_map_originationtriggers_olata = -1;
static int hf_ansi_map_originationtriggers_int = -1;
static int hf_ansi_map_originationtriggers_wz = -1;
static int hf_ansi_map_originationtriggers_unrec = -1;
static int hf_ansi_map_originationtriggers_rvtc = -1;
static int hf_ansi_map_originationtriggers_star = -1;
static int hf_ansi_map_originationtriggers_ds = -1;
static int hf_ansi_map_originationtriggers_pound = -1;
static int hf_ansi_map_originationtriggers_dp = -1;
static int hf_ansi_map_originationtriggers_pa = -1;
static int hf_ansi_map_originationtriggers_nodig = -1;
static int hf_ansi_map_originationtriggers_onedig = -1;
static int hf_ansi_map_originationtriggers_twodig = -1;
static int hf_ansi_map_originationtriggers_threedig = -1;
static int hf_ansi_map_originationtriggers_fourdig = -1;
static int hf_ansi_map_originationtriggers_fivedig = -1;
static int hf_ansi_map_originationtriggers_sixdig = -1;
static int hf_ansi_map_originationtriggers_sevendig = -1;
static int hf_ansi_map_originationtriggers_eightdig = -1;
static int hf_ansi_map_originationtriggers_ninedig = -1;
static int hf_ansi_map_originationtriggers_tendig = -1;
static int hf_ansi_map_originationtriggers_elevendig = -1;
static int hf_ansi_map_originationtriggers_thwelvedig = -1;
static int hf_ansi_map_originationtriggers_thirteendig = -1;
static int hf_ansi_map_originationtriggers_fourteendig = -1;
static int hf_ansi_map_originationtriggers_fifteendig = -1;
static int hf_ansi_map_triggercapability_init = -1;
static int hf_ansi_map_triggercapability_kdigit = -1;
static int hf_ansi_map_triggercapability_all = -1;
static int hf_ansi_map_triggercapability_rvtc = -1;
static int hf_ansi_map_triggercapability_oaa = -1;
static int hf_ansi_map_triggercapability_oans = -1;
static int hf_ansi_map_triggercapability_odisc = -1;
static int hf_ansi_map_triggercapability_ona = -1;

#include "packet-ansi_map-hf.c"

/* Initialize the subtree pointers */
static gint ett_ansi_map = -1;
static gint ett_mintype = -1;
static gint ett_digitstype = -1;
static gint ett_billingid = -1;
static gint ett_mscid = -1;
static gint ett_originationtriggers = -1;
static gint ett_transactioncapability = -1;

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
static dgt_set_t Dgt1_9_bcd = {
    {
  /*  0   1   2   3   4   5   6   7   8   9   a   b   c   d   e */
     '0','1','2','3','4','5','6','7','8','9','?','?','?','?','?'
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
dissect_ansi_map_min_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){
	char		*digit_str;
	int offset = 0;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_mintype);
	
	digit_str = unpack_digits2(tvb, offset, &Dgt1_9_bcd);
	proto_tree_add_string(subtree, hf_ansi_map_bcd_digits, tvb, offset, -1, digit_str);
}

static void 
dissect_ansi_map_digits_type(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){
	
	guint8 octet;
	int offset = 0;
	char		*digit_str;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_digitstype);

	/* Octet 1 */
	proto_tree_add_item(subtree, hf_ansi_map_type_of_digits, tvb, offset, 1, FALSE);
	offset++;
	/* Octet 2 */
	proto_tree_add_item(subtree, hf_ansi_map_si, tvb, offset, 1, FALSE);
	proto_tree_add_item(subtree, hf_ansi_map_navail, tvb, offset, 1, FALSE);
	proto_tree_add_item(subtree, hf_ansi_map_pi, tvb, offset, 1, FALSE);
	proto_tree_add_item(subtree, hf_ansi_map_na, tvb, offset, 1, FALSE);
	offset++;
	/* Octet 3 */
	octet = tvb_get_guint8(tvb,offset);
	proto_tree_add_item(subtree, hf_ansi_map_np, tvb, offset, 1, FALSE);
	proto_tree_add_item(subtree, hf_ansi_map_digits_enc, tvb, offset, 1, FALSE);
	offset++;
	/* Octet 4 - */
	switch(octet>>4){
	case 0:/* Unknown or not applicable */
	case 1:/* ISDN Numbering (not used in this Standard). */
	case 3:/* Data Numbering (ITU-T Rec. X.121) (not used in this Standard). */
	case 4:/* Telex Numbering (ITU-T Rec. F.69) (not used in this Standard). */
	case 5:/* Maritime Mobile Numbering (not used in this Standard). */
		proto_tree_add_text(subtree, tvb, offset, -1, "This Number plan should not have been used");
		break;
	case 2:/* Telephony Numbering (ITU-T Rec. E.164,E.163). */
	case 6:/* Land Mobile Numbering (ITU-T Rec. E.212) */
	case 7:/* Private Numbering Plan */
		if ((octet&0xf) == 1){
			/* BCD Coding */
			proto_tree_add_item(subtree, hf_ansi_map_nr_digits, tvb, offset, 1, FALSE);
			offset++;
			digit_str = unpack_digits2(tvb, offset, &Dgt_tbcd);
			proto_tree_add_string(subtree, hf_ansi_map_bcd_digits, tvb, offset, -1, digit_str);
		}
		break;
	case 13:/* ANSI SS7 Point Code (PC) and Subsystem Number (SSN). */
		break;
	case 14:/* Internet Protocol (IP) Address. */
		break;
	default:
		proto_tree_add_text(subtree, tvb, offset, -1, "This Number plan should not have been used");
		break;
	}

}
/*
 * 6.5.2.2 ActionCode
 * Table 114 ActionCode value
 */


/* 6.5.2.2 ActionCode(TIA/EIA-41.5-D, page 5-129) */

static const value_string ansi_map_ActionCode_vals[]  = {
    {   0, "Not used"},
    {   1, "Continue processing"},
    {   2, "Disconnect call"},
    {   3, "Disconnect call leg"},
    {   4, "Conference Calling Drop Last Party"},
    {   5, "Bridge call leg(s) to conference call"},
    {   6, "Drop call leg on busy or routing failure"},
    {   7, "Disconnect all call legs"},
    {   8, "Attach MSC to OTAF"},
    {   9, "Initiate RegistrationNotification"},
    {   10, "Generate Public Encryption values"},
    {   11, "Generate A-key"},
    {   12, "Perform SSD Update procedure"},
    {   13, "Perform Re-authentication procedure"},
    {   14, "Release TRN"},
    {   15, "Commit A-key"},
    {   16, "Release Resources (e.g., A-key, Traffic Channel)"},
    {   17, "Record NEWMSID"},
    {   18, "Allocate Resources (e.g., Multiple message traffic channel delivery)."},
    {   19, "Generate Authentication Signature"},
	{	0, NULL }
};

/* 6.5.2.16 BillingID */
static void
dissect_ansi_map_billingid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){

	int offset = 0;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_billingid);

	proto_tree_add_item(subtree, hf_ansi_map_MarketID, tvb, offset, 2, FALSE);
	offset = offset + 2;
	proto_tree_add_item(subtree, hf_ansi_map_swno, tvb, offset, 1, FALSE);
	offset++;
	/* ID Number */
	proto_tree_add_item(subtree, hf_ansi_map_idno, tvb, offset, 3, FALSE);
	offset = offset + 3;
	proto_tree_add_item(subtree, hf_ansi_map_segcount, tvb, offset, 1, FALSE);

}
/* 6.5.2.82 MSCID */

static void
dissect_ansi_map_mscid(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){
	int offset = 0;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_mscid);

	proto_tree_add_item(subtree, hf_ansi_map_MarketID, tvb, offset, 2, FALSE);
	offset = offset + 2;
	proto_tree_add_item(subtree, hf_ansi_map_swno, tvb, offset, 1, FALSE);
}

/* 6.5.2.90 OriginationTriggers */


/* All Origination (All) (octet 1, bit A) */
static const true_false_string ansi_map_originationtriggers_all_bool_val  = {
  "Launch an OriginationRequest for any call attempt. This overrides all other values",
  "Trigger is not active"
};

/* Local (octet 1, bit B) */
static const true_false_string ansi_map_originationtriggers_local_bool_val  = {
  "Launch an OriginationRequest for any local call attempt",
  "Trigger is not active"
};

/* Intra-LATA Toll (ILATA) (octet 1, bit C) */
static const true_false_string ansi_map_originationtriggers_ilata_bool_val  = {
  "Launch an OriginationRequest for any intra-LATA call attempt",
  "Trigger is not active"
};
/* Inter-LATA Toll (OLATA) (octet 1, bit D) */
static const true_false_string ansi_map_originationtriggers_olata_bool_val  = {
  "Launch an OriginationRequest for any inter-LATA toll call attempt",
  "Trigger is not active"
};
/* International (Int'l ) (octet 1, bit E) */
static const true_false_string ansi_map_originationtriggers_int_bool_val  = {
  "Launch an OriginationRequest for any international call attempt",
  "Trigger is not active"
};
/* World Zone (WZ) (octet 1, bit F) */
static const true_false_string ansi_map_originationtriggers_wz_bool_val  = {
  "Launch an OriginationRequest for any call attempt outside of the current World Zone (as defined in ITU-T Rec. E.164)",
  "Trigger is not active"
};

/* Unrecognized Number (Unrec) (octet 1, bit G) */
static const true_false_string ansi_map_originationtriggers_unrec_bool_val  = {
  "Launch an OriginationRequest for any call attempt to an unrecognized number",
  "Trigger is not active"
};
/* Revertive Call (RvtC) (octet 1, bit H)*/
static const true_false_string ansi_map_originationtriggers_rvtc_bool_val  = {
  "Launch an OriginationRequest for any Revertive Call attempt",
  "Trigger is not active"
};

/* Star (octet 2, bit A) */
static const true_false_string ansi_map_originationtriggers_star_bool_val  = {
  "Launch an OriginationRequest for any number beginning with a Star '*' digit",
  "Trigger is not active"
};

/* Double Star (DS) (octet 2, bit B) */
static const true_false_string ansi_map_originationtriggers_ds_bool_val  = {
  "Launch an OriginationRequest for any number beginning with two Star '**' digits",
  "Trigger is not active"
};
/* Pound (octet 2, bit C) */
static const true_false_string ansi_map_originationtriggers_pound_bool_val  = {
  "Launch an OriginationRequest for any number beginning with a Pound '#' digit",
  "Trigger is not active"
};
/* Double Pound (DP) (octet 2, bit D) */
static const true_false_string ansi_map_originationtriggers_dp_bool_val  = {
  "Launch an OriginationRequest for any number beginning with two Pound '##' digits",
  "Trigger is not active"
};
/* Prior Agreement (PA) (octet 2, bit E) */
static const true_false_string ansi_map_originationtriggers_pa_bool_val  = {
  "Launch an OriginationRequest for any number matching a criteria of a prior agreement",
  "Trigger is not active"
};

/* No digits (octet 3, bit A) */
static const true_false_string ansi_map_originationtriggers_nodig_bool_val  = {
  "Launch an OriginationRequest for any call attempt with no digits",
  "Trigger is not active"
};

/* 1 digit (octet 3, bit B) */
static const true_false_string ansi_map_originationtriggers_onedig_bool_val  = {
  "Launch an OriginationRequest for any call attempt with 1 digit",
  "Trigger is not active"
};
/* 1 digit (octet 3, bit C) */
static const true_false_string ansi_map_originationtriggers_twodig_bool_val  = {
  "Launch an OriginationRequest for any call attempt with 2 digits",
  "Trigger is not active"
};
/* 1 digit (octet 3, bit D) */
static const true_false_string ansi_map_originationtriggers_threedig_bool_val  = {
  "Launch an OriginationRequest for any call attempt with 3 digits",
  "Trigger is not active"
};
/* 1 digit (octet 3, bit E) */
static const true_false_string ansi_map_originationtriggers_fourdig_bool_val  = {
  "Launch an OriginationRequest for any call attempt with 4 digits",
  "Trigger is not active"
};
/* 1 digit (octet 3, bit F) */
static const true_false_string ansi_map_originationtriggers_fivedig_bool_val  = {
  "Launch an OriginationRequest for any call attempt with 5 digits",
  "Trigger is not active"
};
/* 1 digit (octet 3, bit G) */
static const true_false_string ansi_map_originationtriggers_sixdig_bool_val  = {
  "Launch an OriginationRequest for any call attempt with 6 digits",
  "Trigger is not active"
};
/* 1 digit (octet 3, bit H) */
static const true_false_string ansi_map_originationtriggers_sevendig_bool_val  = {
  "Launch an OriginationRequest for any call attempt with 7 digits",
  "Trigger is not active"
};
/* 1 digit (octet 4, bit A) */
static const true_false_string ansi_map_originationtriggers_eightdig_bool_val  = {
  "Launch an OriginationRequest for any call attempt with 8 digits",
  "Trigger is not active"
};
/* 1 digit (octet 4, bit B) */
static const true_false_string ansi_map_originationtriggers_ninedig_bool_val  = {
  "Launch an OriginationRequest for any call attempt with 9 digits",
  "Trigger is not active"
};
/* 1 digit (octet 4, bit C) */
static const true_false_string ansi_map_originationtriggers_tendig_bool_val  = {
  "Launch an OriginationRequest for any call attempt with 10 digits",
  "Trigger is not active"
};
/* 1 digit (octet 4, bit D) */
static const true_false_string ansi_map_originationtriggers_elevendig_bool_val  = {
  "Launch an OriginationRequest for any call attempt with 11 digits",
  "Trigger is not active"
};
/* 1 digit (octet 4, bit E) */
static const true_false_string ansi_map_originationtriggers_thwelvdig_bool_val  = {
  "Launch an OriginationRequest for any call attempt with 12 digits",
  "Trigger is not active"
};
/* 1 digit (octet 4, bit F) */
static const true_false_string ansi_map_originationtriggers_thirteendig_bool_val  = {
  "Launch an OriginationRequest for any call attempt with 13 digits",
  "Trigger is not active"
};
/* 1 digit (octet 4, bit G) */
static const true_false_string ansi_map_originationtriggers_fourteendig_bool_val  = {
  "Launch an OriginationRequest for any call attempt with 14 digits",
  "Trigger is not active"
};
/* 1 digit (octet 4, bit H) */
static const true_false_string ansi_map_originationtriggers_fifteendig_bool_val  = {
  "Launch an OriginationRequest for any call attempt with 15 digits",
  "Trigger is not active"
};

static void
dissect_ansi_map_originationtriggers(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){

	int offset = 0;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_originationtriggers);

	/* Revertive Call (RvtC) (octet 1, bit H)*/
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_rvtc, tvb, offset,	1, FALSE);
	/* Unrecognized Number (Unrec) (octet 1, bit G) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_unrec, tvb, offset,	1, FALSE);
	/* World Zone (WZ) (octet 1, bit F) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_wz, tvb, offset,	1, FALSE);
	/* International (Int'l ) (octet 1, bit E) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_int, tvb, offset,	1, FALSE);
	/* Inter-LATA Toll (OLATA) (octet 1, bit D) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_olata, tvb, offset,	1, FALSE);
	/* Intra-LATA Toll (ILATA) (octet 1, bit C) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_ilata, tvb, offset,	1, FALSE);
	/* Local (octet 1, bit B) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_local, tvb, offset,	1, FALSE);
	/* All Origination (All) (octet 1, bit A) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_all, tvb, offset,	1, FALSE);
	offset++;

	/*Prior Agreement (PA) (octet 2, bit E) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_pa, tvb, offset,	1, FALSE);
	/* Double Pound (DP) (octet 2, bit D) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_dp, tvb, offset,	1, FALSE);
	/* Pound (octet 2, bit C) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_pound, tvb, offset,	1, FALSE);
	/* Double Star (DS) (octet 2, bit B) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_ds, tvb, offset,	1, FALSE);
	/* Star (octet 2, bit A) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_star, tvb, offset,	1, FALSE);
	offset++;

	/* 7 digit (octet 3, bit H) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_sevendig, tvb, offset,	1, FALSE);
	/* 6 digit (octet 3, bit G) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_sixdig, tvb, offset,	1, FALSE);
	/* 5 digit (octet 3, bit F) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_fivedig, tvb, offset,	1, FALSE);
	/* 4 digit (octet 3, bit E) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_fourdig, tvb, offset,	1, FALSE);
	/* 3 digit (octet 3, bit D) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_threedig, tvb, offset,	1, FALSE);
	/* 2 digit (octet 3, bit C) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_twodig, tvb, offset,	1, FALSE);
	/* 1 digit (octet 3, bit B) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_onedig, tvb, offset,	1, FALSE);
	/* No digits (octet 3, bit A) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_nodig, tvb, offset,	1, FALSE);
	offset++;

	/* 15 digit (octet 4, bit H) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_fifteendig, tvb, offset,	1, FALSE);
	/* 14 digit (octet 4, bit G) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_fourteendig, tvb, offset,	1, FALSE);
	/* 13 digit (octet 4, bit F) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_thirteendig, tvb, offset,	1, FALSE);
	/* 12 digit (octet 4, bit E) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_thwelvedig, tvb, offset,	1, FALSE);
	/* 11 digit (octet 4, bit D) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_elevendig, tvb, offset,	1, FALSE);
	/* 10 digit (octet 4, bit C) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_tendig, tvb, offset,	1, FALSE);
	/* 9 digit (octet 4, bit B) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_ninedig, tvb, offset,	1, FALSE);
	/* 8 digits (octet 4, bit A) */
	proto_tree_add_item(subtree, hf_ansi_map_originationtriggers_eightdig, tvb, offset,	1, FALSE);

}
/*	6.5.2.122 SMS_AccessDeniedReason (TIA/EIA-41.5-D, page 5-256)
	N.S0011-0 v 1.0
 */
static const value_string ansi_map_SMS_AccessDeniedReason_vals[]  = {
    {   0, "Not used"},
    {   1, "Denied"},
    {   2, "Postponed"},
    {   3, "Unavailable"},
    {   4, "Invalid"},
	{	0, NULL }
};

/* 6.5.2.125 SMS_CauseCode (TIA/EIA-41.5-D, page 5-262)
	N.S0011-0 v 1.0
 */
static const value_string ansi_map_SMS_CauseCode_vals[]  = {
    {   0, "Address vacant"},
    {   1, "Address translation failure"},
    {   2, "Network resource shortage"},
    {   3, "Network failure"},
    {   4, "Invalid Teleservice ID"},
    {   5, "Other network problem"},
    {   6, "Unsupported network interface"},
    {   32, "No page response"},
    {   33, "Destination busy"},
    {   34, "No acknowledgment"},
    {   35, "Destination resource shortage"},
    {   36, "SMS delivery postponed"},
    {   37, "Destination out of service"},
    {   38, "Destination no longer at this address"},
    {   39, "Other terminal problem"},
    {   64, "Radio interface resource shortage"},
    {   65, "Radio interface incompatibility"},
    {   66, "Other radio interface problem"},
    {   67, "Unsupported Base Station Capability"},
    {   96, "Encoding problem"},
    {   97, "Service origination denied"},
    {   98, "Service termination denied"},
    {   99, "Supplementary service not supported"},
    {   100, "Service not supported"},
    {   101, "Reserved"},
    {   102, "Missing expected parameter"},
    {   103, "Missing mandatory parameter"},
    {   104, "Unrecognized parameter value"},
    {   105, "Unexpected parameter value"},
    {   106, "User Data size error"},
    {   107, "Other general problems"},
    {   108, "Session not active"},
	{	0, NULL }
};




static const true_false_string ansi_map_trans_cap_prof_bool_val  = {
  "The system is capable of supporting the IS-41-C profile parameters",
  "The system is not capable of supporting the IS-41-C profile parameters"
};

static const true_false_string ansi_map_trans_cap_busy_bool_val  = {
  "The system is capable of detecting a busy condition at the current time",
  "The system is not capable of detecting a busy condition at the current time"
};

static const true_false_string ansi_map_trans_cap_ann_bool_val  = {
  "The system is capable of honoring the AnnouncementList parameter at the current time",
  "The system is not capable of honoring the AnnouncementList parameter at the current time"
};

static const true_false_string ansi_map_trans_cap_rui_bool_val  = {
  "The system is capable of interacting with the user",
  "The system is not capable of interacting with the user"
};

static const true_false_string ansi_map_trans_cap_spini_bool_val  = {
  "The system is capable of supporting local SPINI operation",
  "The system is not capable of supporting local SPINI operation at the current time"
};

static const true_false_string ansi_map_trans_cap_uzci_bool_val  = {
  "The system is User Zone capable at the current time",
  "The system is not User Zone capable at the current time"
};
static const true_false_string ansi_map_trans_cap_ndss_bool_val  = {
  "Serving system is NDSS capable",
  "Serving system is not NDSS capable"
};
static const true_false_string ansi_map_trans_cap_nami_bool_val  = {
  "The system is CNAP/CNAR capable",
  "The system is not CNAP/CNAR capable"
};

static const value_string ansi_map_trans_cap_multerm_vals[]  = {
    {   0, "The system cannot accept a termination at this time (i.e., cannot accept routing information)"},
    {   1, "The system supports the number of call legs indicated"},
    {   2, "The system supports the number of call legs indicated"},
    {   3, "The system supports the number of call legs indicated"},
    {   4, "The system supports the number of call legs indicated"},
    {   5, "The system supports the number of call legs indicated"},
    {   6, "The system supports the number of call legs indicated"},
    {   7, "The system supports the number of call legs indicated"},
    {   8, "The system supports the number of call legs indicated"},
    {   9, "The system supports the number of call legs indicated"},
    {   10, "The system supports the number of call legs indicated"},
    {   11, "The system supports the number of call legs indicated"},
    {   12, "The system supports the number of call legs indicated"},
    {   13, "The system supports the number of call legs indicated"},
    {   14, "The system supports the number of call legs indicated"},
    {   15, "The system supports the number of call legs indicated"},
	{	0, NULL }
};

static const true_false_string ansi_map_trans_cap_tl_bool_val  = {
  "The system is capable of supporting the TerminationList parameter at the current time",
  "The system is not capable of supporting the TerminationList parameter at the current time"
};

/* 6.5.2.160 TransactionCapability (TIA/EIA-41.5-D, page 5-315) */
static void
dissect_ansi_map_transactioncapability(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){

	int offset = 0;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_transactioncapability);

	/*NAME Capability Indicator (NAMI) (octet 1, bit H) */
	proto_tree_add_item(subtree, hf_ansi_map_trans_cap_nami, tvb, offset, 1, FALSE);
	/* NDSS Capability (NDSS) (octet 1, bit G) */
	proto_tree_add_item(subtree, hf_ansi_map_trans_cap_ndss, tvb, offset, 1, FALSE);
	/* UZ Capability Indicator (UZCI) (octet 1, bit F) */
	proto_tree_add_item(subtree, hf_ansi_map_trans_cap_uzci, tvb, offset, 1, FALSE);
	/* Subscriber PIN Intercept (SPINI) (octet 1, bit E) */
	proto_tree_add_item(subtree, hf_ansi_map_trans_cap_spini, tvb, offset, 1, FALSE);
	/* Remote User Interaction (RUI) (octet 1, bit D) */
	proto_tree_add_item(subtree, hf_ansi_map_trans_cap_rui, tvb, offset, 1, FALSE);
	/* Announcements (ANN) (octet 1, bit C) */
	proto_tree_add_item(subtree, hf_ansi_map_trans_cap_ann, tvb, offset, 1, FALSE);
	/* Busy Detection (BUSY) (octet 1, bit B) */
	proto_tree_add_item(subtree, hf_ansi_map_trans_cap_busy, tvb, offset, 1, FALSE);
	/* Profile (PROF) (octet 1, bit A) */
	proto_tree_add_item(subtree, hf_ansi_map_trans_cap_prof, tvb, offset, 1, FALSE);
	offset++;

	/* Multiple Terminations (octet 2, bits A-D) */
	proto_tree_add_item(subtree, hf_ansi_trans_cap_multerm, tvb, offset, 1, FALSE);
	/* TerminationList (TL) (octet 2, bit E) */
	proto_tree_add_item(subtree, hf_ansi_trans_cap_tl, tvb, offset, 1, FALSE);
}
/* 6.5.2.i (IS-730) TDMAServiceCode */
static const value_string ansi_map_TDMAServiceCode_vals[]  = {
    {   0, "Analog Speech Only"},
    {   1, "Digital Speech Only"},
    {   2, "Analog or Digital Speech, Analog Preferred"},
    {   3, "Analog or Digital Speech, Digital Preferred"},
    {   4, "Asynchronous Data"},
    {   5, "G3 Fax"},
    {   6, "Not Used (Service Rejected)"},
    {   7, "STU-III"},
	{	0, NULL }
};

/*- 6.5.2.ac (N.S0007-0 v 1.0) ControlChannelMode */
static const value_string ansi_map_ControlChannelMode_vals[]  = {
    {   0, "Unknown"},
    {   1, "MS is in Analog CC Mode"},
    {   2, "MS is in Digital CC Mode"},
    {   3, "MS is in NAMPS CC Mode"},
	{	0, NULL }
};

/*Table 6.5.2.ay TDMABandwidth value */
static const value_string ansi_map_TDMABandwidth_vals[]  = {
    {   0, "Half-Rate Digital Traffic Channel Only"},
    {   1, "Full-Rate Digital Traffic Channel Only"},
    {   2, "Half-Rate or Full-rate Digital Traffic Channel - Full-Rate Preferred"},
    {   3, "Half-rate or Full-rate Digital Traffic Channel - Half-rate Preferred"},
    {   4, "Double Full-Rate Digital Traffic Channel Only"},
    {   5, "Triple Full-Rate Digital Traffic Channel Only"},
    {   6, "Reserved. Treat reserved values the same as value 1 - Full-Rate Digital Traffic Channel Only"},
    {   7, "Reserved. Treat reserved values the same as value 1 - Full-Rate Digital Traffic Channel Only"},
    {   8, "Reserved. Treat reserved values the same as value 1 - Full-Rate Digital Traffic Channel Only"},
    {   9, "Reserved. Treat reserved values the same as value 1 - Full-Rate Digital Traffic Channel Only"},
    {   10, "Reserved. Treat reserved values the same as value 1 - Full-Rate Digital Traffic Channel Only"},
    {   11, "Reserved. Treat reserved values the same as value 1 - Full-Rate Digital Traffic Channel Only"},
    {   12, "Reserved. Treat reserved values the same as value 1 - Full-Rate Digital Traffic Channel Only"},
    {   13, "Reserved. Treat reserved values the same as value 1 - Full-Rate Digital Traffic Channel Only"},
    {   14, "Reserved. Treat reserved values the same as value 1 - Full-Rate Digital Traffic Channel Only"},
    {   15, "Reserved. Treat reserved values the same as value 1 - Full-Rate Digital Traffic Channel Only"},
	{	0, NULL }

};
/* 6.5.2.bw CallingPartyName N.S0012-0 v 1.0*/

/* Presentation Status (octet 1, bits A and B) */
static const value_string ansi_map_Presentation_Status_vals[]  = {
    {   0, "Presentation allowed"},
    {   1, "Presentation restricted"},
    {   2, "Blocking toggle"},
    {   3, "No indication"},
	{	0, NULL }
};
/* Availability (octet 1, bit E) N.S0012-0 v 1.0*/
static const true_false_string ansi_map_Availability_bool_val  = {
  "Name not available",
  "Name available/unknown"
};
/* 6.5.2.bx DisplayText N.S0012-0 v 1.0*/
/* a. Refer to ANSI T1.610 for field encoding. */

/* 6.5.2.bz ServiceID
Service Identifier (octets 1 to n)
0 Not used.
1 Calling Name Presentation - No RND.
2 Calling Name Presentation with RND.
 */


/* 6.5.2.df TriggerCapability */


static const true_false_string ansi_map_triggercapability_bool_val  = {
  "triggers can be armed by the TriggerAddressList parameter",
  "triggers cannot be armed by the TriggerAddressList parameter"
};

static void
dissect_ansi_map_triggercapability(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){

	int offset = 0;
    proto_item *item;
    proto_tree *subtree;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_originationtriggers);


	/* O_No_Answer (ONA) (octet 1, bit H)*/
	proto_tree_add_item(subtree, hf_ansi_map_triggercapability_ona, tvb, offset,	1, FALSE);
	/* O_Disconnect (ODISC) (octet 1, bit G)*/
	proto_tree_add_item(subtree, hf_ansi_map_triggercapability_odisc, tvb, offset,	1, FALSE);
	/* O_Answer (OANS) (octet 1, bit F)*/
	proto_tree_add_item(subtree, hf_ansi_map_triggercapability_oans, tvb, offset,	1, FALSE);
	/* Origination_Attempt_Authorized (OAA) (octet 1, bit E)*/
	proto_tree_add_item(subtree, hf_ansi_map_triggercapability_oaa, tvb, offset,	1, FALSE);
	/* Revertive_Call (RvtC) (octet 1, bit D)*/
	proto_tree_add_item(subtree, hf_ansi_map_triggercapability_rvtc, tvb, offset,	1, FALSE);
	/* All_Calls (All) (octet 1, bit C)*/
	proto_tree_add_item(subtree, hf_ansi_map_triggercapability_all, tvb, offset,	1, FALSE);
	/* K-digit (K-digit) (octet 1, bit B)*/
	proto_tree_add_item(subtree, hf_ansi_map_triggercapability_kdigit, tvb, offset,	1, FALSE);
	/* Introducing Star/Pound (INIT) (octet 1, bit A) */
	proto_tree_add_item(subtree, hf_ansi_map_triggercapability_init, tvb, offset,	1, FALSE);
	offset++;


	/* O_Called_Party_Busy (OBSY) (octet 2, bit H)*/
	/* Called_Routing_Address_Available (CdRAA) (octet 2, bit G)*/
	/* Initial_Termination (IT) (octet 2, bit F)*/
	/* Calling_Routing_Address_Available (CgRAA)*/
	/* Advanced_Termination (AT) (octet 2, bit D)*/
	/* Prior_Agreement (PA) (octet 2, bit C)*/
	/* Unrecognized_Number (Unrec) (octet 2, bit B)*/
	/* Call Types (CT) (octet 2, bit A)*/

	/* */
	/* */
	/* */
	/* T_Disconnect (TDISC) (octet 3, bit E)*/
	/* T_Answer (TANS) (octet 3, bit D)*/
	/* T_No_Answer (TNA) (octet 3, bit C)*/
	/* T_Busy (TBusy) (octet 3, bit B)*/
	/* Terminating_Resource_Available (TRA) (octet 3, bit A) */

}
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

/* 6.5.2.lB AKeyProtocolVersion
	N.S0011-0 v 1.0
 */
static const value_string ansi_map_AKeyProtocolVersion_vals[]  = {
    {   0, "Not used"},
    {   1, "A-key Generation not supported"},
    {   2, "Diffie Hellman with 768-bit modulus, 160-bit primitive, and 160-bit exponents"},
    {   3, "Diffie Hellman with 512-bit modulus, 160-bit primitive, and 160-bit exponents"},
    {   4, "Diffie Hellman with 768-bit modulus, 32-bit primitive, and 160-bit exponents"},
	{	0, NULL }
};
/* 6.5.2.sB OTASP_ResultCode
	N.S0011-0 v 1.0
 */
static const value_string ansi_map_OTASP_ResultCode_vals[]  = {
    {   0, "Accepted - Successful"},
    {   1, "Rejected - Unknown cause."},
    {   2, "Computation Failure - E.g., unable to compute A-key"},
    {   3, "CSC Rejected - CSC challenge failure"},
    {   4, "Unrecognized OTASPCallEntry"},
    {   5, "Unsupported AKeyProtocolVersion(s)"},
    {   6, "Unable to Commit"},
	{	0, NULL }
};

/*6.5.2.wB ServiceIndicator
	N.S0011-0 v 1.0
 */
static const value_string ansi_map_ServiceIndicator_vals[]  = {
    {   0, "Undefined Service"},
    {   1, "CDMA OTASP Service"},
    {   2, "TDMA OTASP Service"},
    {   3, "CDMA OTAPA Service"},
	{	0, NULL }
};

/* 6.5.2.xB SignalingMessageEncryptionReport
	N.S0011-0 v 1.0
 */
static const value_string ansi_map_SMEReport_vals[]  = {
    {   0, "Not used"},
    {   1, "Signaling Message Encryption enabling not attempted"},
    {   2, "Signaling Message Encryption enabling no response"},
    {   3, "Signaling Message Encryption is enabled"},
    {   4, "Signaling Message Encryption enabling failed"},
	{	0, NULL }
};

/* 6.5.2.zB VoicePrivacyReport
	N.S0011-0 v 1.0
 */
static const value_string ansi_map_VoicePrivacyReport_vals[]  = {
    {   0, "Not used"},
    {   1, "Voice Privacy not attempted"},
    {   2, "Voice Privacy no response"},
    {   3, "Voiec Privacy is active"},
    {   4, "Voice Privacy failed"},
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
	  /* N.S0011-0 v 1.0 */
  case  56: /*OTASP Request 6.4.2.CC*/
	  offset = dissect_ansi_map_OTASPRequest(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
	  /*End N.S0011-0 v 1.0 */
  case  57: /*Information Backward*/
	  offset = offset;
	  break;
	  /*  N.S0008-0 v 1.0 */
  case  58: /*Change Facilities*/
	  offset = dissect_ansi_map_ChangeFacilities(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  59: /*Change Service*/
	  offset = dissect_ansi_map_ChangeService(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
	  /* End N.S0008-0 v 1.0 */	
  case  60: /*Parameter Request*/
	  offset = dissect_ansi_map_ParameterRequest(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  61: /*TMSI Directive*/
	  offset = dissect_ansi_map_TMSIDirective(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
	  /*End  N.S0010-0 v 1.0 */
  case  62: /*Reserved 62*/
	  proto_tree_add_text(tree, tvb, offset, -1, "Unknown invokeData blob(Reserved 62)");
	  break;
  case  63: /*Service Request N.S0012-0 v 1.0*/
	  offset = dissect_ansi_map_ServiceRequest(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
	  /* N.S0013 */
  case  64: /*Analyzed Information Request*/
	  offset = dissect_ansi_map_AnalyzedInformation(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  65: /*Connection Failure Report*/
	  offset = dissect_ansi_map_ConnectionFailureReport(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  66: /*Connect Resource*/
	  offset = dissect_ansi_map_ConnectResource(TRUE, tvb, offset, pinfo, tree, -1);
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
	  offset = dissect_ansi_map_Modify(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  71: /*Reset Timer*/
	  /*No Data*/
	  break;
  case  72: /*Search*/
	  offset = dissect_ansi_map_Search(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  73: /*Seize Resource*/
	  offset = dissect_ansi_map_SeizeResource(TRUE, tvb, offset, pinfo, tree, -1);
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
	  /*  N.S0008-0 v 1.0 */
  case  58: /*Change Facilities*/
	  offset = dissect_ansi_map_ChangeFacilitiesRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  59: /*Change Service*/
	  offset = dissect_ansi_map_ChangeServiceRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  61: /*TMSI Directive*/
	  offset = dissect_ansi_map_TMSIDirectiveRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  63: /*Service Request*/
	  offset = dissect_ansi_map_ServiceRequestRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  68: /*Facility Selected and Available*/
	  offset = dissect_ansi_map_FacilitySelectedAndAvailableRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  70: /*Modify*/
	  offset = dissect_ansi_map_ModifyRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  72: /*Search*/
	  offset = dissect_ansi_map_SearchRes(TRUE, tvb, offset, pinfo, tree, -1);;
	  break;
  case  73: /*Seize Resource*/
	  offset = dissect_ansi_map_SeizeResourceRes(TRUE, tvb, offset, pinfo, tree, -1);
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
	{ &hf_ansi_map_trans_cap_prof,
      { "Profile (PROF)", "ansi_map.trans_cap_prof",
        FT_BOOLEAN, 8, TFS(&ansi_map_trans_cap_prof_bool_val),0x01,
        "Profile (PROF)", HFILL }},
	{ &hf_ansi_map_trans_cap_busy,
      { "Busy Detection (BUSY)", "ansi_map.trans_cap_busy",
        FT_BOOLEAN, 8, TFS(&ansi_map_trans_cap_busy_bool_val),0x02,
        "Busy Detection (BUSY)", HFILL }},
	{ &hf_ansi_map_trans_cap_ann,
      { "Announcements (ANN)", "ansi_map.trans_cap_ann",
        FT_BOOLEAN, 8, TFS(&ansi_map_trans_cap_ann_bool_val),0x04,
        "Announcements (ANN)", HFILL }},
	{ &hf_ansi_map_trans_cap_rui,
      { "Remote User Interaction (RUI)", "ansi_map.trans_cap_rui",
        FT_BOOLEAN, 8, TFS(&ansi_map_trans_cap_rui_bool_val),0x08,
        "Remote User Interaction (RUI)", HFILL }},
	{ &hf_ansi_map_trans_cap_spini,
      { "Subscriber PIN Intercept (SPINI)", "ansi_map.trans_cap_spini",
        FT_BOOLEAN, 8, TFS(&ansi_map_trans_cap_spini_bool_val),0x10,
        "Subscriber PIN Intercept (SPINI)", HFILL }},
	{ &hf_ansi_map_trans_cap_uzci,
      { "UZ Capability Indicator (UZCI)", "ansi_map.trans_cap_uzci",
        FT_BOOLEAN, 8, TFS(&ansi_map_trans_cap_uzci_bool_val),0x20,
        "UZ Capability Indicator (UZCI)", HFILL }},
	{ &hf_ansi_map_trans_cap_ndss,
      { "NDSS Capability (NDSS)", "ansi_map.trans_cap_ndss",
        FT_BOOLEAN, 8, TFS(&ansi_map_trans_cap_ndss_bool_val),0x40,
        "NDSS Capability (NDSS)", HFILL }},		
	{ &hf_ansi_map_trans_cap_nami,
      { "NAME Capability Indicator (NAMI)", "ansi_map.trans_cap_nami",
        FT_BOOLEAN, 8, TFS(&ansi_map_trans_cap_nami_bool_val),0x80,
        "NAME Capability Indicator (NAMI)", HFILL }},
	{ &hf_ansi_trans_cap_multerm,
      { "Multiple Terminations", "ansi_map.trans_cap_multerm",
        FT_UINT8, BASE_DEC, VALS(ansi_map_trans_cap_multerm_vals), 0x0f,
        "Multiple Terminations", HFILL }},
	{ &hf_ansi_trans_cap_tl,
      { "TerminationList (TL)", "ansi_map.trans_cap_tl",
        FT_BOOLEAN, 8, TFS(&ansi_map_trans_cap_nami_bool_val),0x10,
        "TerminationList (TL)", HFILL }},
	{ &hf_ansi_map_MarketID,
      { "MarketID", "ansi_map.marketid",
        FT_UINT16, BASE_DEC, NULL, 0,
        "MarketID", HFILL }},
	{ &hf_ansi_map_swno,
      { "Switch Number (SWNO)", "ansi_map.swno",
        FT_UINT8, BASE_DEC, NULL, 0,
        "Switch Number (SWNO)", HFILL }},
	{ &hf_ansi_map_idno,
      { "ID Number", "ansi_map.idno",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ID Number", HFILL }},
	{ &hf_ansi_map_segcount,
      { "Segment Counter", "ansi_map.segcount",
        FT_UINT8, BASE_DEC, NULL, 0,
        "Segment Counter", HFILL }},
	{ &hf_ansi_map_originationtriggers_all,
      { "All Origination (All)", "ansi_map.originationtriggers.all",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_all_bool_val),0x01,
        "All Origination (All)", HFILL }},
	{ &hf_ansi_map_originationtriggers_local,
      { "Local", "ansi_map.originationtriggers.all",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_local_bool_val),0x02,
        "Local", HFILL }},
	{ &hf_ansi_map_originationtriggers_ilata,
      { "Intra-LATA Toll (ILATA)", "ansi_map.originationtriggers.ilata",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_ilata_bool_val),0x04,
        "Intra-LATA Toll (ILATA)", HFILL }},
	{ &hf_ansi_map_originationtriggers_olata,
      { "Inter-LATA Toll (OLATA)", "ansi_map.originationtriggers.olata",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_olata_bool_val),0x08,
        "Inter-LATA Toll (OLATA)", HFILL }},
	{ &hf_ansi_map_originationtriggers_int,
      { "International (Int'l )", "ansi_map.originationtriggers.int",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_int_bool_val),0x10,
        "International (Int'l )", HFILL }},
	{ &hf_ansi_map_originationtriggers_wz,
      { "World Zone (WZ)", "ansi_map.originationtriggers.wz",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_wz_bool_val),0x20,
        "World Zone (WZ)", HFILL }},
	{ &hf_ansi_map_originationtriggers_unrec,
      { "Unrecognized Number (Unrec)", "ansi_map.originationtriggers.unrec",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_unrec_bool_val),0x40,
        "Unrecognized Number (Unrec)", HFILL }},
	{ &hf_ansi_map_originationtriggers_rvtc,
      { "Revertive Call (RvtC)", "ansi_map.originationtriggers.rvtc",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_rvtc_bool_val),0x80,
        "Revertive Call (RvtC)", HFILL }},
	{ &hf_ansi_map_originationtriggers_star,
      { "Star", "ansi_map.originationtriggers.star",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_star_bool_val),0x01,
        "Star", HFILL }},
	{ &hf_ansi_map_originationtriggers_ds,
      { "Double Star (DS)", "ansi_map.originationtriggers.ds",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_ds_bool_val),0x02,
        "Double Star (DS)", HFILL }},
	{ &hf_ansi_map_originationtriggers_pound,
      { "Pound", "ansi_map.originationtriggers.pound",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_pound_bool_val),0x04,
        "Pound", HFILL }},
	{ &hf_ansi_map_originationtriggers_dp,
      { "Double Pound (DP)", "ansi_map.originationtriggers.dp",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_dp_bool_val),0x08,
        "Double Pound (DP)", HFILL }},
	{ &hf_ansi_map_originationtriggers_pa,
      { "Prior Agreement (PA)", "ansi_map.originationtriggers.pa",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_pa_bool_val),0x10,
        "Prior Agreement (PA)", HFILL }},
	{ &hf_ansi_map_originationtriggers_nodig,
      { "No digits", "ansi_map.originationtriggers.nodig",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_nodig_bool_val),0x01,
        "No digits", HFILL }},
	{ &hf_ansi_map_originationtriggers_onedig,
      { "1 digit", "ansi_map.originationtriggers.onedig",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_onedig_bool_val),0x02,
        "1 digit", HFILL }},
	{ &hf_ansi_map_originationtriggers_twodig,
      { "2 digits", "ansi_map.originationtriggers.twodig",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_twodig_bool_val),0x04,
        "2 digits", HFILL }},
	{ &hf_ansi_map_originationtriggers_threedig,
      { "3 digits", "ansi_map.originationtriggers.threedig",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_threedig_bool_val),0x08,
        "3 digits", HFILL }},
	{ &hf_ansi_map_originationtriggers_fourdig,
      { "4 digits", "ansi_map.originationtriggers.fourdig",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_fourdig_bool_val),0x10,
        "4 digits", HFILL }},
	{ &hf_ansi_map_originationtriggers_fivedig,
      { "5 digits", "ansi_map.originationtriggers.fivedig",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_fivedig_bool_val),0x20,
        "5 digits", HFILL }},
	{ &hf_ansi_map_originationtriggers_sixdig,
      { "6 digits", "ansi_map.originationtriggers.sixdig",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_sixdig_bool_val),0x40,
        "6 digits", HFILL }},
	{ &hf_ansi_map_originationtriggers_sevendig,
      { "7 digits", "ansi_map.originationtriggers.sevendig",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_sevendig_bool_val),0x80,
        "7 digits", HFILL }},
	{ &hf_ansi_map_originationtriggers_eightdig,
      { "8 digits", "ansi_map.originationtriggers.eight",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_eightdig_bool_val),0x01,
        "8 digits", HFILL }},
	{ &hf_ansi_map_originationtriggers_ninedig,
      { "9 digits", "ansi_map.originationtriggers.nine",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_ninedig_bool_val),0x02,
        "9 digits", HFILL }},
	{ &hf_ansi_map_originationtriggers_tendig,
      { "10 digits", "ansi_map.originationtriggers.ten",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_tendig_bool_val),0x04,
        "10 digits", HFILL }},
	{ &hf_ansi_map_originationtriggers_elevendig,
      { "11 digits", "ansi_map.originationtriggers.eleven",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_elevendig_bool_val),0x08,
        "11 digits", HFILL }},
	{ &hf_ansi_map_originationtriggers_thwelvedig,
      { "12 digits", "ansi_map.originationtriggers.thwelv",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_thwelvdig_bool_val),0x10,
        "12 digits", HFILL }},
	{ &hf_ansi_map_originationtriggers_thirteendig,
      { "13 digits", "ansi_map.originationtriggers.thirteen",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_thirteendig_bool_val),0x20,
        "13 digits", HFILL }},
	{ &hf_ansi_map_originationtriggers_fourteendig,
      { "14 digits", "ansi_map.originationtriggers.fourteen",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_fourteendig_bool_val),0x40,
        "14 digits", HFILL }},
	{ &hf_ansi_map_originationtriggers_fifteendig,
      { "15 digits", "ansi_map.originationtriggers.fifteen",
        FT_BOOLEAN, 8, TFS(&ansi_map_originationtriggers_fifteendig_bool_val),0x80,
        "15 digits", HFILL }},

	{ &hf_ansi_map_triggercapability_init,
      { "Introducing Star/Pound (INIT)", "ansi_map.triggercapability.init",
        FT_BOOLEAN, 8, TFS(&ansi_map_triggercapability_bool_val),0x01,
        "Introducing Star/Pound (INIT)", HFILL }},
	{ &hf_ansi_map_triggercapability_kdigit,
      { "K-digit (K-digit)", "ansi_map.triggercapability.kdigit",
        FT_BOOLEAN, 8, TFS(&ansi_map_triggercapability_bool_val),0x02,
        "K-digit (K-digit)", HFILL }},
	{ &hf_ansi_map_triggercapability_all,
      { "All_Calls (All)", "ansi_map.triggercapability.all",
        FT_BOOLEAN, 8, TFS(&ansi_map_triggercapability_bool_val),0x04,
        "All_Calls (All)", HFILL }},
	{ &hf_ansi_map_triggercapability_rvtc,
      { "Revertive_Call (RvtC)", "ansi_map.triggercapability.rvtc",
        FT_BOOLEAN, 8, TFS(&ansi_map_triggercapability_bool_val),0x08,
        "Revertive_Call (RvtC)", HFILL }},
	{ &hf_ansi_map_triggercapability_oaa,
      { "Origination_Attempt_Authorized (OAA)", "ansi_map.triggercapability.oaa",
        FT_BOOLEAN, 8, TFS(&ansi_map_triggercapability_bool_val),0x10,
        "Origination_Attempt_Authorized (OAA)", HFILL }},
	{ &hf_ansi_map_triggercapability_oans,
      { "O_Answer (OANS)", "ansi_map.triggercapability.oans",
        FT_BOOLEAN, 8, TFS(&ansi_map_triggercapability_bool_val),0x20,
        "O_Answer (OANS)", HFILL }},
	{ &hf_ansi_map_triggercapability_odisc,
      { "O_Disconnect (ODISC)", "ansi_map.triggercapability.odisc",
        FT_BOOLEAN, 8, TFS(&ansi_map_triggercapability_bool_val),0x40,
        "O_Disconnect (ODISC)", HFILL }},
	{ &hf_ansi_map_triggercapability_ona,
      { "O_No_Answer (ONA)", "ansi_map.triggercapability.ona",
        FT_BOOLEAN, 8, TFS(&ansi_map_triggercapability_bool_val),0x80,
        "O_No_Answer (ONA)", HFILL }},

#include "packet-ansi_map-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	  &ett_ansi_map,
	  &ett_mintype,
	  &ett_digitstype,
	  &ett_billingid,
	  &ett_mscid,
	  &ett_originationtriggers,
	  &ett_transactioncapability,
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


