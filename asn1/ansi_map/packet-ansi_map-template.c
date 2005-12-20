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

#include <stdio.h>
#include <string.h>

#include "packet-ansi_map.h"
#include "packet-ansi_a.h"
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

#include "packet-ansi_map-fn.c"

static int dissect_invokeData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {


  switch(OperationCode & 0x00ff){
  case  13: /*Registration Notification*/
	  offset = dissect_ansi_map_RegistrationNotification(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  47: /*OriginationRequest*/
	  offset = dissect_ansi_map_OriginationRequest(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  default:
	  proto_tree_add_text(tree, tvb, offset, -1, "Unknown invokeData blob");
	  break;
  }

  return offset;

 }

static int dissect_returnData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {


  switch(OperationCode & 0x00ff){
  case  13: /*Registration Notification*/
	  offset = dissect_ansi_map_RegistrationNotificationRes(TRUE, tvb, offset, pinfo, tree, -1);
	  break;
  case  47: /*OriginationRequest*/
	  offset = dissect_ansi_map_OriginationRequestRes(TRUE, tvb, offset, pinfo, tree, -1);
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


