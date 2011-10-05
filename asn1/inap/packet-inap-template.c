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
#include <epan/oids.h>
#include <epan/expert.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-inap.h"
#include "packet-q931.h"
#include "packet-e164.h"
#include "packet-isup.h"
#include "packet-tcap.h"
#include "packet-dap.h"
#include "packet-dsp.h"

#define PNAME  "Intelligent Network Application Protocol"
#define PSNAME "INAP"
#define PFNAME "inap"

/* Initialize the protocol and registered fields */
static int proto_inap = -1;

/* include constants */
#include "packet-inap-val.h"

#include "packet-inap-hf.c"

#define MAX_SSN 254
static range_t *global_ssn_range;

static dissector_handle_t	inap_handle;
static dissector_handle_t	data_handle;

/* Global variables */
static guint32 opcode=0;
static guint32 errorCode=0;
static const char *obj_id = NULL;

static int inap_opcode_type;
#define INAP_OPCODE_INVOKE        1
#define INAP_OPCODE_RETURN_RESULT 2
#define INAP_OPCODE_RETURN_ERROR  3
#define INAP_OPCODE_REJECT        4

/* Initialize the subtree pointers */
static gint ett_inap = -1;
static gint ett_inapisup_parameter = -1;
static gint ett_inap_HighLayerCompatibility = -1;
#include "packet-inap-ett.c"

#include "packet-inap-table.c"

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

#include "packet-inap-table2.c"


static guint8 inap_pdu_type = 0;
static guint8 inap_pdu_size = 0;


static void
dissect_inap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
    proto_item		*item=NULL;
    proto_tree		*tree=NULL;
	int				offset = 0;
	guint			length;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	length = tvb_length(tvb);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "INAP");

    /* create display subtree for the protocol */
    if(parent_tree){
       item = proto_tree_add_item(parent_tree, proto_inap, tvb, 0, -1, FALSE);
       tree = proto_item_add_subtree(item, ett_inap);
    }
	inap_pdu_type = tvb_get_guint8(tvb, offset)&0x0f;
	/* Get the length and add 2 */
	inap_pdu_size = tvb_get_guint8(tvb, offset+1)+2;
	opcode = 0;
    offset = dissect_inap_ROS(TRUE, tvb, offset, &asn1_ctx, tree, -1);


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

    static gboolean inap_prefs_initialized = FALSE;
    static range_t *ssn_range;

    if (!inap_prefs_initialized) {
	    inap_prefs_initialized = TRUE;
	    inap_handle = find_dissector("inap");
		data_handle = find_dissector("data");
	    oid_add_from_string("Core-INAP-CS1-Codes","0.4.0.1.1.0.3.0");
		oid_add_from_string("iso(1) identified-organization(3) icd-ecma(12) member-company(2) 1107 oen(3) inap(3) extensions(2)","1.3.12.2.1107.3.3.2");
		oid_add_from_string("alcatel(1006)","1.3.12.2.1006.64");
		oid_add_from_string("Siemens (1107)","1.3.12.2.1107");
		oid_add_from_string("iso(1) member-body(2) gb(826) national(0) ericsson(1249) inDomain(51) inNetwork(1) inNetworkcapabilitySet1plus(1) ","1.2.826.0.1249.51.1.1");
    }
    else {
	    range_foreach(ssn_range, range_delete_callback);
            g_free(ssn_range);
    }

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
	&ett_inap_HighLayerCompatibility,
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

  inap_module = prefs_register_protocol(proto_inap, proto_reg_handoff_inap);

  prefs_register_obsolete_preference(inap_module, "tcap.itu_ssn");

  prefs_register_obsolete_preference(inap_module, "tcap.itu_ssn1");

  prefs_register_range_preference(inap_module, "ssn", "TCAP SSNs",
				  "TCAP Subsystem numbers used for INAP",
				  &global_ssn_range, MAX_SSN);
}



