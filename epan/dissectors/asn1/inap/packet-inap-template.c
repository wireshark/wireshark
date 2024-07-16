/* packet-inap-template.c
 * Routines for INAP
 * Copyright 2004, Tim Endean <endeant@hotmail.com>
 * Built from the gsm-map dissector Copyright 2004, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 * References: ETSI 300 374
 * ITU Q.1218
 */

#include "config.h"

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

void proto_register_inap(void);
void proto_reg_handoff_inap(void);


/* Initialize the protocol and registered fields */
static int proto_inap;

/* include constants */
#include "packet-inap-val.h"

#include "packet-inap-hf.c"

#define MAX_SSN 254
static range_t *global_ssn_range;

static dissector_handle_t	inap_handle;

/* Global variables */
static uint32_t opcode=0;
static uint32_t errorCode=0;
static const char *obj_id;
static bool is_ExtensionField;

static int inap_opcode_type;
#define INAP_OPCODE_INVOKE        1
#define INAP_OPCODE_RETURN_RESULT 2
#define INAP_OPCODE_RETURN_ERROR  3
#define INAP_OPCODE_REJECT        4

static int hf_inap_cause_indicator;

/* Initialize the subtree pointers */
static int ett_inap;
static int ett_inapisup_parameter;
static int ett_inap_RedirectionInformation;
static int ett_inap_HighLayerCompatibility;
static int ett_inap_extension_data;
static int ett_inap_cause;
static int ett_inap_calledAddressValue;
static int ett_inap_callingAddressValue;
static int ett_inap_additionalCallingPartyNumber;
static int ett_inap_assistingSSPIPRoutingAddress;
static int ett_inap_correlationID;
static int ett_inap_number;
static int ett_inap_dialledNumber;
static int ett_inap_callingLineID;
static int ett_inap_iNServiceControlCode;
static int ett_inap_iNServiceControlCodeLow;
static int ett_inap_iNServiceControlCodeHigh;
static int ett_inap_lineID;
static int ett_inap_prefix;
static int ett_inap_iPAddressValue;
static int ett_inap_digitsResponse;

#include "packet-inap-ett.c"

static expert_field ei_inap_unknown_invokeData;
static expert_field ei_inap_unknown_returnResultData;
static expert_field ei_inap_unknown_returnErrorData;

#include "packet-inap-table.c"

#if 0
static const value_string inap_general_problem_strings[] = {
  {0,"General Problem Unrecognized Component"},
  {1,"General Problem Mistyped Component"},
  {3,"General Problem Badly Structured Component"},
  {0, NULL}
};
#endif

/* Forward declarations */
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


static uint8_t inap_pdu_type;
static uint8_t inap_pdu_size;


static int
dissect_inap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void *data _U_)
{
  proto_item		*item=NULL;
  proto_tree		*tree=NULL;
  int				offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "INAP");

  /* create display subtree for the protocol */
  if(parent_tree){
    item = proto_tree_add_item(parent_tree, proto_inap, tvb, 0, -1, ENC_NA);
    tree = proto_item_add_subtree(item, ett_inap);
  }
  inap_pdu_type = tvb_get_uint8(tvb, offset)&0x0f;
  /* Get the length and add 2 */
  inap_pdu_size = tvb_get_uint8(tvb, offset+1)+2;
  opcode = 0;
  is_ExtensionField =false;
  dissect_inap_ROS(true, tvb, offset, &asn1_ctx, tree, -1);

  return inap_pdu_size;
}

/*--- proto_reg_handoff_inap ---------------------------------------*/
static void range_delete_callback(uint32_t ssn, void *ptr _U_)
{
  if (ssn) {
    delete_itu_tcap_subdissector(ssn, inap_handle);
  }
}

static void range_add_callback(uint32_t ssn, void *ptr _U_)
{
  if (ssn) {
  add_itu_tcap_subdissector(ssn, inap_handle);
  }
}

void proto_reg_handoff_inap(void) {

  static bool inap_prefs_initialized = false;
  static range_t *ssn_range;

  if (!inap_prefs_initialized) {
    inap_prefs_initialized = true;
    oid_add_from_string("Core-INAP-CS1-Codes","0.4.0.1.1.0.3.0");
    oid_add_from_string("iso(1) identified-organization(3) icd-ecma(12) member-company(2) 1107 oen(3) inap(3) extensions(2)","1.3.12.2.1107.3.3.2");
    oid_add_from_string("alcatel(1006)","1.3.12.2.1006.64");
    oid_add_from_string("Siemens (1107)","1.3.12.2.1107");
    oid_add_from_string("iso(1) member-body(2) gb(826) national(0) ericsson(1249) inDomain(51) inNetwork(1) inNetworkcapabilitySet1plus(1) ","1.2.826.0.1249.51.1.1");
  }
  else {
    range_foreach(ssn_range, range_delete_callback, NULL);
    wmem_free(wmem_epan_scope(), ssn_range);
  }

  ssn_range = range_copy(wmem_epan_scope(), global_ssn_range);

  range_foreach(ssn_range, range_add_callback, NULL);

}


void proto_register_inap(void) {
  module_t *inap_module;
  /* List of fields */
  static hf_register_info hf[] = {


    { &hf_inap_cause_indicator, /* Currently not enabled */
    { "Cause indicator", "inap.cause_indicator",
    FT_UINT8, BASE_DEC | BASE_EXT_STRING, &q850_cause_code_vals_ext, 0x7f,
    NULL, HFILL } },

#include "packet-inap-hfarr.c"
  };






  /* List of subtrees */
  static int *ett[] = {
    &ett_inap,
    &ett_inapisup_parameter,
    &ett_inap_RedirectionInformation,
    &ett_inap_HighLayerCompatibility,
    &ett_inap_extension_data,
    &ett_inap_cause,
    &ett_inap_calledAddressValue,
    &ett_inap_callingAddressValue,
    &ett_inap_additionalCallingPartyNumber,
    &ett_inap_assistingSSPIPRoutingAddress,
    &ett_inap_correlationID,
    &ett_inap_number,
    &ett_inap_dialledNumber,
    &ett_inap_callingLineID,
    &ett_inap_iNServiceControlCode,
    &ett_inap_iNServiceControlCodeLow,
    &ett_inap_iNServiceControlCodeHigh,
    &ett_inap_lineID,
    &ett_inap_prefix,
    &ett_inap_iPAddressValue,
    &ett_inap_digitsResponse,
#include "packet-inap-ettarr.c"
  };

  static ei_register_info ei[] = {
   { &ei_inap_unknown_invokeData, { "inap.unknown.invokeData", PI_MALFORMED, PI_WARN, "Unknown invokeData", EXPFILL }},
   { &ei_inap_unknown_returnResultData, { "inap.unknown.returnResultData", PI_MALFORMED, PI_WARN, "Unknown returnResultData", EXPFILL }},
   { &ei_inap_unknown_returnErrorData, { "inap.unknown.returnErrorData", PI_MALFORMED, PI_WARN, "Unknown returnResultData", EXPFILL }},
  };

  expert_module_t* expert_inap;

  /* Register protocol */
  proto_inap = proto_register_protocol(PNAME, PSNAME, PFNAME);
  inap_handle = register_dissector("inap", dissect_inap, proto_inap);
  /* Register fields and subtrees */
  proto_register_field_array(proto_inap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_inap = expert_register_protocol(proto_inap);
  expert_register_field_array(expert_inap, ei, array_length(ei));

  register_ber_oid_dissector("0.4.0.1.1.1.0.0", dissect_inap, proto_inap, "cs1-ssp-to-scp");

  /* Set default SSNs */
  range_convert_str(wmem_epan_scope(), &global_ssn_range, "106,241", MAX_SSN);

  inap_module = prefs_register_protocol(proto_inap, proto_reg_handoff_inap);

  prefs_register_obsolete_preference(inap_module, "tcap.itu_ssn");

  prefs_register_obsolete_preference(inap_module, "tcap.itu_ssn1");

  prefs_register_range_preference(inap_module, "ssn", "TCAP SSNs",
                 "TCAP Subsystem numbers used for INAP",
                 &global_ssn_range, MAX_SSN);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
