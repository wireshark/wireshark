/* packet-dap.c
 * Routines for X.511 (X.500 Directory Asbtract Service) and X.519 DAP  packet dissection
 * Graeme Lunt 2005
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/oids.h>
#include <epan/asn1.h>
#include <epan/proto_data.h>

#include "packet-ber.h"
#include "packet-acse.h"
#include "packet-ros.h"
#include "packet-idmp.h"

#include "packet-x509if.h"
#include "packet-x509af.h"
#include "packet-x509sat.h"
#include "packet-crmf.h"

#include "packet-dsp.h"
#include "packet-disp.h"
#include "packet-dap.h"
#include <epan/strutil.h>

/* we don't have a separate dissector for X519 -
   most of DAP is defined in X511 */
#define PNAME  "X.519 Directory Access Protocol"
#define PSNAME "DAP"
#define PFNAME "dap"

void proto_register_dap(void);
void proto_reg_handoff_dap(void);

/* Initialize the protocol and registered fields */
static int proto_dap;


#include "packet-dap-hf.c"

/* Initialize the subtree pointers */
static int ett_dap;
#include "packet-dap-ett.c"

static expert_field ei_dap_anonymous;

#include "packet-dap-val.h"

#include "packet-dap-table.c"   /* operation and error codes */

#include "packet-dap-fn.c"

#include "packet-dap-table11.c" /* operation argument/result dissectors */
#include "packet-dap-table21.c" /* error dissector */

static const ros_info_t dap_ros_info = {
  "DAP",
  &proto_dap,
  &ett_dap,
  dap_opr_code_string_vals,
  dap_opr_tab,
  dap_err_code_string_vals,
  dap_err_tab
};


/*--- proto_register_dap -------------------------------------------*/
void proto_register_dap(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {
#include "packet-dap-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_dap,
#include "packet-dap-ettarr.c"
  };

  static ei_register_info ei[] = {
    { &ei_dap_anonymous, { "dap.anonymous", PI_PROTOCOL, PI_NOTE, "Anonymous", EXPFILL }},
  };

  module_t *dap_module;
  expert_module_t* expert_dap;

  /* Register protocol */
  proto_dap = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_dap, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_dap = expert_register_protocol(proto_dap);
  expert_register_field_array(expert_dap, ei, array_length(ei));

  /* Register our configuration options for DAP, particularly our port */

  dap_module = prefs_register_protocol_subtree("OSI/X.500", proto_dap, NULL);

  prefs_register_obsolete_preference(dap_module, "tcp.port");

  prefs_register_static_text_preference(dap_module, "tcp_port_info",
            "The TCP ports used by the DAP protocol should be added to the TPKT preference \"TPKT TCP ports\", or the IDMP preference \"IDMP TCP Port\", or by selecting \"TPKT\" as the \"Transport\" protocol in the \"Decode As\" dialog.",
            "DAP TCP Port preference moved information");
}


/*--- proto_reg_handoff_dap --- */
void proto_reg_handoff_dap(void) {

  /* #include "packet-dap-dis-tab.c" */

  /* APPLICATION CONTEXT */

  oid_add_from_string("id-ac-directory-access","2.5.3.1");

  /* ABSTRACT SYNTAXES */

  /* Register DAP with ROS (with no use of RTSE) */
  register_ros_protocol_info("2.5.9.1", &dap_ros_info, 0, "id-as-directory-access", false);

  register_idmp_protocol_info("2.5.33.0", &dap_ros_info, 0, "dap-ip");

  /* AttributeValueAssertions */
  x509if_register_fmt(hf_dap_equality, "=");
  x509if_register_fmt(hf_dap_greaterOrEqual, ">=");
  x509if_register_fmt(hf_dap_lessOrEqual, "<=");
  x509if_register_fmt(hf_dap_approximateMatch, "=~");
  /* AttributeTypes */
  x509if_register_fmt(hf_dap_present, "= *");

}
