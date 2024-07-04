/* packet-p7.c
 * Routines for X.413 (P7) packet dissection
 * Graeme Lunt 2007
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
#include <epan/oids.h>
#include <epan/asn1.h>
#include <epan/proto_data.h>

#include "packet-ber.h"
#include "packet-acse.h"
#include "packet-ros.h"
#include "packet-rtse.h"
#include "packet-p7.h"

#include "packet-p1.h"
#include <epan/strutil.h>

#define PNAME  "X.413 Message Store Service"
#define PSNAME "P7"
#define PFNAME "p7"

void proto_register_p7(void);
void proto_reg_handoff_p7(void);

static int seqno;

/* Initialize the protocol and registered fields */
static int proto_p7;

#include "packet-p7-val.h"

#include "packet-p7-hf.c"

/* Initialize the subtree pointers */
static int ett_p7;
#include "packet-p7-ett.c"

#include "packet-p7-table.c"   /* operation and error codes */

#include "packet-p7-fn.c"

#include "packet-p7-table11.c" /* operation argument/result dissectors */
#include "packet-p7-table21.c" /* error dissector */

static const ros_info_t p7_ros_info = {
  "P7",
  &proto_p7,
  &ett_p7,
  p7_opr_code_string_vals,
  p7_opr_tab,
  p7_err_code_string_vals,
  p7_err_tab
};


/*--- proto_register_p7 -------------------------------------------*/
void proto_register_p7(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {
#include "packet-p7-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_p7,
#include "packet-p7-ettarr.c"
  };
  module_t *p7_module;

  /* Register protocol */
  proto_p7 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_p7, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register our configuration options for P7, particularly our port */

  p7_module = prefs_register_protocol_subtree("OSI/X.400", proto_p7, NULL);

  prefs_register_obsolete_preference(p7_module, "tcp.port");

  prefs_register_static_text_preference(p7_module, "tcp_port_info",
            "The TCP ports used by the P7 protocol should be added to the TPKT preference \"TPKT TCP ports\", or by selecting \"TPKT\" as the \"Transport\" protocol in the \"Decode As\" dialog.",
            "P7 TCP Port preference moved information");
}


/*--- proto_reg_handoff_p7 --- */
void proto_reg_handoff_p7(void) {

  #include "packet-p7-dis-tab.c"

  /* APPLICATION CONTEXT */

  oid_add_from_string("id-ac-ms-access","2.6.0.1.11");
  oid_add_from_string("id-ac-ms-reliable-access","2.6.0.1.12");

  /* ABSTRACT SYNTAXES */

  /* Register P7 with ROS (with no use of RTSE) */
  register_ros_protocol_info("2.6.0.2.9", &p7_ros_info, 0, "id-as-ms", false);
  register_ros_protocol_info("2.6.0.2.5", &p7_ros_info, 0, "id-as-mrse", false);
  register_ros_protocol_info("2.6.0.2.1", &p7_ros_info, 0, "id-as-msse", false);
}
