/* packet-ns_cert_exts.c
 * Routines for NetScape Certificate Extensions packet dissection
 *   Ronnie Sahlberg 2004
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

#include "packet-ber.h"

#define PNAME  "NetScape Certificate Extensions"
#define PSNAME "NS_CERT_EXTS"
#define PFNAME "ns_cert_exts"

void proto_register_ns_cert_exts(void);
void proto_reg_handoff_ns_cert_exts(void);

/* Initialize the protocol and registered fields */
static int proto_ns_cert_exts;
#include "packet-ns_cert_exts-hf.c"

/* Initialize the subtree pointers */
#include "packet-ns_cert_exts-ett.c"

#include "packet-ns_cert_exts-fn.c"


/*--- proto_register_ns_cert_exts -------------------------------------------*/
void proto_register_ns_cert_exts(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-ns_cert_exts-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
#include "packet-ns_cert_exts-ettarr.c"
  };

  /* Register protocol */
  proto_ns_cert_exts = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_ns_cert_exts, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_ns_cert_exts ---------------------------------------*/
void proto_reg_handoff_ns_cert_exts(void) {
#include "packet-ns_cert_exts-dis-tab.c"
}

