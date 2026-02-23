/* packet-logotypecertextn.c
 * Routines for RFC3709 Logotype Certificate Extensions packet dissection
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
#include <wsutil/array.h>

#include "packet-ber.h"
#include "packet-x509af.h"

void proto_register_logotypecertextn(void);
void proto_reg_handoff_logotypecertextn(void);

/* Initialize the protocol and registered fields */
static int proto_logotypecertextn;
#include "packet-logotypecertextn-hf.c"

/* Initialize the subtree pointers */
#include "packet-logotypecertextn-ett.c"


#include "packet-logotypecertextn-fn.c"


/*--- proto_register_logotypecertextn ----------------------------------------------*/
void proto_register_logotypecertextn(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-logotypecertextn-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
#include "packet-logotypecertextn-ettarr.c"
  };

  /* Register protocol */
  proto_logotypecertextn = proto_register_protocol("Logotype Certificate Extensions", "LogotypeCertExtn", "logotypecertextn");

  /* Register fields and subtrees */
  proto_register_field_array(proto_logotypecertextn, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_logotypecertextn -------------------------------------------*/
void proto_reg_handoff_logotypecertextn(void) {
#include "packet-logotypecertextn-dis-tab.c"
}

