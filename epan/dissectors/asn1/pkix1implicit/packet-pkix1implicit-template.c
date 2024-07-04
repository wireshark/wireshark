/* packet-pkix1implicit.c
 * Routines for PKIX1Implitic packet dissection
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

#include <epan/asn1.h>
#include "packet-ber.h"
#include "packet-pkix1implicit.h"
#include "packet-pkix1explicit.h"
#include "packet-x509ce.h"

#define PNAME  "PKIX1Implicit"
#define PSNAME "PKIX1IMPLICIT"
#define PFNAME "pkix1implicit"

void proto_register_pkix1implicit(void);
void proto_reg_handoff_pkix1implicit(void);

/* Initialize the protocol and registered fields */
static int proto_pkix1implicit;
#include "packet-pkix1implicit-hf.c"

/* Initialize the subtree pointers */
#include "packet-pkix1implicit-ett.c"


int
dissect_pkix1implicit_ReasonFlags(bool implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x509ce_ReasonFlags(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}
int
dissect_pkix1implicit_GeneralName(bool implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x509ce_GeneralName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}

#include "packet-pkix1implicit-fn.c"


/*--- proto_register_pkix1implicit ----------------------------------------------*/
void proto_register_pkix1implicit(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-pkix1implicit-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
#include "packet-pkix1implicit-ettarr.c"
  };

  /* Register protocol */
  proto_pkix1implicit = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_pkix1implicit, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_pkix1implicit -------------------------------------------*/
void proto_reg_handoff_pkix1implicit(void) {
#include "packet-pkix1implicit-dis-tab.c"
}

