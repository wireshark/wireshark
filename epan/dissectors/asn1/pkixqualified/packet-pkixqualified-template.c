/* packet-pkixqualified.c
 * Routines for RFC3739 PKIXqualified packet dissection
 *  Ronnie Sahlberg 2004
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
#include "packet-pkixqualified.h"
#include "packet-x509af.h"
#include "packet-x509ce.h"
#include "packet-x509sat.h"

#define PNAME  "PKIX Qualified"
#define PSNAME "PKIXQUALIFIED"
#define PFNAME "pkixqualified"

void proto_register_pkixqualified(void);
void proto_reg_handoff_pkixqualified(void);


/* Initialize the protocol and registered fields */
static int proto_pkixqualified;
#include "packet-pkixqualified-hf.c"

/* Initialize the subtree pointers */
#include "packet-pkixqualified-ett.c"

static const char *object_identifier_id;

#include "packet-pkixqualified-fn.c"


/*--- proto_register_pkixqualified ----------------------------------------------*/
void proto_register_pkixqualified(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-pkixqualified-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
#include "packet-pkixqualified-ettarr.c"
  };

  /* Register protocol */
  proto_pkixqualified = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_pkixqualified, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_pkixqualified -------------------------------------------*/
void proto_reg_handoff_pkixqualified(void) {
#include "packet-pkixqualified-dis-tab.c"
}

