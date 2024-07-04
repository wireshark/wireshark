/* packet-pkixac.c
 *
 * Routines for PKIXAttributeCertificate (RFC3281) packet dissection.
 *
 * Copyright 2010, Stig Bjorlykke <stig@bjorlykke.org>
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
#include "packet-pkixac.h"
#include "packet-pkix1explicit.h"
#include "packet-pkix1implicit.h"
#include "packet-x509ce.h"

#define PNAME  "PKIX Attribute Certificate"
#define PSNAME "PKIXAC"
#define PFNAME "pkixac"

void proto_register_pkixac(void);
void proto_reg_handoff_pkixac(void);

/* Initialize the protocol and registered fields */
static int proto_pkixac;
#include "packet-pkixac-hf.c"

/* Initialize the subtree pointers */
static int ett_pkixac;
#include "packet-pkixac-ett.c"

static const char *object_identifier_id;

#include "packet-pkixac-fn.c"

/*--- proto_register_pkixac ----------------------------------------------*/
void proto_register_pkixac(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-pkixac-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
	&ett_pkixac,
#include "packet-pkixac-ettarr.c"
  };

  /* Register protocol */
  proto_pkixac = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_pkixac, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

#include "packet-pkixac-syn-reg.c"

}


/*--- proto_reg_handoff_pkixac -------------------------------------------*/
void proto_reg_handoff_pkixac(void) {
#include "packet-pkixac-dis-tab.c"
}

