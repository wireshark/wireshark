/* packet-akp.c
 * Routines for Asymmetric Key Packages (formerly known as PKCS #8) dissection
 *
 * See <https://datatracker.ietf.org/doc/html/rfc5958>.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/asn1.h>
#include <wsutil/array.h>

#include "packet-ber.h"
#include "packet-cms.h"
#include "packet-pkcs12.h"
#include "packet-x509af.h"

#define PNAME  "Asymmetric Key Packages"
#define PSNAME "AKP"
#define PFNAME "akp"


void proto_register_akp(void);
void proto_reg_handoff_akp(void);

/* Initialize the protocol and registered fields */
static int proto_akp;

#include "packet-akp-hf.c"

/* Initialize the subtree pointers */
#include "packet-akp-ett.c"

static int dissect_PrivateKeyInfo_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);

#include "packet-akp-fn.c"

/*--- proto_register_akp ----------------------------------------------*/
void proto_register_akp(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-akp-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
#include "packet-akp-ettarr.c"
  };

  /* Register protocol */
  proto_akp = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_akp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}


/*--- proto_reg_handoff_akp -------------------------------------------*/
void proto_reg_handoff_akp(void) {
#include "packet-akp-dis-tab.c"

  register_ber_syntax_dissector("PrivateKeyInfo", proto_akp, dissect_PrivateKeyInfo_PDU);
  register_ber_syntax_dissector("EncryptedPrivateKeyInfo", proto_akp, dissect_EncryptedPrivateKeyInfo_PDU);

  register_ber_oid_syntax(".p8", NULL, "PrivateKeyInfo");
  dissector_add_string("media_type", "application/pkcs8",
    create_dissector_handle(dissect_PrivateKeyInfo_PDU, proto_akp));

  dissector_add_string("rfc7468.preeb_label", "PRIVATE KEY",
    create_dissector_handle(dissect_PrivateKeyInfo_PDU, proto_akp));
  dissector_add_string("rfc7468.preeb_label", "ENCRYPTED PRIVATE KEY",
    create_dissector_handle(dissect_EncryptedPrivateKeyInfo_PDU, proto_akp));
}
