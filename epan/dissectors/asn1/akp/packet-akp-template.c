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

void proto_register_akp(void);
void proto_reg_handoff_akp(void);

static dissector_handle_t private_key_dissector_handle;
static dissector_handle_t encrypted_private_key_dissector_handle;

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
  proto_akp = proto_register_protocol("Asymmetric Key Packages", "AKP", "akp");

  /* Register fields and subtrees */
  proto_register_field_array(proto_akp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  private_key_dissector_handle = register_dissector_with_description(
    "akp_private_key", "AKP Private Key", dissect_PrivateKeyInfo_PDU, proto_akp);
  encrypted_private_key_dissector_handle = register_dissector_with_description(
    "akp_encrypted_private_key", "AKP Encrypted Private Key", dissect_EncryptedPrivateKeyInfo_PDU, proto_akp);
}


/*--- proto_reg_handoff_akp -------------------------------------------*/
void proto_reg_handoff_akp(void) {
#include "packet-akp-dis-tab.c"

  register_ber_syntax_dissector("PrivateKeyInfo", proto_akp, dissect_PrivateKeyInfo_PDU);
  register_ber_syntax_dissector("EncryptedPrivateKeyInfo", proto_akp, dissect_EncryptedPrivateKeyInfo_PDU);

  register_ber_oid_syntax(".p8", NULL, "PrivateKeyInfo");
  register_ber_oid_syntax(".p8e", NULL, "EncryptedPrivateKeyInfo");
  dissector_add_string("media_type", "application/pkcs8", private_key_dissector_handle);
  dissector_add_string("media_type", "application/pkcs8-encrypted", encrypted_private_key_dissector_handle);

  dissector_add_string("rfc7468.preeb_label", "PRIVATE KEY", private_key_dissector_handle);
  dissector_add_string("rfc7468.preeb_label", "ENCRYPTED PRIVATE KEY", encrypted_private_key_dissector_handle);
}
