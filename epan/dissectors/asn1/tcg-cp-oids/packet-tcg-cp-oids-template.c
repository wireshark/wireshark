/* packet-tcg-cp-oids.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/oids.h>
#include <epan/asn1.h>

#include "packet-tcg-cp-oids.h"
#include "packet-ber.h"
#include "packet-pkix1explicit.h"
#include "packet-pkix1implicit.h"

#define PNAME  "TCG_CP_OIDS"
#define PSNAME "TCG_CP_OIDS"
#define PFNAME "tcg_cp_oids"

void proto_register_tcg_cp_oids(void);
void proto_reg_handoff_tcg_cp_oids(void);

/* Initialize the protocol and registered fields */
static int proto_tcg_cp_oids;
#include "packet-tcg-cp-oids-hf.c"
static int hf_tcg_cp_oids_UTF8String_PDU;

/* Initialize the subtree pointers */
#include "packet-tcg-cp-oids-ett.c"
#include "packet-tcg-cp-oids-fn.c"


/*--- proto_register_tcg_cp_oids ----------------------------------------------*/
void proto_register_tcg_cp_oids(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_tcg_cp_oids_UTF8String_PDU,
      { "UTF8String", "tcg-cp-oids.UTF8String",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
#include "packet-tcg-cp-oids-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
#include "packet-tcg-cp-oids-ettarr.c"
  };

  /* Register protocol */
  proto_tcg_cp_oids = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_tcg_cp_oids, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

/* to be able to register OIDs for UTF8String */
static int
dissect_tcg_cp_oids_UTF8String_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
    int offset = 0;
    asn1_ctx_t actx;
    asn1_ctx_init(&actx, ASN1_ENC_BER, true, pinfo);
    offset = dissect_ber_restricted_string(false, BER_UNI_TAG_UTF8String, &actx, tree, tvb, offset, hf_tcg_cp_oids_UTF8String_PDU, NULL);
    return offset;
}

/*--- proto_reg_handoff_tcg_cp_oids -------------------------------------------*/
void proto_reg_handoff_tcg_cp_oids(void) {
#include "packet-tcg-cp-oids-dis-tab.c"
  oid_add_from_string("tcg","2.23.133");
  oid_add_from_string("tcg-attribute","2.23.133.2");
  oid_add_from_string("tcg-protocol","2.23.133.3");
  oid_add_from_string("tcg-algorithm","2.23.133.4");
  oid_add_from_string("tcg-ce","2.23.133.6");
  oid_add_from_string("tcg-kp","2.23.133.8");
  /* TCG Spec Version OIDs */
  oid_add_from_string("tcg-sv-tpm12","2.23.133.1.1");
  oid_add_from_string("tcg-sv-tpm20","2.23.133.1.2");
  /* TCG Attribute OIDs */
  oid_add_from_string("tcg-at-securityQualities","2.23.133.2.10");
  /* TCG Algorithm OIDs */
  oid_add_from_string("tcg-algorithm-null","2.23.133.4.1");
  /* TCG Key Purposes OIDs */
  oid_add_from_string("tcg-kp-EKCertificate","2.23.133.8.1");
  oid_add_from_string("tcg-kp-PlatformCertificate","2.23.133.8.2");
  oid_add_from_string("tcg-kp-AIKCertificate","2.23.133.8.3");
  /* TCG Protocol OIDs */
  oid_add_from_string("tcg-prt-tpmIdProtocol","2.23.133.3.1");

  register_ber_oid_dissector("2.23.133.2.1", dissect_tcg_cp_oids_UTF8String_PDU, proto_tcg_cp_oids, "tcg-at-tpmManufacturer");
  register_ber_oid_dissector("2.23.133.2.2", dissect_tcg_cp_oids_UTF8String_PDU, proto_tcg_cp_oids, "tcg-at-tpmModel");
  register_ber_oid_dissector("2.23.133.2.3", dissect_tcg_cp_oids_UTF8String_PDU, proto_tcg_cp_oids, "tcg-at-tpmVersion");
  register_ber_oid_dissector("2.23.133.2.4", dissect_tcg_cp_oids_UTF8String_PDU, proto_tcg_cp_oids, "tcg-at-platformManufacturer");
  register_ber_oid_dissector("2.23.133.2.5", dissect_tcg_cp_oids_UTF8String_PDU, proto_tcg_cp_oids, "tcg-at-platformModel");
  register_ber_oid_dissector("2.23.133.2.6", dissect_tcg_cp_oids_UTF8String_PDU, proto_tcg_cp_oids, "tcg-at-platformVersion");
  register_ber_oid_dissector("2.23.133.2.15", dissect_tcg_cp_oids_UTF8String_PDU, proto_tcg_cp_oids, "tcg-at-tpmIdLabel");
}
