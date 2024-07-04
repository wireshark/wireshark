#define BER_UNI_TAG_TeletexString	    20  /* workaround bug in asn2wrs */

/* packet-pkix1explicit.c
 * Routines for PKIX1Explitic packet dissection
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
#include <epan/oids.h>
#include <epan/afn.h>

#include "packet-ber.h"
#include "packet-pkix1explicit.h"
#include "packet-x509af.h"
#include "packet-x509if.h"
#include "packet-x509ce.h"

/* from packet-tls-utils.h */
extern const value_string tls_hello_extension_types[];

#define PNAME  "PKIX1Explicit"
#define PSNAME "PKIX1EXPLICIT"
#define PFNAME "pkix1explicit"

void proto_register_pkix1explicit(void);
void proto_reg_handoff_pkix1explicit(void);

/* Initialize the protocol and registered fields */
static int proto_pkix1explicit;
static int hf_pkix1explicit_object_identifier_id;
static int hf_pkix1explicit_addressFamily_afn;
static int hf_pkix1explicit_addressFamily_safi;

static int ett_pkix1explicit_addressFamily;

#include "packet-pkix1explicit-hf.c"

/* Initialize the subtree pointers */
#include "packet-pkix1explicit-ett.c"

int
dissect_pkix1explicit_Certificate(bool implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_x509af_Certificate(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}
int
dissect_pkix1explicit_CertificateList(bool implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_x509af_CertificateList(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}
int
dissect_pkix1explicit_GeneralName(bool implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_x509ce_GeneralName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}
int
dissect_pkix1explicit_Name(bool implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_x509if_Name(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}
int
dissect_pkix1explicit_AlgorithmIdentifier(bool implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}

int
dissect_pkix1explicit_SubjectPublicKeyInfo(bool implicit_tag, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_x509af_SubjectPublicKeyInfo(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


#include "packet-pkix1explicit-fn.c"


/*--- proto_register_pkix1explicit ----------------------------------------------*/
void proto_register_pkix1explicit(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_pkix1explicit_object_identifier_id,
      { "Id", "pkix1explicit.id", FT_STRING, BASE_NONE, NULL, 0,
	"Object identifier Id", HFILL }},

    { &hf_pkix1explicit_addressFamily_afn,
      { "Address family(AFN)", "pkix1explicit.addressfamily", FT_UINT16, BASE_DEC, VALS(afn_vals), 0,
	NULL, HFILL }},

    { &hf_pkix1explicit_addressFamily_safi,
      { "Subsequent Address Family Identifiers (SAFI)", "pkix1explicit.addressfamily.safi", FT_UINT16, BASE_DEC, NULL, 0,
	"Subsequent Address Family Identifiers (SAFI) RFC4760", HFILL }},
#include "packet-pkix1explicit-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
	  &ett_pkix1explicit_addressFamily,
#include "packet-pkix1explicit-ettarr.c"
  };

  /* Register protocol */
  proto_pkix1explicit = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_pkix1explicit, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_pkix1explicit -------------------------------------------*/
void proto_reg_handoff_pkix1explicit(void) {
	oid_add_from_string("id-pkix","1.3.6.1.5.5.7");
	oid_add_from_string("id-dsa-with-sha1","1.2.840.10040.4.3");
#include "packet-pkix1explicit-dis-tab.c"
}
