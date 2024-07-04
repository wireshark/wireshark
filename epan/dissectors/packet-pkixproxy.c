/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-pkixproxy.c                                                         */
/* asn2wrs.py -b -q -L -p pkixproxy -c ./pkixproxy.cnf -s ./packet-pkixproxy-template -D . -O ../.. PKIXProxy.asn */

/* packet-pkixproxy.c
 * Routines for RFC3820 PKIXProxy packet dissection
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
#include <epan/oids.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-pkixproxy.h"

#define PNAME  "PKIXProxy (RFC3820)"
#define PSNAME "PKIXPROXY"
#define PFNAME "pkixproxy"

void proto_register_pkixproxy(void);
void proto_reg_handoff_pkixproxy(void);

/* Initialize the protocol and registered fields */
static int proto_pkixproxy;
static int hf_pkixproxy_ProxyCertInfoExtension_PDU;  /* ProxyCertInfoExtension */
static int hf_pkixproxy_pCPathLenConstraint;      /* ProxyCertPathLengthConstraint */
static int hf_pkixproxy_proxyPolicy;              /* ProxyPolicy */
static int hf_pkixproxy_policyLanguage;           /* OBJECT_IDENTIFIER */
static int hf_pkixproxy_policy;                   /* OCTET_STRING */

/* Initialize the subtree pointers */
static int ett_pkixproxy_ProxyCertInfoExtension;
static int ett_pkixproxy_ProxyPolicy;



static int
dissect_pkixproxy_ProxyCertPathLengthConstraint(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_pkixproxy_OBJECT_IDENTIFIER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_pkixproxy_OCTET_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t ProxyPolicy_sequence[] = {
  { &hf_pkixproxy_policyLanguage, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_pkixproxy_OBJECT_IDENTIFIER },
  { &hf_pkixproxy_policy    , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_pkixproxy_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkixproxy_ProxyPolicy(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ProxyPolicy_sequence, hf_index, ett_pkixproxy_ProxyPolicy);

  return offset;
}


static const ber_sequence_t ProxyCertInfoExtension_sequence[] = {
  { &hf_pkixproxy_pCPathLenConstraint, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_pkixproxy_ProxyCertPathLengthConstraint },
  { &hf_pkixproxy_proxyPolicy, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkixproxy_ProxyPolicy },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkixproxy_ProxyCertInfoExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ProxyCertInfoExtension_sequence, hf_index, ett_pkixproxy_ProxyCertInfoExtension);

  return offset;
}

/*--- PDUs ---*/

static int dissect_ProxyCertInfoExtension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_pkixproxy_ProxyCertInfoExtension(false, tvb, offset, &asn1_ctx, tree, hf_pkixproxy_ProxyCertInfoExtension_PDU);
  return offset;
}



/*--- proto_register_pkixproxy ----------------------------------------------*/
void proto_register_pkixproxy(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_pkixproxy_ProxyCertInfoExtension_PDU,
      { "ProxyCertInfoExtension", "pkixproxy.ProxyCertInfoExtension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkixproxy_pCPathLenConstraint,
      { "pCPathLenConstraint", "pkixproxy.pCPathLenConstraint",
        FT_INT32, BASE_DEC, NULL, 0,
        "ProxyCertPathLengthConstraint", HFILL }},
    { &hf_pkixproxy_proxyPolicy,
      { "proxyPolicy", "pkixproxy.proxyPolicy_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkixproxy_policyLanguage,
      { "policyLanguage", "pkixproxy.policyLanguage",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_pkixproxy_policy,
      { "policy", "pkixproxy.policy",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_pkixproxy_ProxyCertInfoExtension,
    &ett_pkixproxy_ProxyPolicy,
  };

  /* Register protocol */
  proto_pkixproxy = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_pkixproxy, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_pkixproxy -------------------------------------------*/
void proto_reg_handoff_pkixproxy(void) {
  register_ber_oid_dissector("1.3.6.1.5.5.7.1.14", dissect_ProxyCertInfoExtension_PDU, proto_pkixproxy, "id-pe-proxyCertInfo");

  oid_add_from_string("id-ppl-anyLanguage","1.3.6.1.5.5.7.21.0");
  oid_add_from_string("id-ppl-inheritAll","1.3.6.1.5.5.7.21.1");
  oid_add_from_string("id-ppl-independent","1.3.6.1.5.5.7.21.2");
}

