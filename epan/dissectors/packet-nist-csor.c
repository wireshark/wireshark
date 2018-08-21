/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-nist-csor.c                                                         */
/* asn2wrs.py -b -p nist-csor -c ./nist-csor.cnf -s ./packet-nist-csor-template -D . -O ../.. aes1.asn */

/* Input file: packet-nist-csor-template.c */

#line 1 "./asn1/nist-csor/packet-nist-csor-template.c"
/* packet-nist-csor.c
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

#include "packet-nist-csor.h"
#include "packet-ber.h"
#include "packet-pkix1explicit.h"
#include "packet-pkix1implicit.h"

#define PNAME  "NIST_CSOR"
#define PSNAME "NIST_CSOR"
#define PFNAME "nist_csor"

void proto_register_nist_csor(void);
void proto_reg_handoff_nist_csor(void);

/* Initialize the protocol and registered fields */
static int proto_nist_csor = -1;

/*--- Included file: packet-nist-csor-hf.c ---*/
#line 1 "./asn1/nist-csor/packet-nist-csor-hf.c"
static int hf_nist_csor_CFBParameters_PDU = -1;   /* CFBParameters */
static int hf_nist_csor_AES_IV_PDU = -1;          /* AES_IV */
static int hf_nist_csor_ShakeOutputLen_PDU = -1;  /* ShakeOutputLen */
static int hf_nist_csor_aes_IV = -1;              /* AES_IV */
static int hf_nist_csor_numberOfBits = -1;        /* NumberOfBits */

/*--- End of included file: packet-nist-csor-hf.c ---*/
#line 31 "./asn1/nist-csor/packet-nist-csor-template.c"

/* Initialize the subtree pointers */

/*--- Included file: packet-nist-csor-ett.c ---*/
#line 1 "./asn1/nist-csor/packet-nist-csor-ett.c"
static gint ett_nist_csor_CFBParameters = -1;

/*--- End of included file: packet-nist-csor-ett.c ---*/
#line 34 "./asn1/nist-csor/packet-nist-csor-template.c"

/*--- Included file: packet-nist-csor-fn.c ---*/
#line 1 "./asn1/nist-csor/packet-nist-csor-fn.c"


int
dissect_nist_csor_AES_IV(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



int
dissect_nist_csor_NumberOfBits(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t CFBParameters_sequence[] = {
  { &hf_nist_csor_aes_IV    , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_nist_csor_AES_IV },
  { &hf_nist_csor_numberOfBits, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_nist_csor_NumberOfBits },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_nist_csor_CFBParameters(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CFBParameters_sequence, hf_index, ett_nist_csor_CFBParameters);

  return offset;
}



int
dissect_nist_csor_ShakeOutputLen(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_CFBParameters_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_nist_csor_CFBParameters(FALSE, tvb, offset, &asn1_ctx, tree, hf_nist_csor_CFBParameters_PDU);
  return offset;
}
static int dissect_AES_IV_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_nist_csor_AES_IV(FALSE, tvb, offset, &asn1_ctx, tree, hf_nist_csor_AES_IV_PDU);
  return offset;
}
static int dissect_ShakeOutputLen_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_nist_csor_ShakeOutputLen(FALSE, tvb, offset, &asn1_ctx, tree, hf_nist_csor_ShakeOutputLen_PDU);
  return offset;
}


/*--- End of included file: packet-nist-csor-fn.c ---*/
#line 35 "./asn1/nist-csor/packet-nist-csor-template.c"


/*--- proto_register_nist-csor ----------------------------------------------*/
void proto_register_nist_csor(void) {

  /* List of fields */
  static hf_register_info hf[] = {

/*--- Included file: packet-nist-csor-hfarr.c ---*/
#line 1 "./asn1/nist-csor/packet-nist-csor-hfarr.c"
    { &hf_nist_csor_CFBParameters_PDU,
      { "CFBParameters", "nist-csor.CFBParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nist_csor_AES_IV_PDU,
      { "AES-IV", "nist-csor.AES_IV",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nist_csor_ShakeOutputLen_PDU,
      { "ShakeOutputLen", "nist-csor.ShakeOutputLen",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_nist_csor_aes_IV,
      { "aes-IV", "nist-csor.aes_IV",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_nist_csor_numberOfBits,
      { "numberOfBits", "nist-csor.numberOfBits",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},

/*--- End of included file: packet-nist-csor-hfarr.c ---*/
#line 43 "./asn1/nist-csor/packet-nist-csor-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-nist-csor-ettarr.c ---*/
#line 1 "./asn1/nist-csor/packet-nist-csor-ettarr.c"
    &ett_nist_csor_CFBParameters,

/*--- End of included file: packet-nist-csor-ettarr.c ---*/
#line 48 "./asn1/nist-csor/packet-nist-csor-template.c"
  };

  /* Register protocol */
  proto_nist_csor = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_nist_csor, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}


/*--- proto_reg_handoff_nist_csor -------------------------------------------*/
void proto_reg_handoff_nist_csor(void) {

/*--- Included file: packet-nist-csor-dis-tab.c ---*/
#line 1 "./asn1/nist-csor/packet-nist-csor-dis-tab.c"
  register_ber_oid_dissector("2.16.840.1.101.3.4.1.2", dissect_AES_IV_PDU, proto_nist_csor, "id-aes128-CBC");
  register_ber_oid_dissector("2.16.840.1.101.3.4.1.3", dissect_AES_IV_PDU, proto_nist_csor, "id-aes128-OFB");
  register_ber_oid_dissector("2.16.840.1.101.3.4.1.4", dissect_CFBParameters_PDU, proto_nist_csor, "id-aes128-CFB");
  register_ber_oid_dissector("2.16.840.1.101.3.4.1.22", dissect_AES_IV_PDU, proto_nist_csor, "id-aes192-CBC");
  register_ber_oid_dissector("2.16.840.1.101.3.4.1.23", dissect_AES_IV_PDU, proto_nist_csor, "id-aes192-OFB");
  register_ber_oid_dissector("2.16.840.1.101.3.4.1.24", dissect_CFBParameters_PDU, proto_nist_csor, "id-aes192-CFB");
  register_ber_oid_dissector("2.16.840.1.101.3.4.1.42", dissect_AES_IV_PDU, proto_nist_csor, "id-aes256-CBC");
  register_ber_oid_dissector("2.16.840.1.101.3.4.1.43", dissect_AES_IV_PDU, proto_nist_csor, "id-aes256-OFB");
  register_ber_oid_dissector("2.16.840.1.101.3.4.1.44", dissect_CFBParameters_PDU, proto_nist_csor, "id-aes256-CFB");
  register_ber_oid_dissector("2.16.840.1.101.3.4.2.17", dissect_ShakeOutputLen_PDU, proto_nist_csor, "id-shake128-len");
  register_ber_oid_dissector("2.16.840.1.101.3.4.2.18", dissect_ShakeOutputLen_PDU, proto_nist_csor, "id-shake256-len");


/*--- End of included file: packet-nist-csor-dis-tab.c ---*/
#line 62 "./asn1/nist-csor/packet-nist-csor-template.c"
  oid_add_from_string("id-data","1.2.840.113549.1.7.1");

/* AES  */
  oid_add_from_string("aes","2.16.840.1.101.3.4.1");

/* 128-bit AES information OIDs */
  oid_add_from_string("id-aes128-ECB","2.16.840.1.101.3.4.1.1");
  oid_add_from_string("id-aes128-wrap","2.16.840.1.101.3.4.1.5");
  oid_add_from_string("id-aes128-GCM","2.16.840.1.101.3.4.1.6");
  oid_add_from_string("id-aes128-CCM","2.16.840.1.101.3.4.1.7");
  oid_add_from_string("id-aes128-wrap-pad","2.16.840.1.101.3.4.1.8");

/* 192-bit AES information OIDs */
  oid_add_from_string("id-aes192-ECB","2.16.840.1.101.3.4.1.21");
  oid_add_from_string("id-aes192-wrap","2.16.840.1.101.3.4.1.25");
  oid_add_from_string("id-aes192-GCM","2.16.840.1.101.3.4.1.26");
  oid_add_from_string("id-aes192-CCM","2.16.840.1.101.3.4.1.27");
  oid_add_from_string("id-aes192-wrap-pad","2.16.840.1.101.3.4.1.28");

/* 256-bit AES information OIDs */
  oid_add_from_string("id-aes256-ECB","2.16.840.1.101.3.4.1.41");
  oid_add_from_string("id-aes256-wrap","2.16.840.1.101.3.4.1.45");
  oid_add_from_string("id-aes256-GCM","2.16.840.1.101.3.4.1.46");
  oid_add_from_string("id-aes256-CCM","2.16.840.1.101.3.4.1.47");
  oid_add_from_string("id-aes256-wrap-pad","2.16.840.1.101.3.4.1.48");

/* Secure Hash Algorithms */
  oid_add_from_string("hashAlgs","2.16.840.1.101.3.4.2");

/* SHA-2 family */
  oid_add_from_string("id-sha256","2.16.840.1.101.3.4.2.1");
  oid_add_from_string("id-sha384","2.16.840.1.101.3.4.2.2");
  oid_add_from_string("id-sha512","2.16.840.1.101.3.4.2.3");
  oid_add_from_string("id-sha224","2.16.840.1.101.3.4.2.4");
  oid_add_from_string("id-sha512-224","2.16.840.1.101.3.4.2.5");
  oid_add_from_string("id-sha512-256","2.16.840.1.101.3.4.2.6");

/* SHA-3 family */
  oid_add_from_string("id-sha3-224","2.16.840.1.101.3.4.2.7");
  oid_add_from_string("id-sha3-256","2.16.840.1.101.3.4.2.8");
  oid_add_from_string("id-sha3-384","2.16.840.1.101.3.4.2.9");
  oid_add_from_string("id-sha3-512","2.16.840.1.101.3.4.2.10");

  oid_add_from_string("id-shake128","2.16.840.1.101.3.4.2.11");
  oid_add_from_string("id-shake256","2.16.840.1.101.3.4.2.12");

/* HMAC with SHA-3 family */
  oid_add_from_string("id-hmacWithSHA3-224","2.16.840.1.101.3.4.2.13");
  oid_add_from_string("id-hmacWithSHA3-256","2.16.840.1.101.3.4.2.14");
  oid_add_from_string("id-hmacWithSHA3-384","2.16.840.1.101.3.4.2.15");
  oid_add_from_string("id-hmacWithSHA3-512","2.16.840.1.101.3.4.2.16");

/* Digital Signature Algorithms */
  oid_add_from_string("sigAlgs","2.16.840.1.101.3.4.3");

/* DSA with SHA-2 family */
  oid_add_from_string("id-dsa-with-sha224","2.16.840.1.101.3.4.3.1");
  oid_add_from_string("id-dsa-with-sha256","2.16.840.1.101.3.4.3.2");
  oid_add_from_string("id-dsa-with-sha384","2.16.840.1.101.3.4.3.3");
  oid_add_from_string("id-dsa-with-sha512","2.16.840.1.101.3.4.3.4");

/* DSA with SHA-3 family */
  oid_add_from_string("id-dsa-with-sha3-224","2.16.840.1.101.3.4.3.5");
  oid_add_from_string("id-dsa-with-sha3-256","2.16.840.1.101.3.4.3.6");
  oid_add_from_string("id-dsa-with-sha3-384","2.16.840.1.101.3.4.3.7");
  oid_add_from_string("id-dsa-with-sha3-512","2.16.840.1.101.3.4.3.8");

/* ECDSA with SHA-3 family */
  oid_add_from_string("id-ecdsa-with-sha3-224","2.16.840.1.101.3.4.3.9");
  oid_add_from_string("id-ecdsa-with-sha3-256","2.16.840.1.101.3.4.3.10");
  oid_add_from_string("id-ecdsa-with-sha3-384","2.16.840.1.101.3.4.3.11");
  oid_add_from_string("id-ecdsa-with-sha3-512","2.16.840.1.101.3.4.3.12");

/* RSA PKCS#1 v1.5 Signature with SHA-3 family */
  oid_add_from_string("id-rsassa-pkcs1-v1_5-with-sha3-224","2.16.840.1.101.3.4.3.13");
  oid_add_from_string("id-rsassa-pkcs1-v1_5-with-sha3-256","2.16.840.1.101.3.4.3.14");
  oid_add_from_string("id-rsassa-pkcs1-v1_5-with-sha3-384","2.16.840.1.101.3.4.3.15");
  oid_add_from_string("id-rsassa-pkcs1-v1_5-with-sha3-512","2.16.840.1.101.3.4.3.16");
}
