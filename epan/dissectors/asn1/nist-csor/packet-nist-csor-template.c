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
static int proto_nist_csor;
#include "packet-nist-csor-hf.c"

/* Initialize the subtree pointers */
#include "packet-nist-csor-ett.c"
#include "packet-nist-csor-fn.c"


/*--- proto_register_nist-csor ----------------------------------------------*/
void proto_register_nist_csor(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-nist-csor-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
#include "packet-nist-csor-ettarr.c"
  };

  /* Register protocol */
  proto_nist_csor = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_nist_csor, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}


/*--- proto_reg_handoff_nist_csor -------------------------------------------*/
void proto_reg_handoff_nist_csor(void) {
#include "packet-nist-csor-dis-tab.c"
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
