/* packet-pkcs1.c
 * Routines for PKCS#1/RFC2313 packet dissection
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
#include "packet-pkcs1.h"
#include "packet-x509af.h"

#define PNAME  "PKCS#1"
#define PSNAME "PKCS-1"
#define PFNAME "pkcs-1"

void proto_register_pkcs1(void);
void proto_reg_handoff_pkcs1(void);

/* Initialize the protocol and registered fields */
static int proto_pkcs1;
#include "packet-pkcs1-hf.c"

/* Initialize the subtree pointers */
#include "packet-pkcs1-ett.c"

#include "packet-pkcs1-fn.c"

/*--- proto_register_pkcs1 ----------------------------------------------*/
void proto_register_pkcs1(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-pkcs1-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
#include "packet-pkcs1-ettarr.c"
  };

  /* Register protocol */
  proto_pkcs1 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_pkcs1, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_pkcs1 -------------------------------------------*/
void proto_reg_handoff_pkcs1(void) {
#include "packet-pkcs1-dis-tab.c"

	register_ber_oid_dissector("1.2.840.113549.2.2", dissect_ber_oid_NULL_callback, proto_pkcs1, "md2");
	register_ber_oid_dissector("1.2.840.113549.2.4", dissect_ber_oid_NULL_callback, proto_pkcs1, "md4");
	register_ber_oid_dissector("1.2.840.113549.2.5", dissect_ber_oid_NULL_callback, proto_pkcs1, "md5");

	register_ber_oid_dissector("1.2.840.113549.1.1.1", dissect_ber_oid_NULL_callback, proto_pkcs1, "rsaEncryption");
	register_ber_oid_dissector("1.2.840.113549.1.1.2", dissect_ber_oid_NULL_callback, proto_pkcs1, "md2WithRSAEncryption");
	register_ber_oid_dissector("1.2.840.113549.1.1.3", dissect_ber_oid_NULL_callback, proto_pkcs1, "md4WithRSAEncryption");
	register_ber_oid_dissector("1.2.840.113549.1.1.4", dissect_ber_oid_NULL_callback, proto_pkcs1, "md5WithRSAEncryption");


	/* these two are not from RFC2313  but pulled in from
 	   http://www.alvestrand.no/objectid/1.2.840.113549.1.1.html
	*/
	register_ber_oid_dissector("1.2.840.113549.1.1.5", dissect_ber_oid_NULL_callback, proto_pkcs1, "sha1WithRSAEncryption");
	register_ber_oid_dissector("1.2.840.113549.1.1.6", dissect_ber_oid_NULL_callback, proto_pkcs1, "rsaOAEPEncryptionSET");

	/* these sha2 algorithms are from RFC3447 */
	register_ber_oid_dissector("1.2.840.113549.1.1.11", dissect_ber_oid_NULL_callback, proto_pkcs1, "sha256WithRSAEncryption");
	register_ber_oid_dissector("1.2.840.113549.1.1.12", dissect_ber_oid_NULL_callback, proto_pkcs1, "sha384WithRSAEncryption");
	register_ber_oid_dissector("1.2.840.113549.1.1.13", dissect_ber_oid_NULL_callback, proto_pkcs1, "sha512WithRSAEncryption");
	register_ber_oid_dissector("1.2.840.113549.1.1.14", dissect_ber_oid_NULL_callback, proto_pkcs1, "sha224WithRSAEncryption");

	/* ECDSA SHA-1 algorithm from RFC 3279 */
	register_ber_oid_dissector("1.2.840.10045.4.1", dissect_ber_oid_NULL_callback, proto_pkcs1, "ecdsa-with-SHA1");

	/* SM2-with-SM3 from GM/T 0006 Cryptographic application identifier criterion specification */
	register_ber_oid_dissector("1.2.156.10197.1.501", dissect_ber_oid_NULL_callback, proto_pkcs1, "SM2-with-SM3");

	/* ECDSA SHA2 algorithms from X9.62, RFC5480, RFC 5758, RFC 5912 */
	register_ber_oid_dissector("1.2.840.10045.4.3.1", dissect_ber_oid_NULL_callback, proto_pkcs1, "ecdsa-with-SHA224");
	register_ber_oid_dissector("1.2.840.10045.4.3.2", dissect_ber_oid_NULL_callback, proto_pkcs1, "ecdsa-with-SHA256");
	register_ber_oid_dissector("1.2.840.10045.4.3.3", dissect_ber_oid_NULL_callback, proto_pkcs1, "ecdsa-with-SHA384");
	register_ber_oid_dissector("1.2.840.10045.4.3.4", dissect_ber_oid_NULL_callback, proto_pkcs1, "ecdsa-with-SHA512");

	/* DSA SHA2 algorithms from FIPS186-3, RFC5480, RFC 5758, RFC 5912 */
	register_ber_oid_dissector("2.16.840.1.101.3.4.3.1", dissect_ber_oid_NULL_callback, proto_pkcs1, "id-dsa-with-sha224");
	register_ber_oid_dissector("2.16.840.1.101.3.4.3.2", dissect_ber_oid_NULL_callback, proto_pkcs1, "id-dsa-with-sha256");

	oid_add_from_string("secp192r1","1.2.840.10045.3.1.1");
	oid_add_from_string("sect163k1","1.3.132.0.1");
	oid_add_from_string("sect163r2","1.3.132.0.15");
	oid_add_from_string("secp224r1","1.3.132.0.33");
	oid_add_from_string("sect233k1","1.3.132.0.26");
	oid_add_from_string("sect233r1","1.3.132.0.27");
	oid_add_from_string("secp256r1","1.2.840.10045.3.1.7");
	oid_add_from_string("sect283k1","1.3.132.0.16");
	oid_add_from_string("sect283r1","1.3.132.0.17");
	oid_add_from_string("secp384r1","1.3.132.0.34");
	oid_add_from_string("sect409k1","1.3.132.0.36");
	oid_add_from_string("sect409r1","1.3.132.0.37");
	oid_add_from_string("secp521r1","1.3.132.0.35");
	oid_add_from_string("sect571k1","1.3.132.0.38");
	oid_add_from_string("sect571r1","1.3.132.0.39");

	/* SM2 from GM/T 0006 Cryptographic application identifier criterion specification */
	oid_add_from_string("sm2","1.2.156.10197.1.301");

	/* sha2 family, see RFC3447 and http://www.oid-info.com/get/2.16.840.1.101.3.4.2 */
	oid_add_from_string("sha256", "2.16.840.1.101.3.4.2.1");
	oid_add_from_string("sha384", "2.16.840.1.101.3.4.2.2");
	oid_add_from_string("sha512", "2.16.840.1.101.3.4.2.3");
	oid_add_from_string("sha224", "2.16.840.1.101.3.4.2.4");

	/* SM3 from GM/T 0006 Cryptographic application identifier criterion specification */
	oid_add_from_string("sm3","1.2.156.10197.1.401");

	/* PQC digital signature algorithms from OQS-OpenSSL,
		see https://github.com/open-quantum-safe/openssl/blob/OQS-OpenSSL_1_1_1-stable/oqs-template/oqs-sig-info.md */
	oid_add_from_string("dilithium2", "1.3.6.1.4.1.2.267.7.4.4");
	oid_add_from_string("p256_dilithium2", "1.3.9999.2.7.1");
	oid_add_from_string("rsa3072_dilithium2", "1.3.9999.2.7.2");
	oid_add_from_string("dilithium3", "1.3.6.1.4.1.2.267.7.6.5");
	oid_add_from_string("p384_dilithium3", "1.3.9999.2.7.3");
	oid_add_from_string("dilithium5", "1.3.6.1.4.1.2.267.7.8.7");
	oid_add_from_string("p521_dilithium5", "1.3.9999.2.7.4");
	oid_add_from_string("dilithium2_aes", "1.3.6.1.4.1.2.267.11.4.4");
	oid_add_from_string("p256_dilithium2_aes", "1.3.9999.2.11.1");
	oid_add_from_string("rsa3072_dilithium2_aes", "1.3.9999.2.11.2");
	oid_add_from_string("dilithium3_aes", "1.3.6.1.4.1.2.267.11.6.5");
	oid_add_from_string("p384_dilithium3_aes", "1.3.9999.2.11.3");
	oid_add_from_string("dilithium5_aes", "1.3.6.1.4.1.2.267.11.8.7");
	oid_add_from_string("p521_dilithium5_aes", "1.3.9999.2.11.4");
	oid_add_from_string("falcon512", "1.3.9999.3.1");
	oid_add_from_string("p256_falcon512", "1.3.9999.3.2");
	oid_add_from_string("rsa3072_falcon512", "1.3.9999.3.3");
	oid_add_from_string("falcon1024", "1.3.9999.3.4");
	oid_add_from_string("p521_falcon1024", "1.3.9999.3.5");
	oid_add_from_string("picnicl1full", "1.3.6.1.4.1.311.89.2.1.7");
	oid_add_from_string("p256_picnicl1full", "1.3.6.1.4.1.311.89.2.1.8");
	oid_add_from_string("rsa3072_picnicl1full", "1.3.6.1.4.1.311.89.2.1.9");
	oid_add_from_string("picnic3l1", "1.3.6.1.4.1.311.89.2.1.21");
	oid_add_from_string("p256_picnic3l1", "1.3.6.1.4.1.311.89.2.1.22");
	oid_add_from_string("rsa3072_picnic3l1", "1.3.6.1.4.1.311.89.2.1.23");
	oid_add_from_string("rainbowIclassic", "1.3.9999.5.1.1.1");
	oid_add_from_string("p256_rainbowIclassic", "1.3.9999.5.1.2.1");
	oid_add_from_string("rsa3072_rainbowIclassic", "1.3.9999.5.1.3.1");
	oid_add_from_string("rainbowVclassic", "1.3.9999.5.3.1.1");
	oid_add_from_string("p521_rainbowVclassic", "1.3.9999.5.3.2.1");
	oid_add_from_string("sphincsharaka128frobust", "1.3.9999.6.1.1");
	oid_add_from_string("p256_sphincsharaka128frobust", "1.3.9999.6.1.2");
	oid_add_from_string("rsa3072_sphincsharaka128frobust", "1.3.9999.6.1.3");
	oid_add_from_string("sphincssha256128frobust", "1.3.9999.6.4.1");
	oid_add_from_string("p256_sphincssha256128frobust", "1.3.9999.6.4.2");
	oid_add_from_string("rsa3072_sphincssha256128frobust", "1.3.9999.6.4.3");
	oid_add_from_string("sphincsshake256128frobust", "1.3.9999.6.7.1");
	oid_add_from_string("p256_sphincsshake256128frobust", "1.3.9999.6.7.2");
	oid_add_from_string("rsa3072_sphincsshake256128frobust", "1.3.9999.6.7.3");

}

