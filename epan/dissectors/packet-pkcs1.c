/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* .\packet-pkcs1.c                                                           */
/* ../../tools/asn2wrs.py -b -p pkcs1 -c pkcs1.cnf -s packet-pkcs1-template PKCS1.asn */

/* Input file: packet-pkcs1-template.c */

#line 1 "packet-pkcs1-template.c"
/* packet-pkcs1.c
 * Routines for PKCS#1/RFC2313 packet dissection
 *  Ronnie Sahlberg 2004
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include "packet-pkcs1.h"
#include "packet-ber.h"
#include "packet-x509af.h"

#define PNAME  "PKCS#1"
#define PSNAME "PKCS-1"
#define PFNAME "pkcs-1"

/* Initialize the protocol and registered fields */
static int proto_pkcs1 = -1;

/*--- Included file: packet-pkcs1-hf.c ---*/
#line 1 "packet-pkcs1-hf.c"
static int hf_pkcs1_modulus = -1;                 /* INTEGER */
static int hf_pkcs1_publicExponent = -1;          /* INTEGER */
static int hf_pkcs1_version = -1;                 /* Version */
static int hf_pkcs1_privateExponent = -1;         /* INTEGER */
static int hf_pkcs1_prime1 = -1;                  /* INTEGER */
static int hf_pkcs1_prime2 = -1;                  /* INTEGER */
static int hf_pkcs1_exponent1 = -1;               /* INTEGER */
static int hf_pkcs1_exponent2 = -1;               /* INTEGER */
static int hf_pkcs1_coefficient = -1;             /* INTEGER */
static int hf_pkcs1_digestAlgorithm = -1;         /* DigestAlgorithmIdentifier */
static int hf_pkcs1_digest = -1;                  /* Digest */

/*--- End of included file: packet-pkcs1-hf.c ---*/
#line 48 "packet-pkcs1-template.c"

/* Initialize the subtree pointers */

/*--- Included file: packet-pkcs1-ett.c ---*/
#line 1 "packet-pkcs1-ett.c"
static gint ett_pkcs1_RSAPublicKey = -1;
static gint ett_pkcs1_RSAPrivateKey = -1;
static gint ett_pkcs1_DigestInfo = -1;

/*--- End of included file: packet-pkcs1-ett.c ---*/
#line 51 "packet-pkcs1-template.c"


/*--- Included file: packet-pkcs1-fn.c ---*/
#line 1 "packet-pkcs1-fn.c"
/*--- Fields for imported types ---*/




static int
dissect_pkcs1_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_modulus(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs1_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_pkcs1_modulus);
}
static int dissect_publicExponent(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs1_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_pkcs1_publicExponent);
}
static int dissect_privateExponent(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs1_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_pkcs1_privateExponent);
}
static int dissect_prime1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs1_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_pkcs1_prime1);
}
static int dissect_prime2(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs1_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_pkcs1_prime2);
}
static int dissect_exponent1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs1_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_pkcs1_exponent1);
}
static int dissect_exponent2(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs1_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_pkcs1_exponent2);
}
static int dissect_coefficient(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs1_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_pkcs1_coefficient);
}


static const ber_sequence_t RSAPublicKey_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_modulus },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_publicExponent },
  { 0, 0, 0, NULL }
};

int
dissect_pkcs1_RSAPublicKey(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   RSAPublicKey_sequence, hf_index, ett_pkcs1_RSAPublicKey);

  return offset;
}



static int
dissect_pkcs1_Version(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_version(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs1_Version(FALSE, tvb, offset, pinfo, tree, hf_pkcs1_version);
}


static const ber_sequence_t RSAPrivateKey_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_version },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_modulus },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_publicExponent },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_privateExponent },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_prime1 },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_prime2 },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_exponent1 },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_exponent2 },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_coefficient },
  { 0, 0, 0, NULL }
};

int
dissect_pkcs1_RSAPrivateKey(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   RSAPrivateKey_sequence, hf_index, ett_pkcs1_RSAPrivateKey);

  return offset;
}



static int
dissect_pkcs1_DigestAlgorithmIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_digestAlgorithm(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs1_DigestAlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_pkcs1_digestAlgorithm);
}



static int
dissect_pkcs1_Digest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_digest(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkcs1_Digest(FALSE, tvb, offset, pinfo, tree, hf_pkcs1_digest);
}


static const ber_sequence_t DigestInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_digestAlgorithm },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_digest },
  { 0, 0, 0, NULL }
};

int
dissect_pkcs1_DigestInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DigestInfo_sequence, hf_index, ett_pkcs1_DigestInfo);

  return offset;
}


/*--- End of included file: packet-pkcs1-fn.c ---*/
#line 53 "packet-pkcs1-template.c"

/*--- proto_register_pkcs1 ----------------------------------------------*/
void proto_register_pkcs1(void) {

  /* List of fields */
  static hf_register_info hf[] = {

/*--- Included file: packet-pkcs1-hfarr.c ---*/
#line 1 "packet-pkcs1-hfarr.c"
    { &hf_pkcs1_modulus,
      { "modulus", "pkcs1.modulus",
        FT_INT32, BASE_DEC, NULL, 0,
        "pkcs1.INTEGER", HFILL }},
    { &hf_pkcs1_publicExponent,
      { "publicExponent", "pkcs1.publicExponent",
        FT_INT32, BASE_DEC, NULL, 0,
        "pkcs1.INTEGER", HFILL }},
    { &hf_pkcs1_version,
      { "version", "pkcs1.version",
        FT_INT32, BASE_DEC, VALS(x509af_Version_vals), 0,
        "pkcs1.Version", HFILL }},
    { &hf_pkcs1_privateExponent,
      { "privateExponent", "pkcs1.privateExponent",
        FT_INT32, BASE_DEC, NULL, 0,
        "pkcs1.INTEGER", HFILL }},
    { &hf_pkcs1_prime1,
      { "prime1", "pkcs1.prime1",
        FT_INT32, BASE_DEC, NULL, 0,
        "pkcs1.INTEGER", HFILL }},
    { &hf_pkcs1_prime2,
      { "prime2", "pkcs1.prime2",
        FT_INT32, BASE_DEC, NULL, 0,
        "pkcs1.INTEGER", HFILL }},
    { &hf_pkcs1_exponent1,
      { "exponent1", "pkcs1.exponent1",
        FT_INT32, BASE_DEC, NULL, 0,
        "pkcs1.INTEGER", HFILL }},
    { &hf_pkcs1_exponent2,
      { "exponent2", "pkcs1.exponent2",
        FT_INT32, BASE_DEC, NULL, 0,
        "pkcs1.INTEGER", HFILL }},
    { &hf_pkcs1_coefficient,
      { "coefficient", "pkcs1.coefficient",
        FT_INT32, BASE_DEC, NULL, 0,
        "pkcs1.INTEGER", HFILL }},
    { &hf_pkcs1_digestAlgorithm,
      { "digestAlgorithm", "pkcs1.digestAlgorithm",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkcs1.DigestAlgorithmIdentifier", HFILL }},
    { &hf_pkcs1_digest,
      { "digest", "pkcs1.digest",
        FT_BYTES, BASE_HEX, NULL, 0,
        "pkcs1.Digest", HFILL }},

/*--- End of included file: packet-pkcs1-hfarr.c ---*/
#line 60 "packet-pkcs1-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-pkcs1-ettarr.c ---*/
#line 1 "packet-pkcs1-ettarr.c"
    &ett_pkcs1_RSAPublicKey,
    &ett_pkcs1_RSAPrivateKey,
    &ett_pkcs1_DigestInfo,

/*--- End of included file: packet-pkcs1-ettarr.c ---*/
#line 65 "packet-pkcs1-template.c"
  };

  /* Register protocol */
  proto_pkcs1 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_pkcs1, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_pkcs1 -------------------------------------------*/
void proto_reg_handoff_pkcs1(void) {
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
	register_ber_oid_dissector("1.2.840.113549.1.1.5", dissect_ber_oid_NULL_callback, proto_pkcs1, "shaWithRSAEncryption");
	register_ber_oid_dissector("1.2.840.113549.1.1.6", dissect_ber_oid_NULL_callback, proto_pkcs1, "rsaOAEPEncryptionSET");
}

