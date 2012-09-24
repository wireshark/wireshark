/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-pkcs1.c                                                             */
/* ../../tools/asn2wrs.py -b -p pkcs1 -c ./pkcs1.cnf -s ./packet-pkcs1-template -D . -O ../../epan/dissectors PKIXAlgs-2009.asn */

/* Input file: packet-pkcs1-template.c */

#line 1 "../../asn1/pkcs1/packet-pkcs1-template.c"
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/oids.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-pkcs1.h"
#include "packet-x509af.h"

#define PNAME  "PKCS#1"
#define PSNAME "PKCS-1"
#define PFNAME "pkcs-1"

/* Initialize the protocol and registered fields */
static int proto_pkcs1 = -1;

/*--- Included file: packet-pkcs1-hf.c ---*/
#line 1 "../../asn1/pkcs1/packet-pkcs1-hf.c"
static int hf_pkcs1_DSA_Params_PDU = -1;          /* DSA_Params */
static int hf_pkcs1_DomainParameters_PDU = -1;    /* DomainParameters */
static int hf_pkcs1_KEA_Params_Id_PDU = -1;       /* KEA_Params_Id */
static int hf_pkcs1_HashAlgorithm_PDU = -1;       /* HashAlgorithm */
static int hf_pkcs1_RSASSA_PSS_params_PDU = -1;   /* RSASSA_PSS_params */
static int hf_pkcs1_ECParameters_PDU = -1;        /* ECParameters */
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
static int hf_pkcs1_p = -1;                       /* INTEGER */
static int hf_pkcs1_q = -1;                       /* INTEGER */
static int hf_pkcs1_g = -1;                       /* INTEGER */
static int hf_pkcs1_j = -1;                       /* INTEGER */
static int hf_pkcs1_validationParams = -1;        /* ValidationParams */
static int hf_pkcs1_seed = -1;                    /* BIT_STRING */
static int hf_pkcs1_pgenCounter = -1;             /* INTEGER */
static int hf_pkcs1_hashAlgorithm = -1;           /* HashAlgorithm */
static int hf_pkcs1_maskGenAlgorithm = -1;        /* MaskGenAlgorithm */
static int hf_pkcs1_saltLength = -1;              /* INTEGER */
static int hf_pkcs1_trailerField = -1;            /* INTEGER */
static int hf_pkcs1_namedCurve = -1;              /* OBJECT_IDENTIFIER */
static int hf_pkcs1_r = -1;                       /* INTEGER */
static int hf_pkcs1_s = -1;                       /* INTEGER */

/*--- End of included file: packet-pkcs1-hf.c ---*/
#line 44 "../../asn1/pkcs1/packet-pkcs1-template.c"

/* Initialize the subtree pointers */

/*--- Included file: packet-pkcs1-ett.c ---*/
#line 1 "../../asn1/pkcs1/packet-pkcs1-ett.c"
static gint ett_pkcs1_RSAPublicKey = -1;
static gint ett_pkcs1_RSAPrivateKey = -1;
static gint ett_pkcs1_DigestInfo = -1;
static gint ett_pkcs1_DSA_Params = -1;
static gint ett_pkcs1_DomainParameters = -1;
static gint ett_pkcs1_ValidationParams = -1;
static gint ett_pkcs1_RSASSA_PSS_params = -1;
static gint ett_pkcs1_ECParameters = -1;
static gint ett_pkcs1_DSA_Sig_Value = -1;
static gint ett_pkcs1_ECDSA_Sig_Value = -1;

/*--- End of included file: packet-pkcs1-ett.c ---*/
#line 47 "../../asn1/pkcs1/packet-pkcs1-template.c"


/*--- Included file: packet-pkcs1-fn.c ---*/
#line 1 "../../asn1/pkcs1/packet-pkcs1-fn.c"


static int
dissect_pkcs1_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t RSAPublicKey_sequence[] = {
  { &hf_pkcs1_modulus       , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pkcs1_INTEGER },
  { &hf_pkcs1_publicExponent, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pkcs1_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_pkcs1_RSAPublicKey(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RSAPublicKey_sequence, hf_index, ett_pkcs1_RSAPublicKey);

  return offset;
}



static int
dissect_pkcs1_Version(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t RSAPrivateKey_sequence[] = {
  { &hf_pkcs1_version       , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pkcs1_Version },
  { &hf_pkcs1_modulus       , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pkcs1_INTEGER },
  { &hf_pkcs1_publicExponent, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pkcs1_INTEGER },
  { &hf_pkcs1_privateExponent, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pkcs1_INTEGER },
  { &hf_pkcs1_prime1        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pkcs1_INTEGER },
  { &hf_pkcs1_prime2        , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pkcs1_INTEGER },
  { &hf_pkcs1_exponent1     , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pkcs1_INTEGER },
  { &hf_pkcs1_exponent2     , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pkcs1_INTEGER },
  { &hf_pkcs1_coefficient   , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pkcs1_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_pkcs1_RSAPrivateKey(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RSAPrivateKey_sequence, hf_index, ett_pkcs1_RSAPrivateKey);

  return offset;
}



static int
dissect_pkcs1_DigestAlgorithmIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_pkcs1_Digest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t DigestInfo_sequence[] = {
  { &hf_pkcs1_digestAlgorithm, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkcs1_DigestAlgorithmIdentifier },
  { &hf_pkcs1_digest        , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_pkcs1_Digest },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_pkcs1_DigestInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DigestInfo_sequence, hf_index, ett_pkcs1_DigestInfo);

  return offset;
}


static const ber_sequence_t DSA_Params_sequence[] = {
  { &hf_pkcs1_p             , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pkcs1_INTEGER },
  { &hf_pkcs1_q             , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pkcs1_INTEGER },
  { &hf_pkcs1_g             , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pkcs1_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkcs1_DSA_Params(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DSA_Params_sequence, hf_index, ett_pkcs1_DSA_Params);

  return offset;
}




static int
dissect_pkcs1_BIT_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}


static const ber_sequence_t ValidationParams_sequence[] = {
  { &hf_pkcs1_seed          , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_pkcs1_BIT_STRING },
  { &hf_pkcs1_pgenCounter   , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pkcs1_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkcs1_ValidationParams(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ValidationParams_sequence, hf_index, ett_pkcs1_ValidationParams);

  return offset;
}


static const ber_sequence_t DomainParameters_sequence[] = {
  { &hf_pkcs1_p             , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pkcs1_INTEGER },
  { &hf_pkcs1_g             , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pkcs1_INTEGER },
  { &hf_pkcs1_q             , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pkcs1_INTEGER },
  { &hf_pkcs1_j             , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_pkcs1_INTEGER },
  { &hf_pkcs1_validationParams, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_pkcs1_ValidationParams },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkcs1_DomainParameters(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DomainParameters_sequence, hf_index, ett_pkcs1_DomainParameters);

  return offset;
}




static int
dissect_pkcs1_KEA_Params_Id(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_pkcs1_HashAlgorithm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_pkcs1_MaskGenAlgorithm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t RSASSA_PSS_params_sequence[] = {
  { &hf_pkcs1_hashAlgorithm , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_pkcs1_HashAlgorithm },
  { &hf_pkcs1_maskGenAlgorithm, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_pkcs1_MaskGenAlgorithm },
  { &hf_pkcs1_saltLength    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_pkcs1_INTEGER },
  { &hf_pkcs1_trailerField  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_pkcs1_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkcs1_RSASSA_PSS_params(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RSASSA_PSS_params_sequence, hf_index, ett_pkcs1_RSASSA_PSS_params);

  return offset;
}




static int
dissect_pkcs1_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const value_string pkcs1_ECParameters_vals[] = {
  {   0, "namedCurve" },
  { 0, NULL }
};

static const ber_choice_t ECParameters_choice[] = {
  {   0, &hf_pkcs1_namedCurve    , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_pkcs1_OBJECT_IDENTIFIER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_pkcs1_ECParameters(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ECParameters_choice, hf_index, ett_pkcs1_ECParameters,
                                 NULL);

  return offset;
}



/*--- PDUs ---*/

static void dissect_DSA_Params_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_pkcs1_DSA_Params(FALSE, tvb, 0, &asn1_ctx, tree, hf_pkcs1_DSA_Params_PDU);
}
static void dissect_DomainParameters_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_pkcs1_DomainParameters(FALSE, tvb, 0, &asn1_ctx, tree, hf_pkcs1_DomainParameters_PDU);
}
static void dissect_KEA_Params_Id_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_pkcs1_KEA_Params_Id(FALSE, tvb, 0, &asn1_ctx, tree, hf_pkcs1_KEA_Params_Id_PDU);
}
static void dissect_HashAlgorithm_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_pkcs1_HashAlgorithm(FALSE, tvb, 0, &asn1_ctx, tree, hf_pkcs1_HashAlgorithm_PDU);
}
static void dissect_RSASSA_PSS_params_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_pkcs1_RSASSA_PSS_params(FALSE, tvb, 0, &asn1_ctx, tree, hf_pkcs1_RSASSA_PSS_params_PDU);
}
static void dissect_ECParameters_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_pkcs1_ECParameters(FALSE, tvb, 0, &asn1_ctx, tree, hf_pkcs1_ECParameters_PDU);
}


/*--- End of included file: packet-pkcs1-fn.c ---*/
#line 49 "../../asn1/pkcs1/packet-pkcs1-template.c"

/*--- proto_register_pkcs1 ----------------------------------------------*/
void proto_register_pkcs1(void) {

  /* List of fields */
  static hf_register_info hf[] = {

/*--- Included file: packet-pkcs1-hfarr.c ---*/
#line 1 "../../asn1/pkcs1/packet-pkcs1-hfarr.c"
    { &hf_pkcs1_DSA_Params_PDU,
      { "DSA-Params", "pkcs1.DSA_Params",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs1_DomainParameters_PDU,
      { "DomainParameters", "pkcs1.DomainParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs1_KEA_Params_Id_PDU,
      { "KEA-Params-Id", "pkcs1.KEA_Params_Id",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs1_HashAlgorithm_PDU,
      { "HashAlgorithm", "pkcs1.HashAlgorithm",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs1_RSASSA_PSS_params_PDU,
      { "RSASSA-PSS-params", "pkcs1.RSASSA_PSS_params",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs1_ECParameters_PDU,
      { "ECParameters", "pkcs1.ECParameters",
        FT_UINT32, BASE_DEC, VALS(pkcs1_ECParameters_vals), 0,
        NULL, HFILL }},
    { &hf_pkcs1_modulus,
      { "modulus", "pkcs1.modulus",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_pkcs1_publicExponent,
      { "publicExponent", "pkcs1.publicExponent",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_pkcs1_version,
      { "version", "pkcs1.version",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs1_privateExponent,
      { "privateExponent", "pkcs1.privateExponent",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_pkcs1_prime1,
      { "prime1", "pkcs1.prime1",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_pkcs1_prime2,
      { "prime2", "pkcs1.prime2",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_pkcs1_exponent1,
      { "exponent1", "pkcs1.exponent1",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_pkcs1_exponent2,
      { "exponent2", "pkcs1.exponent2",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_pkcs1_coefficient,
      { "coefficient", "pkcs1.coefficient",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_pkcs1_digestAlgorithm,
      { "digestAlgorithm", "pkcs1.digestAlgorithm",
        FT_NONE, BASE_NONE, NULL, 0,
        "DigestAlgorithmIdentifier", HFILL }},
    { &hf_pkcs1_digest,
      { "digest", "pkcs1.digest",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs1_p,
      { "p", "pkcs1.p",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_pkcs1_q,
      { "q", "pkcs1.q",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_pkcs1_g,
      { "g", "pkcs1.g",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_pkcs1_j,
      { "j", "pkcs1.j",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_pkcs1_validationParams,
      { "validationParams", "pkcs1.validationParams",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs1_seed,
      { "seed", "pkcs1.seed",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_pkcs1_pgenCounter,
      { "pgenCounter", "pkcs1.pgenCounter",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_pkcs1_hashAlgorithm,
      { "hashAlgorithm", "pkcs1.hashAlgorithm",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs1_maskGenAlgorithm,
      { "maskGenAlgorithm", "pkcs1.maskGenAlgorithm",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs1_saltLength,
      { "saltLength", "pkcs1.saltLength",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_pkcs1_trailerField,
      { "trailerField", "pkcs1.trailerField",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_pkcs1_namedCurve,
      { "namedCurve", "pkcs1.namedCurve",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_pkcs1_r,
      { "r", "pkcs1.r",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_pkcs1_s,
      { "s", "pkcs1.s",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},

/*--- End of included file: packet-pkcs1-hfarr.c ---*/
#line 56 "../../asn1/pkcs1/packet-pkcs1-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-pkcs1-ettarr.c ---*/
#line 1 "../../asn1/pkcs1/packet-pkcs1-ettarr.c"
    &ett_pkcs1_RSAPublicKey,
    &ett_pkcs1_RSAPrivateKey,
    &ett_pkcs1_DigestInfo,
    &ett_pkcs1_DSA_Params,
    &ett_pkcs1_DomainParameters,
    &ett_pkcs1_ValidationParams,
    &ett_pkcs1_RSASSA_PSS_params,
    &ett_pkcs1_ECParameters,
    &ett_pkcs1_DSA_Sig_Value,
    &ett_pkcs1_ECDSA_Sig_Value,

/*--- End of included file: packet-pkcs1-ettarr.c ---*/
#line 61 "../../asn1/pkcs1/packet-pkcs1-template.c"
  };

  /* Register protocol */
  proto_pkcs1 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_pkcs1, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_pkcs1 -------------------------------------------*/
void proto_reg_handoff_pkcs1(void) {

/*--- Included file: packet-pkcs1-dis-tab.c ---*/
#line 1 "../../asn1/pkcs1/packet-pkcs1-dis-tab.c"
  register_ber_oid_dissector("1.2.840.10040.4.1", dissect_DSA_Params_PDU, proto_pkcs1, "id-dsa");
  register_ber_oid_dissector("1.2.840.10046.2.1", dissect_DomainParameters_PDU, proto_pkcs1, "dhpublicnumber");
  register_ber_oid_dissector("2.16.840.1.101.2.1.1.22", dissect_KEA_Params_Id_PDU, proto_pkcs1, "id-keyExchangeAlgorithm");
  register_ber_oid_dissector("1.2.840.10045.2.1", dissect_ECParameters_PDU, proto_pkcs1, "id-ecPublicKey");
  register_ber_oid_dissector("1.3.132.1.12", dissect_ECParameters_PDU, proto_pkcs1, "id-ecDH");
  register_ber_oid_dissector("1.2.840.10045.2.13", dissect_ECParameters_PDU, proto_pkcs1, "id-ecMQV");
  register_ber_oid_dissector("1.2.840.113549.1.1.10", dissect_RSASSA_PSS_params_PDU, proto_pkcs1, "id-RSASSA-PSS");
  register_ber_oid_dissector("1.2.840.113549.1.1.8", dissect_HashAlgorithm_PDU, proto_pkcs1, "id-mgf1");


/*--- End of included file: packet-pkcs1-dis-tab.c ---*/
#line 76 "../../asn1/pkcs1/packet-pkcs1-template.c"

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
	oid_add_from_string("sect521r1","1.3.132.0.35")
;	oid_add_from_string("sect571k1","1.3.132.0.38");
	oid_add_from_string("sect571r1","1.3.132.0.39");

	/* sha2 family, see RFC3447 and http://www.oid-info.com/get/2.16.840.1.101.3.4.2 */
	oid_add_from_string("sha256", "2.16.840.1.101.3.4.2.1");

}

