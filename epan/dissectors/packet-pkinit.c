/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-pkinit.c                                                            */
/* ../../tools/asn2wrs.py -b -p pkinit -c ./pkinit.cnf -s ./packet-pkinit-template -D . -O ../../epan/dissectors PKINIT.asn */

/* Input file: packet-pkinit-template.c */

#line 1 "../../asn1/pkinit/packet-pkinit-template.c"
/* packet-pkinit.c
 * Routines for PKINIT packet dissection
 *  Ronnie Sahlberg 2004
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
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-pkinit.h"
#include "packet-cms.h"
#include "packet-pkix1explicit.h"
#include "packet-kerberos.h"

#define PNAME  "PKINIT"
#define PSNAME "PKInit"
#define PFNAME "pkinit"

void proto_register_pkinit(void);
void proto_reg_handoff_pkinit(void);

/* Initialize the protocol and registered fields */
static int proto_pkinit = -1;

/*--- Included file: packet-pkinit-hf.c ---*/
#line 1 "../../asn1/pkinit/packet-pkinit-hf.c"
static int hf_pkinit_AuthPack_PDU = -1;           /* AuthPack */
static int hf_pkinit_KRB5PrincipalName_PDU = -1;  /* KRB5PrincipalName */
static int hf_pkinit_KDCDHKeyInfo_PDU = -1;       /* KDCDHKeyInfo */
static int hf_pkinit_signedAuthPack = -1;         /* ContentInfo */
static int hf_pkinit_trustedCertifiers = -1;      /* SEQUENCE_OF_TrustedCA */
static int hf_pkinit_trustedCertifiers_item = -1;  /* TrustedCA */
static int hf_pkinit_kdcCert = -1;                /* IssuerAndSerialNumber */
static int hf_pkinit_caName = -1;                 /* Name */
static int hf_pkinit_issuerAndSerial = -1;        /* IssuerAndSerialNumber */
static int hf_pkinit_pkAuthenticator = -1;        /* PKAuthenticator */
static int hf_pkinit_clientPublicValue = -1;      /* SubjectPublicKeyInfo */
static int hf_pkinit_supportedCMSTypes = -1;      /* SEQUENCE_OF_AlgorithmIdentifier */
static int hf_pkinit_supportedCMSTypes_item = -1;  /* AlgorithmIdentifier */
static int hf_pkinit_cusec = -1;                  /* INTEGER */
static int hf_pkinit_ctime = -1;                  /* KerberosTime */
static int hf_pkinit_paNonce = -1;                /* INTEGER_0_4294967295 */
static int hf_pkinit_paChecksum = -1;             /* Checksum */
static int hf_pkinit_realm = -1;                  /* Realm */
static int hf_pkinit_principalName = -1;          /* PrincipalName */
static int hf_pkinit_dhSignedData = -1;           /* ContentInfo */
static int hf_pkinit_encKeyPack = -1;             /* ContentInfo */
static int hf_pkinit_subjectPublicKey = -1;       /* BIT_STRING */
static int hf_pkinit_dhNonce = -1;                /* INTEGER */
static int hf_pkinit_dhKeyExpiration = -1;        /* KerberosTime */

/*--- End of included file: packet-pkinit-hf.c ---*/
#line 46 "../../asn1/pkinit/packet-pkinit-template.c"

/* Initialize the subtree pointers */

/*--- Included file: packet-pkinit-ett.c ---*/
#line 1 "../../asn1/pkinit/packet-pkinit-ett.c"
static gint ett_pkinit_PaPkAsReq = -1;
static gint ett_pkinit_SEQUENCE_OF_TrustedCA = -1;
static gint ett_pkinit_TrustedCA = -1;
static gint ett_pkinit_AuthPack = -1;
static gint ett_pkinit_SEQUENCE_OF_AlgorithmIdentifier = -1;
static gint ett_pkinit_PKAuthenticator = -1;
static gint ett_pkinit_KRB5PrincipalName = -1;
static gint ett_pkinit_PaPkAsRep = -1;
static gint ett_pkinit_KDCDHKeyInfo = -1;

/*--- End of included file: packet-pkinit-ett.c ---*/
#line 49 "../../asn1/pkinit/packet-pkinit-template.c"

static int dissect_KerberosV5Spec2_KerberosTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset,  asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_);
static int dissect_KerberosV5Spec2_Checksum(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset,  asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_);
static int dissect_KerberosV5Spec2_Realm(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset,  asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_);
static int dissect_KerberosV5Spec2_PrincipalName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset,  asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_);


/*--- Included file: packet-pkinit-fn.c ---*/
#line 1 "../../asn1/pkinit/packet-pkinit-fn.c"

static const value_string pkinit_TrustedCA_vals[] = {
  {   0, "caName" },
  {   2, "issuerAndSerial" },
  { 0, NULL }
};

static const ber_choice_t TrustedCA_choice[] = {
  {   0, &hf_pkinit_caName       , BER_CLASS_CON, 0, 0, dissect_pkix1explicit_Name },
  {   2, &hf_pkinit_issuerAndSerial, BER_CLASS_CON, 2, 0, dissect_cms_IssuerAndSerialNumber },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_pkinit_TrustedCA(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 TrustedCA_choice, hf_index, ett_pkinit_TrustedCA,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_TrustedCA_sequence_of[1] = {
  { &hf_pkinit_trustedCertifiers_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_pkinit_TrustedCA },
};

static int
dissect_pkinit_SEQUENCE_OF_TrustedCA(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_TrustedCA_sequence_of, hf_index, ett_pkinit_SEQUENCE_OF_TrustedCA);

  return offset;
}


static const ber_sequence_t PaPkAsReq_sequence[] = {
  { &hf_pkinit_signedAuthPack, BER_CLASS_CON, 0, 0, dissect_cms_ContentInfo },
  { &hf_pkinit_trustedCertifiers, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_pkinit_SEQUENCE_OF_TrustedCA },
  { &hf_pkinit_kdcCert      , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_cms_IssuerAndSerialNumber },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_pkinit_PaPkAsReq(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PaPkAsReq_sequence, hf_index, ett_pkinit_PaPkAsReq);

  return offset;
}



static int
dissect_pkinit_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_pkinit_INTEGER_0_4294967295(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t PKAuthenticator_sequence[] = {
  { &hf_pkinit_cusec        , BER_CLASS_CON, 0, 0, dissect_pkinit_INTEGER },
  { &hf_pkinit_ctime        , BER_CLASS_CON, 1, 0, dissect_KerberosV5Spec2_KerberosTime },
  { &hf_pkinit_paNonce      , BER_CLASS_CON, 2, 0, dissect_pkinit_INTEGER_0_4294967295 },
  { &hf_pkinit_paChecksum   , BER_CLASS_CON, 3, 0, dissect_KerberosV5Spec2_Checksum },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkinit_PKAuthenticator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PKAuthenticator_sequence, hf_index, ett_pkinit_PKAuthenticator);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_AlgorithmIdentifier_sequence_of[1] = {
  { &hf_pkinit_supportedCMSTypes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_AlgorithmIdentifier },
};

static int
dissect_pkinit_SEQUENCE_OF_AlgorithmIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_AlgorithmIdentifier_sequence_of, hf_index, ett_pkinit_SEQUENCE_OF_AlgorithmIdentifier);

  return offset;
}


static const ber_sequence_t AuthPack_sequence[] = {
  { &hf_pkinit_pkAuthenticator, BER_CLASS_CON, 0, 0, dissect_pkinit_PKAuthenticator },
  { &hf_pkinit_clientPublicValue, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_pkix1explicit_SubjectPublicKeyInfo },
  { &hf_pkinit_supportedCMSTypes, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_pkinit_SEQUENCE_OF_AlgorithmIdentifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkinit_AuthPack(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AuthPack_sequence, hf_index, ett_pkinit_AuthPack);

  return offset;
}


static const ber_sequence_t KRB5PrincipalName_sequence[] = {
  { &hf_pkinit_realm        , BER_CLASS_CON, 0, 0, dissect_KerberosV5Spec2_Realm },
  { &hf_pkinit_principalName, BER_CLASS_CON, 1, 0, dissect_KerberosV5Spec2_PrincipalName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkinit_KRB5PrincipalName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   KRB5PrincipalName_sequence, hf_index, ett_pkinit_KRB5PrincipalName);

  return offset;
}


const value_string pkinit_PaPkAsRep_vals[] = {
  {   0, "dhSignedData" },
  {   1, "encKeyPack" },
  { 0, NULL }
};

static const ber_choice_t PaPkAsRep_choice[] = {
  {   0, &hf_pkinit_dhSignedData , BER_CLASS_CON, 0, 0, dissect_cms_ContentInfo },
  {   1, &hf_pkinit_encKeyPack   , BER_CLASS_CON, 1, 0, dissect_cms_ContentInfo },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_pkinit_PaPkAsRep(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PaPkAsRep_choice, hf_index, ett_pkinit_PaPkAsRep,
                                 NULL);

  return offset;
}



static int
dissect_pkinit_BIT_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}


static const ber_sequence_t KDCDHKeyInfo_sequence[] = {
  { &hf_pkinit_subjectPublicKey, BER_CLASS_CON, 0, 0, dissect_pkinit_BIT_STRING },
  { &hf_pkinit_dhNonce      , BER_CLASS_CON, 1, 0, dissect_pkinit_INTEGER },
  { &hf_pkinit_dhKeyExpiration, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_KerberosV5Spec2_KerberosTime },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkinit_KDCDHKeyInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   KDCDHKeyInfo_sequence, hf_index, ett_pkinit_KDCDHKeyInfo);

  return offset;
}

/*--- PDUs ---*/

static void dissect_AuthPack_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_pkinit_AuthPack(FALSE, tvb, 0, &asn1_ctx, tree, hf_pkinit_AuthPack_PDU);
}
static void dissect_KRB5PrincipalName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_pkinit_KRB5PrincipalName(FALSE, tvb, 0, &asn1_ctx, tree, hf_pkinit_KRB5PrincipalName_PDU);
}
static void dissect_KDCDHKeyInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_pkinit_KDCDHKeyInfo(FALSE, tvb, 0, &asn1_ctx, tree, hf_pkinit_KDCDHKeyInfo_PDU);
}


/*--- End of included file: packet-pkinit-fn.c ---*/
#line 56 "../../asn1/pkinit/packet-pkinit-template.c"

int
dissect_pkinit_PA_PK_AS_REQ(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_) {
  offset = dissect_pkinit_PaPkAsReq(FALSE, tvb, offset, actx, tree, -1);
  return offset;
}

int
dissect_pkinit_PA_PK_AS_REP(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_) {
  offset = dissect_pkinit_PaPkAsRep(FALSE, tvb, offset, actx, tree, -1);
  return offset;
}

static int
dissect_KerberosV5Spec2_KerberosTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_) {
  offset = dissect_krb5_ctime(tree, tvb, offset, actx);
  return offset;
}

static int
dissect_KerberosV5Spec2_Checksum(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_) {
  offset = dissect_krb5_Checksum(tree, tvb, offset, actx);
  return offset;
}

static int
dissect_KerberosV5Spec2_Realm(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_) {
  offset = dissect_krb5_realm(tree, tvb, offset, actx);
  return offset;
}

static int
dissect_KerberosV5Spec2_PrincipalName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_) {
  offset = dissect_krb5_cname(tree, tvb, offset, actx);
  return offset;
}


/*--- proto_register_pkinit ----------------------------------------------*/
void proto_register_pkinit(void) {

  /* List of fields */
  static hf_register_info hf[] = {

/*--- Included file: packet-pkinit-hfarr.c ---*/
#line 1 "../../asn1/pkinit/packet-pkinit-hfarr.c"
    { &hf_pkinit_AuthPack_PDU,
      { "AuthPack", "pkinit.AuthPack_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkinit_KRB5PrincipalName_PDU,
      { "KRB5PrincipalName", "pkinit.KRB5PrincipalName_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkinit_KDCDHKeyInfo_PDU,
      { "KDCDHKeyInfo", "pkinit.KDCDHKeyInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkinit_signedAuthPack,
      { "signedAuthPack", "pkinit.signedAuthPack_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ContentInfo", HFILL }},
    { &hf_pkinit_trustedCertifiers,
      { "trustedCertifiers", "pkinit.trustedCertifiers",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_TrustedCA", HFILL }},
    { &hf_pkinit_trustedCertifiers_item,
      { "TrustedCA", "pkinit.TrustedCA",
        FT_UINT32, BASE_DEC, VALS(pkinit_TrustedCA_vals), 0,
        NULL, HFILL }},
    { &hf_pkinit_kdcCert,
      { "kdcCert", "pkinit.kdcCert_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IssuerAndSerialNumber", HFILL }},
    { &hf_pkinit_caName,
      { "caName", "pkinit.caName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Name", HFILL }},
    { &hf_pkinit_issuerAndSerial,
      { "issuerAndSerial", "pkinit.issuerAndSerial_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IssuerAndSerialNumber", HFILL }},
    { &hf_pkinit_pkAuthenticator,
      { "pkAuthenticator", "pkinit.pkAuthenticator_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkinit_clientPublicValue,
      { "clientPublicValue", "pkinit.clientPublicValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SubjectPublicKeyInfo", HFILL }},
    { &hf_pkinit_supportedCMSTypes,
      { "supportedCMSTypes", "pkinit.supportedCMSTypes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_AlgorithmIdentifier", HFILL }},
    { &hf_pkinit_supportedCMSTypes_item,
      { "AlgorithmIdentifier", "pkinit.AlgorithmIdentifier_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkinit_cusec,
      { "cusec", "pkinit.cusec",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_pkinit_ctime,
      { "ctime", "pkinit.ctime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "KerberosTime", HFILL }},
    { &hf_pkinit_paNonce,
      { "nonce", "pkinit.nonce",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_pkinit_paChecksum,
      { "paChecksum", "pkinit.paChecksum_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Checksum", HFILL }},
    { &hf_pkinit_realm,
      { "realm", "pkinit.realm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkinit_principalName,
      { "principalName", "pkinit.principalName_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkinit_dhSignedData,
      { "dhSignedData", "pkinit.dhSignedData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ContentInfo", HFILL }},
    { &hf_pkinit_encKeyPack,
      { "encKeyPack", "pkinit.encKeyPack_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ContentInfo", HFILL }},
    { &hf_pkinit_subjectPublicKey,
      { "subjectPublicKey", "pkinit.subjectPublicKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_pkinit_dhNonce,
      { "nonce", "pkinit.nonce",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_pkinit_dhKeyExpiration,
      { "dhKeyExpiration", "pkinit.dhKeyExpiration_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "KerberosTime", HFILL }},

/*--- End of included file: packet-pkinit-hfarr.c ---*/
#line 100 "../../asn1/pkinit/packet-pkinit-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-pkinit-ettarr.c ---*/
#line 1 "../../asn1/pkinit/packet-pkinit-ettarr.c"
    &ett_pkinit_PaPkAsReq,
    &ett_pkinit_SEQUENCE_OF_TrustedCA,
    &ett_pkinit_TrustedCA,
    &ett_pkinit_AuthPack,
    &ett_pkinit_SEQUENCE_OF_AlgorithmIdentifier,
    &ett_pkinit_PKAuthenticator,
    &ett_pkinit_KRB5PrincipalName,
    &ett_pkinit_PaPkAsRep,
    &ett_pkinit_KDCDHKeyInfo,

/*--- End of included file: packet-pkinit-ettarr.c ---*/
#line 105 "../../asn1/pkinit/packet-pkinit-template.c"
  };

  /* Register protocol */
  proto_pkinit = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_pkinit, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_pkinit -------------------------------------------*/
void proto_reg_handoff_pkinit(void) {

/*--- Included file: packet-pkinit-dis-tab.c ---*/
#line 1 "../../asn1/pkinit/packet-pkinit-dis-tab.c"
  register_ber_oid_dissector("1.3.6.1.5.2.3.1", dissect_AuthPack_PDU, proto_pkinit, "id-pkauthdata");
  register_ber_oid_dissector("1.3.6.1.5.2.3.2", dissect_KDCDHKeyInfo_PDU, proto_pkinit, "id-pkdhkeydata");
  register_ber_oid_dissector("1.3.6.1.5.2.2", dissect_KRB5PrincipalName_PDU, proto_pkinit, "id-pkinit-san");


/*--- End of included file: packet-pkinit-dis-tab.c ---*/
#line 120 "../../asn1/pkinit/packet-pkinit-template.c"
}

