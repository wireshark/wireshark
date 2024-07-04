/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-pkinit.c                                                            */
/* asn2wrs.py -b -q -L -p pkinit -c ./pkinit.cnf -s ./packet-pkinit-template -D . -O ../.. PKINIT.asn */

/* packet-pkinit.c
 * Routines for PKINIT packet dissection
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
#include <epan/asn1.h>
#include <epan/proto_data.h>

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
static int proto_pkinit;
static int hf_pkinit_AuthPack_PDU;                /* AuthPack */
static int hf_pkinit_KRB5PrincipalName_PDU;       /* KRB5PrincipalName */
static int hf_pkinit_KDCDHKeyInfo_PDU;            /* KDCDHKeyInfo */
static int hf_pkinit_signedAuthPack;              /* ContentInfo */
static int hf_pkinit_trustedCertifiers;           /* SEQUENCE_OF_TrustedCA */
static int hf_pkinit_trustedCertifiers_item;      /* TrustedCA */
static int hf_pkinit_kdcCert;                     /* IssuerAndSerialNumber */
static int hf_pkinit_caName;                      /* Name */
static int hf_pkinit_issuerAndSerial;             /* IssuerAndSerialNumber */
static int hf_pkinit_pkAuthenticator;             /* PKAuthenticator */
static int hf_pkinit_clientPublicValue;           /* SubjectPublicKeyInfo */
static int hf_pkinit_supportedCMSTypes;           /* SEQUENCE_OF_AlgorithmIdentifier */
static int hf_pkinit_supportedCMSTypes_item;      /* AlgorithmIdentifier */
static int hf_pkinit_clientDHNonce;               /* DHNonce */
static int hf_pkinit_cusec;                       /* INTEGER */
static int hf_pkinit_ctime;                       /* KerberosTime */
static int hf_pkinit_paNonce;                     /* INTEGER_0_4294967295 */
static int hf_pkinit_paChecksum;                  /* OCTET_STRING */
static int hf_pkinit_realm;                       /* Realm */
static int hf_pkinit_principalName;               /* PrincipalName */
static int hf_pkinit_dhSignedData;                /* ContentInfo */
static int hf_pkinit_encKeyPack;                  /* ContentInfo */
static int hf_pkinit_subjectPublicKey;            /* BIT_STRING */
static int hf_pkinit_dhNonce;                     /* INTEGER */
static int hf_pkinit_dhKeyExpiration;             /* KerberosTime */
static int hf_pkinit_kdcName;                     /* PrincipalName */
static int hf_pkinit_kdcRealm;                    /* Realm */
static int hf_pkinit_cusecWin2k;                  /* INTEGER_0_4294967295 */
static int hf_pkinit_paNonceWin2k;                /* INTEGER_M2147483648_2147483647 */
static int hf_pkinit_signed_auth_pack;            /* ContentInfo */
static int hf_pkinit_trusted_certifiers;          /* SEQUENCE_OF_TrustedCA */
static int hf_pkinit_trusted_certifiers_item;     /* TrustedCA */
static int hf_pkinit_kdc_cert;                    /* OCTET_STRING */
static int hf_pkinit_encryption_cert;             /* OCTET_STRING */

/* Initialize the subtree pointers */
static int ett_pkinit_PaPkAsReq;
static int ett_pkinit_SEQUENCE_OF_TrustedCA;
static int ett_pkinit_TrustedCA;
static int ett_pkinit_AuthPack;
static int ett_pkinit_SEQUENCE_OF_AlgorithmIdentifier;
static int ett_pkinit_PKAuthenticator;
static int ett_pkinit_KRB5PrincipalName;
static int ett_pkinit_PaPkAsRep;
static int ett_pkinit_KDCDHKeyInfo;
static int ett_pkinit_PKAuthenticator_Win2k;
static int ett_pkinit_PA_PK_AS_REQ_Win2k;

static int dissect_KerberosV5Spec2_KerberosTime(bool implicit_tag _U_, tvbuff_t *tvb, int offset,  asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_);
static int dissect_KerberosV5Spec2_Realm(bool implicit_tag _U_, tvbuff_t *tvb, int offset,  asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_);
static int dissect_KerberosV5Spec2_PrincipalName(bool implicit_tag _U_, tvbuff_t *tvb, int offset,  asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_);
static int dissect_pkinit_PKAuthenticator_Win2k(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);


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
dissect_pkinit_TrustedCA(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 TrustedCA_choice, hf_index, ett_pkinit_TrustedCA,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_TrustedCA_sequence_of[1] = {
  { &hf_pkinit_trustedCertifiers_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_pkinit_TrustedCA },
};

static int
dissect_pkinit_SEQUENCE_OF_TrustedCA(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_pkinit_PaPkAsReq(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PaPkAsReq_sequence, hf_index, ett_pkinit_PaPkAsReq);

  return offset;
}



static int
dissect_pkinit_DHNonce(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_pkinit_INTEGER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_pkinit_INTEGER_0_4294967295(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_pkinit_OCTET_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t PKAuthenticator_sequence[] = {
  { &hf_pkinit_cusec        , BER_CLASS_CON, 0, 0, dissect_pkinit_INTEGER },
  { &hf_pkinit_ctime        , BER_CLASS_CON, 1, 0, dissect_KerberosV5Spec2_KerberosTime },
  { &hf_pkinit_paNonce      , BER_CLASS_CON, 2, 0, dissect_pkinit_INTEGER_0_4294967295 },
  { &hf_pkinit_paChecksum   , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_pkinit_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkinit_PKAuthenticator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

	if (p_get_proto_data(actx->pinfo->pool, actx->pinfo, proto_pkinit, 0)) {
		return dissect_pkinit_PKAuthenticator_Win2k(implicit_tag, tvb, offset, actx, tree, hf_index);
	}
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PKAuthenticator_sequence, hf_index, ett_pkinit_PKAuthenticator);



  return offset;
}


static const ber_sequence_t SEQUENCE_OF_AlgorithmIdentifier_sequence_of[1] = {
  { &hf_pkinit_supportedCMSTypes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_AlgorithmIdentifier },
};

static int
dissect_pkinit_SEQUENCE_OF_AlgorithmIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_AlgorithmIdentifier_sequence_of, hf_index, ett_pkinit_SEQUENCE_OF_AlgorithmIdentifier);

  return offset;
}


static const ber_sequence_t AuthPack_sequence[] = {
  { &hf_pkinit_pkAuthenticator, BER_CLASS_CON, 0, 0, dissect_pkinit_PKAuthenticator },
  { &hf_pkinit_clientPublicValue, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_pkix1explicit_SubjectPublicKeyInfo },
  { &hf_pkinit_supportedCMSTypes, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_pkinit_SEQUENCE_OF_AlgorithmIdentifier },
  { &hf_pkinit_clientDHNonce, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_pkinit_DHNonce },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkinit_AuthPack(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_pkinit_KRB5PrincipalName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_pkinit_PaPkAsRep(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PaPkAsRep_choice, hf_index, ett_pkinit_PaPkAsRep,
                                 NULL);

  return offset;
}



static int
dissect_pkinit_BIT_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
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
dissect_pkinit_KDCDHKeyInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   KDCDHKeyInfo_sequence, hf_index, ett_pkinit_KDCDHKeyInfo);

  return offset;
}



static int
dissect_pkinit_INTEGER_M2147483648_2147483647(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t PKAuthenticator_Win2k_sequence[] = {
  { &hf_pkinit_kdcName      , BER_CLASS_CON, 0, 0, dissect_KerberosV5Spec2_PrincipalName },
  { &hf_pkinit_kdcRealm     , BER_CLASS_CON, 1, 0, dissect_KerberosV5Spec2_Realm },
  { &hf_pkinit_cusecWin2k   , BER_CLASS_CON, 2, 0, dissect_pkinit_INTEGER_0_4294967295 },
  { &hf_pkinit_ctime        , BER_CLASS_CON, 3, 0, dissect_KerberosV5Spec2_KerberosTime },
  { &hf_pkinit_paNonceWin2k , BER_CLASS_CON, 4, 0, dissect_pkinit_INTEGER_M2147483648_2147483647 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkinit_PKAuthenticator_Win2k(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PKAuthenticator_Win2k_sequence, hf_index, ett_pkinit_PKAuthenticator_Win2k);

  return offset;
}


static const ber_sequence_t PA_PK_AS_REQ_Win2k_sequence[] = {
  { &hf_pkinit_signed_auth_pack, BER_CLASS_CON, 0, 0, dissect_cms_ContentInfo },
  { &hf_pkinit_trusted_certifiers, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_pkinit_SEQUENCE_OF_TrustedCA },
  { &hf_pkinit_kdc_cert     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pkinit_OCTET_STRING },
  { &hf_pkinit_encryption_cert, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pkinit_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_pkinit_PA_PK_AS_REQ_Win2k(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	uint8_t v = 1;

	if (kerberos_is_win2k_pkinit(actx)) {
		p_set_proto_data(actx->pinfo->pool, actx->pinfo, proto_pkinit, 0, &v);
	}
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PA_PK_AS_REQ_Win2k_sequence, hf_index, ett_pkinit_PA_PK_AS_REQ_Win2k);

	if (kerberos_is_win2k_pkinit(actx)) {
		p_remove_proto_data(actx->pinfo->pool, actx->pinfo, proto_pkinit, 0);
	}


  return offset;
}



int
dissect_pkinit_PA_PK_AS_REP_Win2k(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_pkinit_PaPkAsRep(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}

/*--- PDUs ---*/

static int dissect_AuthPack_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_pkinit_AuthPack(false, tvb, offset, &asn1_ctx, tree, hf_pkinit_AuthPack_PDU);
  return offset;
}
static int dissect_KRB5PrincipalName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_pkinit_KRB5PrincipalName(false, tvb, offset, &asn1_ctx, tree, hf_pkinit_KRB5PrincipalName_PDU);
  return offset;
}
static int dissect_KDCDHKeyInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_pkinit_KDCDHKeyInfo(false, tvb, offset, &asn1_ctx, tree, hf_pkinit_KDCDHKeyInfo_PDU);
  return offset;
}


int
dissect_pkinit_PA_PK_AS_REQ(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_) {
  offset = dissect_pkinit_PaPkAsReq(false, tvb, offset, actx, tree, -1);
  return offset;
}

int
dissect_pkinit_PA_PK_AS_REP(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_) {
  offset = dissect_pkinit_PaPkAsRep(false, tvb, offset, actx, tree, -1);
  return offset;
}

static int
dissect_KerberosV5Spec2_KerberosTime(bool implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_) {
  offset = dissect_krb5_ctime(tree, tvb, offset, actx);
  return offset;
}

static int
dissect_KerberosV5Spec2_Realm(bool implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_) {
  offset = dissect_krb5_realm(tree, tvb, offset, actx);
  return offset;
}

static int
dissect_KerberosV5Spec2_PrincipalName(bool implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_) {
  offset = dissect_krb5_cname(tree, tvb, offset, actx);
  return offset;
}


/*--- proto_register_pkinit ----------------------------------------------*/
void proto_register_pkinit(void) {

  /* List of fields */
  static hf_register_info hf[] = {
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
    { &hf_pkinit_clientDHNonce,
      { "clientDHNonce", "pkinit.clientDHNonce",
        FT_BYTES, BASE_NONE, NULL, 0,
        "DHNonce", HFILL }},
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
      { "paChecksum", "pkinit.paChecksum",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
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
    { &hf_pkinit_kdcName,
      { "kdcName", "pkinit.kdcName_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PrincipalName", HFILL }},
    { &hf_pkinit_kdcRealm,
      { "kdcRealm", "pkinit.kdcRealm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Realm", HFILL }},
    { &hf_pkinit_cusecWin2k,
      { "cusec", "pkinit.cusec",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_pkinit_paNonceWin2k,
      { "nonce", "pkinit.nonce",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M2147483648_2147483647", HFILL }},
    { &hf_pkinit_signed_auth_pack,
      { "signed-auth-pack", "pkinit.signed_auth_pack_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ContentInfo", HFILL }},
    { &hf_pkinit_trusted_certifiers,
      { "trusted-certifiers", "pkinit.trusted_certifiers",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_TrustedCA", HFILL }},
    { &hf_pkinit_trusted_certifiers_item,
      { "TrustedCA", "pkinit.TrustedCA",
        FT_UINT32, BASE_DEC, VALS(pkinit_TrustedCA_vals), 0,
        NULL, HFILL }},
    { &hf_pkinit_kdc_cert,
      { "kdc-cert", "pkinit.kdc_cert",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_pkinit_encryption_cert,
      { "encryption-cert", "pkinit.encryption_cert",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_pkinit_PaPkAsReq,
    &ett_pkinit_SEQUENCE_OF_TrustedCA,
    &ett_pkinit_TrustedCA,
    &ett_pkinit_AuthPack,
    &ett_pkinit_SEQUENCE_OF_AlgorithmIdentifier,
    &ett_pkinit_PKAuthenticator,
    &ett_pkinit_KRB5PrincipalName,
    &ett_pkinit_PaPkAsRep,
    &ett_pkinit_KDCDHKeyInfo,
    &ett_pkinit_PKAuthenticator_Win2k,
    &ett_pkinit_PA_PK_AS_REQ_Win2k,
  };

  /* Register protocol */
  proto_pkinit = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_pkinit, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_pkinit -------------------------------------------*/
void proto_reg_handoff_pkinit(void) {
  register_ber_oid_dissector("1.3.6.1.5.2.3.1", dissect_AuthPack_PDU, proto_pkinit, "id-pkauthdata");
  register_ber_oid_dissector("1.3.6.1.5.2.3.2", dissect_KDCDHKeyInfo_PDU, proto_pkinit, "id-pkdhkeydata");
  register_ber_oid_dissector("1.3.6.1.5.2.2", dissect_KRB5PrincipalName_PDU, proto_pkinit, "id-pkinit-san");

}

