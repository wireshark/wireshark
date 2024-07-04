/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-crmf.c                                                              */
/* asn2wrs.py -b -q -L -p crmf -c ./crmf.cnf -s ./packet-crmf-template -D . -O ../.. CRMF.asn */

/* packet-crmf.c
 * Routines for RFC2511 Certificate Request Message Format packet dissection
 *   Ronnie Sahlberg 2004
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
#include "packet-crmf.h"
#include "packet-cms.h"
#include "packet-pkix1explicit.h"
#include "packet-pkix1implicit.h"

#define PNAME  "Certificate Request Message Format"
#define PSNAME "CRMF"
#define PFNAME "crmf"

void proto_register_crmf(void);
void proto_reg_handoff_crmf(void);

/* Initialize the protocol and registered fields */
static int proto_crmf;
static int hf_crmf_type_oid;
static int hf_crmf_PBMParameter_PDU;              /* PBMParameter */
static int hf_crmf_RegToken_PDU;                  /* RegToken */
static int hf_crmf_Authenticator_PDU;             /* Authenticator */
static int hf_crmf_PKIPublicationInfo_PDU;        /* PKIPublicationInfo */
static int hf_crmf_PKIArchiveOptions_PDU;         /* PKIArchiveOptions */
static int hf_crmf_OldCertId_PDU;                 /* OldCertId */
static int hf_crmf_ProtocolEncrKey_PDU;           /* ProtocolEncrKey */
static int hf_crmf_UTF8Pairs_PDU;                 /* UTF8Pairs */
static int hf_crmf_CertReq_PDU;                   /* CertReq */
static int hf_crmf_EncKeyWithID_PDU;              /* EncKeyWithID */
static int hf_crmf_CertReqMessages_item;          /* CertReqMsg */
static int hf_crmf_certReq;                       /* CertRequest */
static int hf_crmf_popo;                          /* ProofOfPossession */
static int hf_crmf_regInfo;                       /* SEQUENCE_SIZE_1_MAX_OF_AttributeTypeAndValue */
static int hf_crmf_regInfo_item;                  /* AttributeTypeAndValue */
static int hf_crmf_certReqId;                     /* INTEGER */
static int hf_crmf_certTemplate;                  /* CertTemplate */
static int hf_crmf_controls;                      /* Controls */
static int hf_crmf_version;                       /* Version */
static int hf_crmf_serialNumber;                  /* INTEGER_MIN_MAX */
static int hf_crmf_signingAlg;                    /* AlgorithmIdentifier */
static int hf_crmf_template_issuer;               /* Name */
static int hf_crmf_validity;                      /* OptionalValidity */
static int hf_crmf_subject;                       /* Name */
static int hf_crmf_publicKey;                     /* SubjectPublicKeyInfo */
static int hf_crmf_issuerUID;                     /* UniqueIdentifier */
static int hf_crmf_subjectUID;                    /* UniqueIdentifier */
static int hf_crmf_extensions;                    /* Extensions */
static int hf_crmf_notBefore;                     /* Time */
static int hf_crmf_notAfter;                      /* Time */
static int hf_crmf_Controls_item;                 /* AttributeTypeAndValue */
static int hf_crmf_type;                          /* T_type */
static int hf_crmf_value;                         /* T_value */
static int hf_crmf_raVerified;                    /* NULL */
static int hf_crmf_signature;                     /* POPOSigningKey */
static int hf_crmf_keyEncipherment;               /* POPOPrivKey */
static int hf_crmf_keyAgreement;                  /* POPOPrivKey */
static int hf_crmf_poposkInput;                   /* POPOSigningKeyInput */
static int hf_crmf_algorithmIdentifier;           /* AlgorithmIdentifier */
static int hf_crmf_sk_signature;                  /* BIT_STRING */
static int hf_crmf_authInfo;                      /* T_authInfo */
static int hf_crmf_sender;                        /* GeneralName */
static int hf_crmf_publicKeyMAC;                  /* PKMACValue */
static int hf_crmf_algId;                         /* AlgorithmIdentifier */
static int hf_crmf_pkmac_value;                   /* BIT_STRING */
static int hf_crmf_salt;                          /* OCTET_STRING */
static int hf_crmf_owf;                           /* AlgorithmIdentifier */
static int hf_crmf_iterationCount;                /* INTEGER */
static int hf_crmf_mac;                           /* AlgorithmIdentifier */
static int hf_crmf_thisMessage;                   /* BIT_STRING */
static int hf_crmf_subsequentMessage;             /* SubsequentMessage */
static int hf_crmf_dhMAC;                         /* BIT_STRING */
static int hf_crmf_agreeMAC;                      /* PKMACValue */
static int hf_crmf_encryptedKey;                  /* EnvelopedData */
static int hf_crmf_action;                        /* T_action */
static int hf_crmf_pubInfos;                      /* SEQUENCE_SIZE_1_MAX_OF_SinglePubInfo */
static int hf_crmf_pubInfos_item;                 /* SinglePubInfo */
static int hf_crmf_pubMethod;                     /* T_pubMethod */
static int hf_crmf_pubLocation;                   /* GeneralName */
static int hf_crmf_encryptedPrivKey;              /* EncryptedKey */
static int hf_crmf_keyGenParameters;              /* KeyGenParameters */
static int hf_crmf_archiveRemGenPrivKey;          /* BOOLEAN */
static int hf_crmf_encryptedValue;                /* EncryptedValue */
static int hf_crmf_envelopedData;                 /* EnvelopedData */
static int hf_crmf_intendedAlg;                   /* AlgorithmIdentifier */
static int hf_crmf_symmAlg;                       /* AlgorithmIdentifier */
static int hf_crmf_encSymmKey;                    /* BIT_STRING */
static int hf_crmf_keyAlg;                        /* AlgorithmIdentifier */
static int hf_crmf_valueHint;                     /* OCTET_STRING */
static int hf_crmf_encValue;                      /* BIT_STRING */
static int hf_crmf_issuer;                        /* GeneralName */
static int hf_crmf_enckeywid_privkey;             /* PrivateKeyInfo */
static int hf_crmf_identifier;                    /* T_identifier */
static int hf_crmf_string;                        /* UTF8String */
static int hf_crmf_generalName;                   /* GeneralName */
static int hf_crmf_privkey_version;               /* INTEGER */
static int hf_crmf_privateKeyAlgorithm;           /* AlgorithmIdentifier */
static int hf_crmf_privateKey;                    /* OCTET_STRING */
static int hf_crmf_attributes;                    /* Attributes */
static int hf_crmf_Attributes_item;               /* Attribute */

/* Initialize the subtree pointers */
static int ett_crmf_CertReqMessages;
static int ett_crmf_CertReqMsg;
static int ett_crmf_SEQUENCE_SIZE_1_MAX_OF_AttributeTypeAndValue;
static int ett_crmf_CertRequest;
static int ett_crmf_CertTemplate;
static int ett_crmf_OptionalValidity;
static int ett_crmf_Controls;
static int ett_crmf_AttributeTypeAndValue;
static int ett_crmf_ProofOfPossession;
static int ett_crmf_POPOSigningKey;
static int ett_crmf_POPOSigningKeyInput;
static int ett_crmf_T_authInfo;
static int ett_crmf_PKMACValue;
static int ett_crmf_PBMParameter;
static int ett_crmf_POPOPrivKey;
static int ett_crmf_PKIPublicationInfo;
static int ett_crmf_SEQUENCE_SIZE_1_MAX_OF_SinglePubInfo;
static int ett_crmf_SinglePubInfo;
static int ett_crmf_PKIArchiveOptions;
static int ett_crmf_EncryptedKey;
static int ett_crmf_EncryptedValue;
static int ett_crmf_CertId;
static int ett_crmf_EncKeyWithID;
static int ett_crmf_T_identifier;
static int ett_crmf_PrivateKeyInfo;
static int ett_crmf_Attributes;


static int
dissect_crmf_INTEGER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_crmf_INTEGER_MIN_MAX(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer64(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t OptionalValidity_sequence[] = {
  { &hf_crmf_notBefore      , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pkix1explicit_Time },
  { &hf_crmf_notAfter       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pkix1explicit_Time },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_crmf_OptionalValidity(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OptionalValidity_sequence, hf_index, ett_crmf_OptionalValidity);

  return offset;
}


static const ber_sequence_t CertTemplate_sequence[] = {
  { &hf_crmf_version        , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pkix1explicit_Version },
  { &hf_crmf_serialNumber   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_crmf_INTEGER_MIN_MAX },
  { &hf_crmf_signingAlg     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pkix1explicit_AlgorithmIdentifier },
  { &hf_crmf_template_issuer, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pkix1explicit_Name },
  { &hf_crmf_validity       , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_crmf_OptionalValidity },
  { &hf_crmf_subject        , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pkix1explicit_Name },
  { &hf_crmf_publicKey      , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pkix1explicit_SubjectPublicKeyInfo },
  { &hf_crmf_issuerUID      , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pkix1explicit_UniqueIdentifier },
  { &hf_crmf_subjectUID     , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pkix1explicit_UniqueIdentifier },
  { &hf_crmf_extensions     , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pkix1explicit_Extensions },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_crmf_CertTemplate(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CertTemplate_sequence, hf_index, ett_crmf_CertTemplate);

  return offset;
}



static int
dissect_crmf_T_type(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_crmf_type_oid, &actx->external.direct_reference);

  return offset;
}



static int
dissect_crmf_T_value(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset=call_ber_oid_callback(actx->external.direct_reference, tvb, offset, actx->pinfo, tree, NULL);


  return offset;
}


static const ber_sequence_t AttributeTypeAndValue_sequence[] = {
  { &hf_crmf_type           , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_crmf_T_type },
  { &hf_crmf_value          , BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_crmf_T_value },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_crmf_AttributeTypeAndValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttributeTypeAndValue_sequence, hf_index, ett_crmf_AttributeTypeAndValue);

  return offset;
}


static const ber_sequence_t Controls_sequence_of[1] = {
  { &hf_crmf_Controls_item  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_crmf_AttributeTypeAndValue },
};

static int
dissect_crmf_Controls(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Controls_sequence_of, hf_index, ett_crmf_Controls);

  return offset;
}


static const ber_sequence_t CertRequest_sequence[] = {
  { &hf_crmf_certReqId      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_crmf_INTEGER },
  { &hf_crmf_certTemplate   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_crmf_CertTemplate },
  { &hf_crmf_controls       , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_crmf_Controls },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_crmf_CertRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CertRequest_sequence, hf_index, ett_crmf_CertRequest);

  return offset;
}



static int
dissect_crmf_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_crmf_BIT_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
                                    NULL);

  return offset;
}


static const ber_sequence_t PKMACValue_sequence[] = {
  { &hf_crmf_algId          , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_AlgorithmIdentifier },
  { &hf_crmf_pkmac_value    , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_crmf_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_crmf_PKMACValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PKMACValue_sequence, hf_index, ett_crmf_PKMACValue);

  return offset;
}


static const value_string crmf_T_authInfo_vals[] = {
  {   0, "sender" },
  {   1, "publicKeyMAC" },
  { 0, NULL }
};

static const ber_choice_t T_authInfo_choice[] = {
  {   0, &hf_crmf_sender         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_pkix1implicit_GeneralName },
  {   1, &hf_crmf_publicKeyMAC   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_crmf_PKMACValue },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_crmf_T_authInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_authInfo_choice, hf_index, ett_crmf_T_authInfo,
                                 NULL);

  return offset;
}


static const ber_sequence_t POPOSigningKeyInput_sequence[] = {
  { &hf_crmf_authInfo       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_crmf_T_authInfo },
  { &hf_crmf_publicKey      , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_SubjectPublicKeyInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_crmf_POPOSigningKeyInput(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   POPOSigningKeyInput_sequence, hf_index, ett_crmf_POPOSigningKeyInput);

  return offset;
}


static const ber_sequence_t POPOSigningKey_sequence[] = {
  { &hf_crmf_poposkInput    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_crmf_POPOSigningKeyInput },
  { &hf_crmf_algorithmIdentifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_AlgorithmIdentifier },
  { &hf_crmf_sk_signature   , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_crmf_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_crmf_POPOSigningKey(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   POPOSigningKey_sequence, hf_index, ett_crmf_POPOSigningKey);

  return offset;
}


static const value_string crmf_SubsequentMessage_vals[] = {
  {   0, "encrCert" },
  {   1, "challengeResp" },
  { 0, NULL }
};


static int
dissect_crmf_SubsequentMessage(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string crmf_POPOPrivKey_vals[] = {
  {   0, "thisMessage" },
  {   1, "subsequentMessage" },
  {   2, "dhMAC" },
  {   3, "agreeMAC" },
  {   4, "encryptedKey" },
  { 0, NULL }
};

static const ber_choice_t POPOPrivKey_choice[] = {
  {   0, &hf_crmf_thisMessage    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_crmf_BIT_STRING },
  {   1, &hf_crmf_subsequentMessage, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_crmf_SubsequentMessage },
  {   2, &hf_crmf_dhMAC          , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_crmf_BIT_STRING },
  {   3, &hf_crmf_agreeMAC       , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_crmf_PKMACValue },
  {   4, &hf_crmf_encryptedKey   , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_cms_EnvelopedData },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_crmf_POPOPrivKey(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 POPOPrivKey_choice, hf_index, ett_crmf_POPOPrivKey,
                                 NULL);

  return offset;
}


static const value_string crmf_ProofOfPossession_vals[] = {
  {   0, "raVerified" },
  {   1, "signature" },
  {   2, "keyEncipherment" },
  {   3, "keyAgreement" },
  { 0, NULL }
};

static const ber_choice_t ProofOfPossession_choice[] = {
  {   0, &hf_crmf_raVerified     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_crmf_NULL },
  {   1, &hf_crmf_signature      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_crmf_POPOSigningKey },
  {   2, &hf_crmf_keyEncipherment, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_crmf_POPOPrivKey },
  {   3, &hf_crmf_keyAgreement   , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_crmf_POPOPrivKey },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_crmf_ProofOfPossession(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ProofOfPossession_choice, hf_index, ett_crmf_ProofOfPossession,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_AttributeTypeAndValue_sequence_of[1] = {
  { &hf_crmf_regInfo_item   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_crmf_AttributeTypeAndValue },
};

static int
dissect_crmf_SEQUENCE_SIZE_1_MAX_OF_AttributeTypeAndValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_AttributeTypeAndValue_sequence_of, hf_index, ett_crmf_SEQUENCE_SIZE_1_MAX_OF_AttributeTypeAndValue);

  return offset;
}


static const ber_sequence_t CertReqMsg_sequence[] = {
  { &hf_crmf_certReq        , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_crmf_CertRequest },
  { &hf_crmf_popo           , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_crmf_ProofOfPossession },
  { &hf_crmf_regInfo        , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_crmf_SEQUENCE_SIZE_1_MAX_OF_AttributeTypeAndValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_crmf_CertReqMsg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CertReqMsg_sequence, hf_index, ett_crmf_CertReqMsg);

  return offset;
}


static const ber_sequence_t CertReqMessages_sequence_of[1] = {
  { &hf_crmf_CertReqMessages_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_crmf_CertReqMsg },
};

int
dissect_crmf_CertReqMessages(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      CertReqMessages_sequence_of, hf_index, ett_crmf_CertReqMessages);

  return offset;
}



static int
dissect_crmf_OCTET_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t PBMParameter_sequence[] = {
  { &hf_crmf_salt           , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_crmf_OCTET_STRING },
  { &hf_crmf_owf            , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_AlgorithmIdentifier },
  { &hf_crmf_iterationCount , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_crmf_INTEGER },
  { &hf_crmf_mac            , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_AlgorithmIdentifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_crmf_PBMParameter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PBMParameter_sequence, hf_index, ett_crmf_PBMParameter);

  return offset;
}



static int
dissect_crmf_RegToken(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_crmf_Authenticator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string crmf_T_action_vals[] = {
  {   0, "dontPublish" },
  {   1, "pleasePublish" },
  { 0, NULL }
};


static int
dissect_crmf_T_action(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string crmf_T_pubMethod_vals[] = {
  {   0, "dontCare" },
  {   1, "x500" },
  {   2, "web" },
  {   3, "ldap" },
  { 0, NULL }
};


static int
dissect_crmf_T_pubMethod(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t SinglePubInfo_sequence[] = {
  { &hf_crmf_pubMethod      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_crmf_T_pubMethod },
  { &hf_crmf_pubLocation    , BER_CLASS_CON, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_pkix1implicit_GeneralName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_crmf_SinglePubInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SinglePubInfo_sequence, hf_index, ett_crmf_SinglePubInfo);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_SinglePubInfo_sequence_of[1] = {
  { &hf_crmf_pubInfos_item  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_crmf_SinglePubInfo },
};

static int
dissect_crmf_SEQUENCE_SIZE_1_MAX_OF_SinglePubInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_SinglePubInfo_sequence_of, hf_index, ett_crmf_SEQUENCE_SIZE_1_MAX_OF_SinglePubInfo);

  return offset;
}


static const ber_sequence_t PKIPublicationInfo_sequence[] = {
  { &hf_crmf_action         , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_crmf_T_action },
  { &hf_crmf_pubInfos       , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_crmf_SEQUENCE_SIZE_1_MAX_OF_SinglePubInfo },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_crmf_PKIPublicationInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PKIPublicationInfo_sequence, hf_index, ett_crmf_PKIPublicationInfo);

  return offset;
}


static const ber_sequence_t EncryptedValue_sequence[] = {
  { &hf_crmf_intendedAlg    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pkix1explicit_AlgorithmIdentifier },
  { &hf_crmf_symmAlg        , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pkix1explicit_AlgorithmIdentifier },
  { &hf_crmf_encSymmKey     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_crmf_BIT_STRING },
  { &hf_crmf_keyAlg         , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pkix1explicit_AlgorithmIdentifier },
  { &hf_crmf_valueHint      , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_crmf_OCTET_STRING },
  { &hf_crmf_encValue       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_crmf_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_crmf_EncryptedValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EncryptedValue_sequence, hf_index, ett_crmf_EncryptedValue);

  return offset;
}


static const value_string crmf_EncryptedKey_vals[] = {
  {   0, "encryptedValue" },
  {   1, "envelopedData" },
  { 0, NULL }
};

static const ber_choice_t EncryptedKey_choice[] = {
  {   0, &hf_crmf_encryptedValue , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_crmf_EncryptedValue },
  {   1, &hf_crmf_envelopedData  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_cms_EnvelopedData },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_crmf_EncryptedKey(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 EncryptedKey_choice, hf_index, ett_crmf_EncryptedKey,
                                 NULL);

  return offset;
}



static int
dissect_crmf_KeyGenParameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_crmf_BOOLEAN(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const value_string crmf_PKIArchiveOptions_vals[] = {
  {   0, "encryptedPrivKey" },
  {   1, "keyGenParameters" },
  {   2, "archiveRemGenPrivKey" },
  { 0, NULL }
};

static const ber_choice_t PKIArchiveOptions_choice[] = {
  {   0, &hf_crmf_encryptedPrivKey, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_crmf_EncryptedKey },
  {   1, &hf_crmf_keyGenParameters, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_crmf_KeyGenParameters },
  {   2, &hf_crmf_archiveRemGenPrivKey, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_crmf_BOOLEAN },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_crmf_PKIArchiveOptions(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PKIArchiveOptions_choice, hf_index, ett_crmf_PKIArchiveOptions,
                                 NULL);

  return offset;
}


static const ber_sequence_t CertId_sequence[] = {
  { &hf_crmf_issuer         , BER_CLASS_CON, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_pkix1implicit_GeneralName },
  { &hf_crmf_serialNumber   , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_crmf_INTEGER_MIN_MAX },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_crmf_CertId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CertId_sequence, hf_index, ett_crmf_CertId);

  return offset;
}



static int
dissect_crmf_OldCertId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_crmf_CertId(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_crmf_ProtocolEncrKey(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_pkix1explicit_SubjectPublicKeyInfo(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_crmf_UTF8Pairs(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_crmf_CertReq(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_crmf_CertRequest(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t Attributes_set_of[1] = {
  { &hf_crmf_Attributes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_Attribute },
};

static int
dissect_crmf_Attributes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 Attributes_set_of, hf_index, ett_crmf_Attributes);

  return offset;
}


static const ber_sequence_t PrivateKeyInfo_sequence[] = {
  { &hf_crmf_privkey_version, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_crmf_INTEGER },
  { &hf_crmf_privateKeyAlgorithm, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_AlgorithmIdentifier },
  { &hf_crmf_privateKey     , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_crmf_OCTET_STRING },
  { &hf_crmf_attributes     , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_crmf_Attributes },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_crmf_PrivateKeyInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PrivateKeyInfo_sequence, hf_index, ett_crmf_PrivateKeyInfo);

  return offset;
}



static int
dissect_crmf_UTF8String(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string crmf_T_identifier_vals[] = {
  {   0, "string" },
  {   1, "generalName" },
  { 0, NULL }
};

static const ber_choice_t T_identifier_choice[] = {
  {   0, &hf_crmf_string         , BER_CLASS_UNI, BER_UNI_TAG_UTF8String, BER_FLAGS_NOOWNTAG, dissect_crmf_UTF8String },
  {   1, &hf_crmf_generalName    , BER_CLASS_CON, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_pkix1implicit_GeneralName },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_crmf_T_identifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_identifier_choice, hf_index, ett_crmf_T_identifier,
                                 NULL);

  return offset;
}


static const ber_sequence_t EncKeyWithID_sequence[] = {
  { &hf_crmf_enckeywid_privkey, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_crmf_PrivateKeyInfo },
  { &hf_crmf_identifier     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_crmf_T_identifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_crmf_EncKeyWithID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EncKeyWithID_sequence, hf_index, ett_crmf_EncKeyWithID);

  return offset;
}

/*--- PDUs ---*/

static int dissect_PBMParameter_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_crmf_PBMParameter(false, tvb, offset, &asn1_ctx, tree, hf_crmf_PBMParameter_PDU);
  return offset;
}
static int dissect_RegToken_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_crmf_RegToken(false, tvb, offset, &asn1_ctx, tree, hf_crmf_RegToken_PDU);
  return offset;
}
static int dissect_Authenticator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_crmf_Authenticator(false, tvb, offset, &asn1_ctx, tree, hf_crmf_Authenticator_PDU);
  return offset;
}
static int dissect_PKIPublicationInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_crmf_PKIPublicationInfo(false, tvb, offset, &asn1_ctx, tree, hf_crmf_PKIPublicationInfo_PDU);
  return offset;
}
static int dissect_PKIArchiveOptions_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_crmf_PKIArchiveOptions(false, tvb, offset, &asn1_ctx, tree, hf_crmf_PKIArchiveOptions_PDU);
  return offset;
}
static int dissect_OldCertId_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_crmf_OldCertId(false, tvb, offset, &asn1_ctx, tree, hf_crmf_OldCertId_PDU);
  return offset;
}
static int dissect_ProtocolEncrKey_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_crmf_ProtocolEncrKey(false, tvb, offset, &asn1_ctx, tree, hf_crmf_ProtocolEncrKey_PDU);
  return offset;
}
static int dissect_UTF8Pairs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_crmf_UTF8Pairs(false, tvb, offset, &asn1_ctx, tree, hf_crmf_UTF8Pairs_PDU);
  return offset;
}
static int dissect_CertReq_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_crmf_CertReq(false, tvb, offset, &asn1_ctx, tree, hf_crmf_CertReq_PDU);
  return offset;
}
static int dissect_EncKeyWithID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_crmf_EncKeyWithID(false, tvb, offset, &asn1_ctx, tree, hf_crmf_EncKeyWithID_PDU);
  return offset;
}



/*--- proto_register_crmf ----------------------------------------------*/
void proto_register_crmf(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_crmf_type_oid,
      { "Type", "crmf.type.oid",
        FT_STRING, BASE_NONE, NULL, 0,
        "Type of AttributeTypeAndValue", HFILL }},
    { &hf_crmf_PBMParameter_PDU,
      { "PBMParameter", "crmf.PBMParameter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_crmf_RegToken_PDU,
      { "RegToken", "crmf.RegToken",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_crmf_Authenticator_PDU,
      { "Authenticator", "crmf.Authenticator",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_crmf_PKIPublicationInfo_PDU,
      { "PKIPublicationInfo", "crmf.PKIPublicationInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_crmf_PKIArchiveOptions_PDU,
      { "PKIArchiveOptions", "crmf.PKIArchiveOptions",
        FT_UINT32, BASE_DEC, VALS(crmf_PKIArchiveOptions_vals), 0,
        NULL, HFILL }},
    { &hf_crmf_OldCertId_PDU,
      { "OldCertId", "crmf.OldCertId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_crmf_ProtocolEncrKey_PDU,
      { "ProtocolEncrKey", "crmf.ProtocolEncrKey_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_crmf_UTF8Pairs_PDU,
      { "UTF8Pairs", "crmf.UTF8Pairs",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_crmf_CertReq_PDU,
      { "CertReq", "crmf.CertReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_crmf_EncKeyWithID_PDU,
      { "EncKeyWithID", "crmf.EncKeyWithID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_crmf_CertReqMessages_item,
      { "CertReqMsg", "crmf.CertReqMsg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_crmf_certReq,
      { "certReq", "crmf.certReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertRequest", HFILL }},
    { &hf_crmf_popo,
      { "popo", "crmf.popo",
        FT_UINT32, BASE_DEC, VALS(crmf_ProofOfPossession_vals), 0,
        "ProofOfPossession", HFILL }},
    { &hf_crmf_regInfo,
      { "regInfo", "crmf.regInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_AttributeTypeAndValue", HFILL }},
    { &hf_crmf_regInfo_item,
      { "AttributeTypeAndValue", "crmf.AttributeTypeAndValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_crmf_certReqId,
      { "certReqId", "crmf.certReqId",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_crmf_certTemplate,
      { "certTemplate", "crmf.certTemplate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_crmf_controls,
      { "controls", "crmf.controls",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_crmf_version,
      { "version", "crmf.version",
        FT_INT32, BASE_DEC, VALS(pkix1explicit_Version_vals), 0,
        NULL, HFILL }},
    { &hf_crmf_serialNumber,
      { "serialNumber", "crmf.serialNumber",
        FT_INT64, BASE_DEC, NULL, 0,
        "INTEGER_MIN_MAX", HFILL }},
    { &hf_crmf_signingAlg,
      { "signingAlg", "crmf.signingAlg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_crmf_template_issuer,
      { "issuer", "crmf.issuer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Name", HFILL }},
    { &hf_crmf_validity,
      { "validity", "crmf.validity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "OptionalValidity", HFILL }},
    { &hf_crmf_subject,
      { "subject", "crmf.subject",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Name", HFILL }},
    { &hf_crmf_publicKey,
      { "publicKey", "crmf.publicKey_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SubjectPublicKeyInfo", HFILL }},
    { &hf_crmf_issuerUID,
      { "issuerUID", "crmf.issuerUID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "UniqueIdentifier", HFILL }},
    { &hf_crmf_subjectUID,
      { "subjectUID", "crmf.subjectUID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "UniqueIdentifier", HFILL }},
    { &hf_crmf_extensions,
      { "extensions", "crmf.extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_crmf_notBefore,
      { "notBefore", "crmf.notBefore",
        FT_UINT32, BASE_DEC, VALS(pkix1explicit_Time_vals), 0,
        "Time", HFILL }},
    { &hf_crmf_notAfter,
      { "notAfter", "crmf.notAfter",
        FT_UINT32, BASE_DEC, VALS(pkix1explicit_Time_vals), 0,
        "Time", HFILL }},
    { &hf_crmf_Controls_item,
      { "AttributeTypeAndValue", "crmf.AttributeTypeAndValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_crmf_type,
      { "type", "crmf.type",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_crmf_value,
      { "value", "crmf.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_crmf_raVerified,
      { "raVerified", "crmf.raVerified_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_crmf_signature,
      { "signature", "crmf.signature_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "POPOSigningKey", HFILL }},
    { &hf_crmf_keyEncipherment,
      { "keyEncipherment", "crmf.keyEncipherment",
        FT_UINT32, BASE_DEC, VALS(crmf_POPOPrivKey_vals), 0,
        "POPOPrivKey", HFILL }},
    { &hf_crmf_keyAgreement,
      { "keyAgreement", "crmf.keyAgreement",
        FT_UINT32, BASE_DEC, VALS(crmf_POPOPrivKey_vals), 0,
        "POPOPrivKey", HFILL }},
    { &hf_crmf_poposkInput,
      { "poposkInput", "crmf.poposkInput_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "POPOSigningKeyInput", HFILL }},
    { &hf_crmf_algorithmIdentifier,
      { "algorithmIdentifier", "crmf.algorithmIdentifier_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_crmf_sk_signature,
      { "signature", "crmf.signature",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_crmf_authInfo,
      { "authInfo", "crmf.authInfo",
        FT_UINT32, BASE_DEC, VALS(crmf_T_authInfo_vals), 0,
        NULL, HFILL }},
    { &hf_crmf_sender,
      { "sender", "crmf.sender",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GeneralName", HFILL }},
    { &hf_crmf_publicKeyMAC,
      { "publicKeyMAC", "crmf.publicKeyMAC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PKMACValue", HFILL }},
    { &hf_crmf_algId,
      { "algId", "crmf.algId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_crmf_pkmac_value,
      { "value", "crmf.value",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_crmf_salt,
      { "salt", "crmf.salt",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_crmf_owf,
      { "owf", "crmf.owf_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_crmf_iterationCount,
      { "iterationCount", "crmf.iterationCount",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_crmf_mac,
      { "mac", "crmf.mac_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_crmf_thisMessage,
      { "thisMessage", "crmf.thisMessage",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_crmf_subsequentMessage,
      { "subsequentMessage", "crmf.subsequentMessage",
        FT_INT32, BASE_DEC, VALS(crmf_SubsequentMessage_vals), 0,
        NULL, HFILL }},
    { &hf_crmf_dhMAC,
      { "dhMAC", "crmf.dhMAC",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_crmf_agreeMAC,
      { "agreeMAC", "crmf.agreeMAC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PKMACValue", HFILL }},
    { &hf_crmf_encryptedKey,
      { "encryptedKey", "crmf.encryptedKey_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EnvelopedData", HFILL }},
    { &hf_crmf_action,
      { "action", "crmf.action",
        FT_INT32, BASE_DEC, VALS(crmf_T_action_vals), 0,
        NULL, HFILL }},
    { &hf_crmf_pubInfos,
      { "pubInfos", "crmf.pubInfos",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_SinglePubInfo", HFILL }},
    { &hf_crmf_pubInfos_item,
      { "SinglePubInfo", "crmf.SinglePubInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_crmf_pubMethod,
      { "pubMethod", "crmf.pubMethod",
        FT_INT32, BASE_DEC, VALS(crmf_T_pubMethod_vals), 0,
        NULL, HFILL }},
    { &hf_crmf_pubLocation,
      { "pubLocation", "crmf.pubLocation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GeneralName", HFILL }},
    { &hf_crmf_encryptedPrivKey,
      { "encryptedPrivKey", "crmf.encryptedPrivKey",
        FT_UINT32, BASE_DEC, VALS(crmf_EncryptedKey_vals), 0,
        "EncryptedKey", HFILL }},
    { &hf_crmf_keyGenParameters,
      { "keyGenParameters", "crmf.keyGenParameters",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_crmf_archiveRemGenPrivKey,
      { "archiveRemGenPrivKey", "crmf.archiveRemGenPrivKey",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_crmf_encryptedValue,
      { "encryptedValue", "crmf.encryptedValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_crmf_envelopedData,
      { "envelopedData", "crmf.envelopedData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_crmf_intendedAlg,
      { "intendedAlg", "crmf.intendedAlg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_crmf_symmAlg,
      { "symmAlg", "crmf.symmAlg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_crmf_encSymmKey,
      { "encSymmKey", "crmf.encSymmKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_crmf_keyAlg,
      { "keyAlg", "crmf.keyAlg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_crmf_valueHint,
      { "valueHint", "crmf.valueHint",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_crmf_encValue,
      { "encValue", "crmf.encValue",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_crmf_issuer,
      { "issuer", "crmf.issuer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GeneralName", HFILL }},
    { &hf_crmf_enckeywid_privkey,
      { "privateKey", "crmf.privateKey_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PrivateKeyInfo", HFILL }},
    { &hf_crmf_identifier,
      { "identifier", "crmf.identifier",
        FT_UINT32, BASE_DEC, VALS(crmf_T_identifier_vals), 0,
        NULL, HFILL }},
    { &hf_crmf_string,
      { "string", "crmf.string",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_crmf_generalName,
      { "generalName", "crmf.generalName",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_crmf_privkey_version,
      { "version", "crmf.version",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_crmf_privateKeyAlgorithm,
      { "privateKeyAlgorithm", "crmf.privateKeyAlgorithm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_crmf_privateKey,
      { "privateKey", "crmf.privateKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_crmf_attributes,
      { "attributes", "crmf.attributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_crmf_Attributes_item,
      { "Attribute", "crmf.Attribute_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_crmf_CertReqMessages,
    &ett_crmf_CertReqMsg,
    &ett_crmf_SEQUENCE_SIZE_1_MAX_OF_AttributeTypeAndValue,
    &ett_crmf_CertRequest,
    &ett_crmf_CertTemplate,
    &ett_crmf_OptionalValidity,
    &ett_crmf_Controls,
    &ett_crmf_AttributeTypeAndValue,
    &ett_crmf_ProofOfPossession,
    &ett_crmf_POPOSigningKey,
    &ett_crmf_POPOSigningKeyInput,
    &ett_crmf_T_authInfo,
    &ett_crmf_PKMACValue,
    &ett_crmf_PBMParameter,
    &ett_crmf_POPOPrivKey,
    &ett_crmf_PKIPublicationInfo,
    &ett_crmf_SEQUENCE_SIZE_1_MAX_OF_SinglePubInfo,
    &ett_crmf_SinglePubInfo,
    &ett_crmf_PKIArchiveOptions,
    &ett_crmf_EncryptedKey,
    &ett_crmf_EncryptedValue,
    &ett_crmf_CertId,
    &ett_crmf_EncKeyWithID,
    &ett_crmf_T_identifier,
    &ett_crmf_PrivateKeyInfo,
    &ett_crmf_Attributes,
  };

  /* Register protocol */
  proto_crmf = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_crmf, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_crmf -------------------------------------------*/
void proto_reg_handoff_crmf(void) {
	oid_add_from_string("id-pkip","1.3.6.1.5.5.7.5");
	oid_add_from_string("id-regCtrl","1.3.6.1.5.5.7.5.1");
	oid_add_from_string("id-regInfo","1.3.6.1.5.5.7.5.2");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.1.21", dissect_EncKeyWithID_PDU, proto_crmf, "id-ct-encKeyWithID");
  register_ber_oid_dissector("1.2.840.113533.7.66.13", dissect_PBMParameter_PDU, proto_crmf, "PasswordBasedMac");
  register_ber_oid_dissector("1.3.6.1.5.5.7.5.1.1", dissect_RegToken_PDU, proto_crmf, "id-regCtrl-regToken");
  register_ber_oid_dissector("1.3.6.1.5.5.7.5.1.2", dissect_Authenticator_PDU, proto_crmf, "id-regCtrl-authenticator");
  register_ber_oid_dissector("1.3.6.1.5.5.7.5.1.3", dissect_PKIPublicationInfo_PDU, proto_crmf, "id-regCtrl-pkiPublicationInfo");
  register_ber_oid_dissector("1.3.6.1.5.5.7.5.1.4", dissect_PKIArchiveOptions_PDU, proto_crmf, "id-regCtrl-pkiArchiveOptions");
  register_ber_oid_dissector("1.3.6.1.5.5.7.5.1.5", dissect_OldCertId_PDU, proto_crmf, "id-regCtrl-oldCertID");
  register_ber_oid_dissector("1.3.6.1.5.5.7.5.1.6", dissect_ProtocolEncrKey_PDU, proto_crmf, "id-regCtrl-protocolEncrKey");
  register_ber_oid_dissector("1.3.6.1.5.5.7.5.2.1", dissect_UTF8Pairs_PDU, proto_crmf, "id-regInfo-utf8Pairs");
  register_ber_oid_dissector("1.3.6.1.5.5.7.5.2.2", dissect_CertReq_PDU, proto_crmf, "id-regInfo-certReq");

}

