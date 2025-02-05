/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-akp.c                                                               */
/* asn2wrs.py -b -q -L -p akp -c ./akp.cnf -s ./packet-akp-template -D . -O ../.. AsymmetricKeyPackageModuleV1.asn */

/* packet-akp.c
 * Routines for Asymmetric Key Packages (formerly known as PKCS #8) dissection
 *
 * See <https://datatracker.ietf.org/doc/html/rfc5958>.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/asn1.h>
#include <wsutil/array.h>

#include "packet-ber.h"
#include "packet-cms.h"
#include "packet-pkcs12.h"
#include "packet-x509af.h"

#define PNAME  "Asymmetric Key Packages"
#define PSNAME "AKP"
#define PFNAME "akp"


void proto_register_akp(void);
void proto_reg_handoff_akp(void);

/* Initialize the protocol and registered fields */
static int proto_akp;

static int hf_akp_AsymmetricKeyPackage_PDU;       /* AsymmetricKeyPackage */
static int hf_akp_PrivateKeyInfo_PDU;             /* PrivateKeyInfo */
static int hf_akp_EncryptedPrivateKeyInfo_PDU;    /* EncryptedPrivateKeyInfo */
static int hf_akp_AsymmetricKeyPackage_item;      /* OneAsymmetricKey */
static int hf_akp_version;                        /* Version */
static int hf_akp_privateKeyAlgorithm;            /* PrivateKeyAlgorithmIdentifier */
static int hf_akp_privateKey;                     /* PrivateKey */
static int hf_akp_attributes;                     /* Attributes */
static int hf_akp_publicKey;                      /* PublicKey */
static int hf_akp_Attributes_item;                /* Attribute */
static int hf_akp_encryptionAlgorithm;            /* EncryptionAlgorithmIdentifier */
static int hf_akp_encryptedData;                  /* EncryptedData */

/* Initialize the subtree pointers */
static int ett_akp_AsymmetricKeyPackage;
static int ett_akp_OneAsymmetricKey;
static int ett_akp_Attributes;
static int ett_akp_EncryptedPrivateKeyInfo;

static int dissect_PrivateKeyInfo_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);


static const value_string akp_Version_vals[] = {
  {   0, "v1" },
  {   1, "v2" },
  { 0, NULL }
};


static int
dissect_akp_Version(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_akp_PrivateKeyAlgorithmIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_akp_PrivateKey(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t Attributes_set_of[1] = {
  { &hf_akp_Attributes_item , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_Attribute },
};

static int
dissect_akp_Attributes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 Attributes_set_of, hf_index, ett_akp_Attributes);

  return offset;
}



static int
dissect_akp_PublicKey(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
                                    NULL);

  return offset;
}


static const ber_sequence_t OneAsymmetricKey_sequence[] = {
  { &hf_akp_version         , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_akp_Version },
  { &hf_akp_privateKeyAlgorithm, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_akp_PrivateKeyAlgorithmIdentifier },
  { &hf_akp_privateKey      , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_akp_PrivateKey },
  { &hf_akp_attributes      , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_akp_Attributes },
  { &hf_akp_publicKey       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_akp_PublicKey },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_akp_OneAsymmetricKey(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OneAsymmetricKey_sequence, hf_index, ett_akp_OneAsymmetricKey);

  return offset;
}


static const ber_sequence_t AsymmetricKeyPackage_sequence_of[1] = {
  { &hf_akp_AsymmetricKeyPackage_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_akp_OneAsymmetricKey },
};

static int
dissect_akp_AsymmetricKeyPackage(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      AsymmetricKeyPackage_sequence_of, hf_index, ett_akp_AsymmetricKeyPackage);

  return offset;
}



int
dissect_akp_PrivateKeyInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_akp_OneAsymmetricKey(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_akp_EncryptionAlgorithmIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_akp_EncryptedData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *encrypted_tvb;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &encrypted_tvb);

  PBE_decrypt_data(dissect_PrivateKeyInfo_PDU, "PrivateKeyInfo",
    encrypted_tvb, actx->pinfo, actx, actx->created_item);

  return offset;
}


static const ber_sequence_t EncryptedPrivateKeyInfo_sequence[] = {
  { &hf_akp_encryptionAlgorithm, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_akp_EncryptionAlgorithmIdentifier },
  { &hf_akp_encryptedData   , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_akp_EncryptedData },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_akp_EncryptedPrivateKeyInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EncryptedPrivateKeyInfo_sequence, hf_index, ett_akp_EncryptedPrivateKeyInfo);

  return offset;
}

/*--- PDUs ---*/

static int dissect_AsymmetricKeyPackage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_akp_AsymmetricKeyPackage(false, tvb, offset, &asn1_ctx, tree, hf_akp_AsymmetricKeyPackage_PDU);
  return offset;
}
static int dissect_PrivateKeyInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_akp_PrivateKeyInfo(false, tvb, offset, &asn1_ctx, tree, hf_akp_PrivateKeyInfo_PDU);
  return offset;
}
static int dissect_EncryptedPrivateKeyInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_akp_EncryptedPrivateKeyInfo(false, tvb, offset, &asn1_ctx, tree, hf_akp_EncryptedPrivateKeyInfo_PDU);
  return offset;
}


/*--- proto_register_akp ----------------------------------------------*/
void proto_register_akp(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_akp_AsymmetricKeyPackage_PDU,
      { "AsymmetricKeyPackage", "akp.AsymmetricKeyPackage",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_akp_PrivateKeyInfo_PDU,
      { "PrivateKeyInfo", "akp.PrivateKeyInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_akp_EncryptedPrivateKeyInfo_PDU,
      { "EncryptedPrivateKeyInfo", "akp.EncryptedPrivateKeyInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_akp_AsymmetricKeyPackage_item,
      { "OneAsymmetricKey", "akp.OneAsymmetricKey_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_akp_version,
      { "version", "akp.version",
        FT_UINT32, BASE_DEC, VALS(akp_Version_vals), 0,
        NULL, HFILL }},
    { &hf_akp_privateKeyAlgorithm,
      { "privateKeyAlgorithm", "akp.privateKeyAlgorithm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PrivateKeyAlgorithmIdentifier", HFILL }},
    { &hf_akp_privateKey,
      { "privateKey", "akp.privateKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_akp_attributes,
      { "attributes", "akp.attributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_akp_publicKey,
      { "publicKey", "akp.publicKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_akp_Attributes_item,
      { "Attribute", "akp.Attribute_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_akp_encryptionAlgorithm,
      { "encryptionAlgorithm", "akp.encryptionAlgorithm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EncryptionAlgorithmIdentifier", HFILL }},
    { &hf_akp_encryptedData,
      { "encryptedData", "akp.encryptedData",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_akp_AsymmetricKeyPackage,
    &ett_akp_OneAsymmetricKey,
    &ett_akp_Attributes,
    &ett_akp_EncryptedPrivateKeyInfo,
  };

  /* Register protocol */
  proto_akp = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_akp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}


/*--- proto_reg_handoff_akp -------------------------------------------*/
void proto_reg_handoff_akp(void) {
  register_ber_oid_dissector("2.16.840.1.101.2.1.2.78.5", dissect_AsymmetricKeyPackage_PDU, proto_akp, "id-ct-KP-aKeyPackage");
  register_ber_oid_dissector("1.2.840.113549.1.9.25.2", dissect_EncryptedPrivateKeyInfo_PDU, proto_akp, "pkcs-9-at-encryptedPrivateKeyInfo");


  register_ber_syntax_dissector("PrivateKeyInfo", proto_akp, dissect_PrivateKeyInfo_PDU);
  register_ber_syntax_dissector("EncryptedPrivateKeyInfo", proto_akp, dissect_EncryptedPrivateKeyInfo_PDU);

  register_ber_oid_syntax(".p8", NULL, "PrivateKeyInfo");
  dissector_add_string("media_type", "application/pkcs8",
    create_dissector_handle(dissect_PrivateKeyInfo_PDU, proto_akp));

  dissector_add_string("rfc7468.preeb_label", "PRIVATE KEY",
    create_dissector_handle(dissect_PrivateKeyInfo_PDU, proto_akp));
  dissector_add_string("rfc7468.preeb_label", "ENCRYPTED PRIVATE KEY",
    create_dissector_handle(dissect_EncryptedPrivateKeyInfo_PDU, proto_akp));
}
