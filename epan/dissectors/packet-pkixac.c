/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-pkixac.c                                                            */
/* asn2wrs.py -b -q -L -p pkixac -c ./pkixac.cnf -s ./packet-pkixac-template -D . -O ../.. PKIXAttributeCertificate.asn */

/* packet-pkixac.c
 *
 * Routines for PKIXAttributeCertificate (RFC3281) packet dissection.
 *
 * Copyright 2010, Stig Bjorlykke <stig@bjorlykke.org>
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
#include "packet-ber.h"
#include "packet-pkixac.h"
#include "packet-pkix1explicit.h"
#include "packet-pkix1implicit.h"
#include "packet-x509ce.h"

#define PNAME  "PKIX Attribute Certificate"
#define PSNAME "PKIXAC"
#define PFNAME "pkixac"

void proto_register_pkixac(void);
void proto_reg_handoff_pkixac(void);

/* Initialize the protocol and registered fields */
static int proto_pkixac;
static int hf_pkixac_Targets_PDU;                 /* Targets */
static int hf_pkixac_IetfAttrSyntax_PDU;          /* IetfAttrSyntax */
static int hf_pkixac_SvceAuthInfo_PDU;            /* SvceAuthInfo */
static int hf_pkixac_RoleSyntax_PDU;              /* RoleSyntax */
static int hf_pkixac_Clearance_PDU;               /* Clearance */
static int hf_pkixac_RFC3281Clearance_PDU;        /* RFC3281Clearance */
static int hf_pkixac_AAControls_PDU;              /* AAControls */
static int hf_pkixac_ProxyInfo_PDU;               /* ProxyInfo */
static int hf_pkixac_digestedObjectType;          /* T_digestedObjectType */
static int hf_pkixac_otherObjectTypeID;           /* OBJECT_IDENTIFIER */
static int hf_pkixac_digestAlgorithm;             /* AlgorithmIdentifier */
static int hf_pkixac_objectDigest;                /* BIT_STRING */
static int hf_pkixac_issuer;                      /* GeneralNames */
static int hf_pkixac_serial;                      /* CertificateSerialNumber */
static int hf_pkixac_issuerUID;                   /* UniqueIdentifier */
static int hf_pkixac_Targets_item;                /* Target */
static int hf_pkixac_targetName;                  /* GeneralName */
static int hf_pkixac_targetGroup;                 /* GeneralName */
static int hf_pkixac_targetCert;                  /* TargetCert */
static int hf_pkixac_targetCertificate;           /* IssuerSerial */
static int hf_pkixac_certDigestInfo;              /* ObjectDigestInfo */
static int hf_pkixac_policyAuthority;             /* GeneralNames */
static int hf_pkixac_values;                      /* T_values */
static int hf_pkixac_values_item;                 /* T_values_item */
static int hf_pkixac_octets;                      /* OCTET_STRING */
static int hf_pkixac_oid;                         /* OBJECT_IDENTIFIER */
static int hf_pkixac_string;                      /* UTF8String */
static int hf_pkixac_service;                     /* GeneralName */
static int hf_pkixac_ident;                       /* GeneralName */
static int hf_pkixac_authInfo;                    /* OCTET_STRING */
static int hf_pkixac_roleAuthority;               /* GeneralNames */
static int hf_pkixac_roleName;                    /* GeneralName */
static int hf_pkixac_policyId;                    /* OBJECT_IDENTIFIER */
static int hf_pkixac_classList;                   /* ClassList */
static int hf_pkixac_securityCategories;          /* SET_OF_SecurityCategory */
static int hf_pkixac_securityCategories_item;     /* SecurityCategory */
static int hf_pkixac_type;                        /* T_type */
static int hf_pkixac_value;                       /* T_value */
static int hf_pkixac_pathLenConstraint;           /* INTEGER_0_MAX */
static int hf_pkixac_permittedAttrs;              /* AttrSpec */
static int hf_pkixac_excludedAttrs;               /* AttrSpec */
static int hf_pkixac_permitUnSpecified;           /* BOOLEAN */
static int hf_pkixac_AttrSpec_item;               /* OBJECT_IDENTIFIER */
static int hf_pkixac_ProxyInfo_item;              /* Targets */
/* named bits */
static int hf_pkixac_ClassList_unmarked;
static int hf_pkixac_ClassList_unclassified;
static int hf_pkixac_ClassList_restricted;
static int hf_pkixac_ClassList_confidential;
static int hf_pkixac_ClassList_secret;
static int hf_pkixac_ClassList_topSecret;

/* Initialize the subtree pointers */
static int ett_pkixac;
static int ett_pkixac_ObjectDigestInfo;
static int ett_pkixac_IssuerSerial;
static int ett_pkixac_Targets;
static int ett_pkixac_Target;
static int ett_pkixac_TargetCert;
static int ett_pkixac_IetfAttrSyntax;
static int ett_pkixac_T_values;
static int ett_pkixac_T_values_item;
static int ett_pkixac_SvceAuthInfo;
static int ett_pkixac_RoleSyntax;
static int ett_pkixac_Clearance;
static int ett_pkixac_SET_OF_SecurityCategory;
static int ett_pkixac_RFC3281Clearance;
static int ett_pkixac_ClassList;
static int ett_pkixac_SecurityCategory;
static int ett_pkixac_AAControls;
static int ett_pkixac_AttrSpec;
static int ett_pkixac_ProxyInfo;

static const char *object_identifier_id;


static const value_string pkixac_T_digestedObjectType_vals[] = {
  {   0, "publicKey" },
  {   1, "publicKeyCert" },
  {   2, "otherObjectTypes" },
  { 0, NULL }
};


static int
dissect_pkixac_T_digestedObjectType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_pkixac_OBJECT_IDENTIFIER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_pkixac_BIT_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
                                    NULL);

  return offset;
}


static const ber_sequence_t ObjectDigestInfo_sequence[] = {
  { &hf_pkixac_digestedObjectType, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_pkixac_T_digestedObjectType },
  { &hf_pkixac_otherObjectTypeID, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_pkixac_OBJECT_IDENTIFIER },
  { &hf_pkixac_digestAlgorithm, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_AlgorithmIdentifier },
  { &hf_pkixac_objectDigest , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_pkixac_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkixac_ObjectDigestInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ObjectDigestInfo_sequence, hf_index, ett_pkixac_ObjectDigestInfo);

  return offset;
}


static const ber_sequence_t IssuerSerial_sequence[] = {
  { &hf_pkixac_issuer       , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509ce_GeneralNames },
  { &hf_pkixac_serial       , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_CertificateSerialNumber },
  { &hf_pkixac_issuerUID    , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_UniqueIdentifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkixac_IssuerSerial(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IssuerSerial_sequence, hf_index, ett_pkixac_IssuerSerial);

  return offset;
}


static const ber_sequence_t TargetCert_sequence[] = {
  { &hf_pkixac_targetCertificate, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkixac_IssuerSerial },
  { &hf_pkixac_targetName   , BER_CLASS_CON, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509ce_GeneralName },
  { &hf_pkixac_certDigestInfo, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_pkixac_ObjectDigestInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkixac_TargetCert(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TargetCert_sequence, hf_index, ett_pkixac_TargetCert);

  return offset;
}


static const value_string pkixac_Target_vals[] = {
  {   0, "targetName" },
  {   1, "targetGroup" },
  {   2, "targetCert" },
  { 0, NULL }
};

static const ber_choice_t Target_choice[] = {
  {   0, &hf_pkixac_targetName   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x509ce_GeneralName },
  {   1, &hf_pkixac_targetGroup  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_x509ce_GeneralName },
  {   2, &hf_pkixac_targetCert   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_pkixac_TargetCert },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_pkixac_Target(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Target_choice, hf_index, ett_pkixac_Target,
                                 NULL);

  return offset;
}


static const ber_sequence_t Targets_sequence_of[1] = {
  { &hf_pkixac_Targets_item , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_pkixac_Target },
};

static int
dissect_pkixac_Targets(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Targets_sequence_of, hf_index, ett_pkixac_Targets);

  return offset;
}



static int
dissect_pkixac_OCTET_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_pkixac_UTF8String(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string pkixac_T_values_item_vals[] = {
  {   0, "octets" },
  {   1, "oid" },
  {   2, "string" },
  { 0, NULL }
};

static const ber_choice_t T_values_item_choice[] = {
  {   0, &hf_pkixac_octets       , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_pkixac_OCTET_STRING },
  {   1, &hf_pkixac_oid          , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_pkixac_OBJECT_IDENTIFIER },
  {   2, &hf_pkixac_string       , BER_CLASS_UNI, BER_UNI_TAG_UTF8String, BER_FLAGS_NOOWNTAG, dissect_pkixac_UTF8String },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_pkixac_T_values_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_values_item_choice, hf_index, ett_pkixac_T_values_item,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_values_sequence_of[1] = {
  { &hf_pkixac_values_item  , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_pkixac_T_values_item },
};

static int
dissect_pkixac_T_values(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_values_sequence_of, hf_index, ett_pkixac_T_values);

  return offset;
}


static const ber_sequence_t IetfAttrSyntax_sequence[] = {
  { &hf_pkixac_policyAuthority, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_GeneralNames },
  { &hf_pkixac_values       , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkixac_T_values },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkixac_IetfAttrSyntax(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IetfAttrSyntax_sequence, hf_index, ett_pkixac_IetfAttrSyntax);

  return offset;
}


static const ber_sequence_t SvceAuthInfo_sequence[] = {
  { &hf_pkixac_service      , BER_CLASS_CON, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_x509ce_GeneralName },
  { &hf_pkixac_ident        , BER_CLASS_CON, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_x509ce_GeneralName },
  { &hf_pkixac_authInfo     , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_pkixac_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkixac_SvceAuthInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SvceAuthInfo_sequence, hf_index, ett_pkixac_SvceAuthInfo);

  return offset;
}


static const ber_sequence_t RoleSyntax_sequence[] = {
  { &hf_pkixac_roleAuthority, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_GeneralNames },
  { &hf_pkixac_roleName     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_x509ce_GeneralName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkixac_RoleSyntax(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RoleSyntax_sequence, hf_index, ett_pkixac_RoleSyntax);

  return offset;
}


static int * const ClassList_bits[] = {
  &hf_pkixac_ClassList_unmarked,
  &hf_pkixac_ClassList_unclassified,
  &hf_pkixac_ClassList_restricted,
  &hf_pkixac_ClassList_confidential,
  &hf_pkixac_ClassList_secret,
  &hf_pkixac_ClassList_topSecret,
  NULL
};

static int
dissect_pkixac_ClassList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    ClassList_bits, 6, hf_index, ett_pkixac_ClassList,
                                    NULL);

  return offset;
}



static int
dissect_pkixac_T_type(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &object_identifier_id);

  return offset;
}



static int
dissect_pkixac_T_value(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
   if (object_identifier_id)
      offset = call_ber_oid_callback (object_identifier_id, tvb, offset, actx->pinfo, tree, NULL);


  return offset;
}


static const ber_sequence_t SecurityCategory_sequence[] = {
  { &hf_pkixac_type         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_pkixac_T_type },
  { &hf_pkixac_value        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_pkixac_T_value },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkixac_SecurityCategory(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  object_identifier_id = NULL;
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SecurityCategory_sequence, hf_index, ett_pkixac_SecurityCategory);



  return offset;
}


static const ber_sequence_t SET_OF_SecurityCategory_set_of[1] = {
  { &hf_pkixac_securityCategories_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkixac_SecurityCategory },
};

static int
dissect_pkixac_SET_OF_SecurityCategory(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_SecurityCategory_set_of, hf_index, ett_pkixac_SET_OF_SecurityCategory);

  return offset;
}


static const ber_sequence_t Clearance_sequence[] = {
  { &hf_pkixac_policyId     , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_pkixac_OBJECT_IDENTIFIER },
  { &hf_pkixac_classList    , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_pkixac_ClassList },
  { &hf_pkixac_securityCategories, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_pkixac_SET_OF_SecurityCategory },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkixac_Clearance(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Clearance_sequence, hf_index, ett_pkixac_Clearance);

  return offset;
}


static const ber_sequence_t RFC3281Clearance_sequence[] = {
  { &hf_pkixac_policyId     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_pkixac_OBJECT_IDENTIFIER },
  { &hf_pkixac_classList    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pkixac_ClassList },
  { &hf_pkixac_securityCategories, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pkixac_SET_OF_SecurityCategory },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkixac_RFC3281Clearance(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RFC3281Clearance_sequence, hf_index, ett_pkixac_RFC3281Clearance);

  return offset;
}



static int
dissect_pkixac_INTEGER_0_MAX(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer64(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t AttrSpec_sequence_of[1] = {
  { &hf_pkixac_AttrSpec_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_pkixac_OBJECT_IDENTIFIER },
};

static int
dissect_pkixac_AttrSpec(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      AttrSpec_sequence_of, hf_index, ett_pkixac_AttrSpec);

  return offset;
}



static int
dissect_pkixac_BOOLEAN(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t AAControls_sequence[] = {
  { &hf_pkixac_pathLenConstraint, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_pkixac_INTEGER_0_MAX },
  { &hf_pkixac_permittedAttrs, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pkixac_AttrSpec },
  { &hf_pkixac_excludedAttrs, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pkixac_AttrSpec },
  { &hf_pkixac_permitUnSpecified, BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_pkixac_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkixac_AAControls(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AAControls_sequence, hf_index, ett_pkixac_AAControls);

  return offset;
}


static const ber_sequence_t ProxyInfo_sequence_of[1] = {
  { &hf_pkixac_ProxyInfo_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkixac_Targets },
};

static int
dissect_pkixac_ProxyInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      ProxyInfo_sequence_of, hf_index, ett_pkixac_ProxyInfo);

  return offset;
}

/*--- PDUs ---*/

static int dissect_Targets_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_pkixac_Targets(false, tvb, offset, &asn1_ctx, tree, hf_pkixac_Targets_PDU);
  return offset;
}
static int dissect_IetfAttrSyntax_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_pkixac_IetfAttrSyntax(false, tvb, offset, &asn1_ctx, tree, hf_pkixac_IetfAttrSyntax_PDU);
  return offset;
}
static int dissect_SvceAuthInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_pkixac_SvceAuthInfo(false, tvb, offset, &asn1_ctx, tree, hf_pkixac_SvceAuthInfo_PDU);
  return offset;
}
static int dissect_RoleSyntax_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_pkixac_RoleSyntax(false, tvb, offset, &asn1_ctx, tree, hf_pkixac_RoleSyntax_PDU);
  return offset;
}
static int dissect_Clearance_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_pkixac_Clearance(false, tvb, offset, &asn1_ctx, tree, hf_pkixac_Clearance_PDU);
  return offset;
}
static int dissect_RFC3281Clearance_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_pkixac_RFC3281Clearance(false, tvb, offset, &asn1_ctx, tree, hf_pkixac_RFC3281Clearance_PDU);
  return offset;
}
static int dissect_AAControls_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_pkixac_AAControls(false, tvb, offset, &asn1_ctx, tree, hf_pkixac_AAControls_PDU);
  return offset;
}
static int dissect_ProxyInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_pkixac_ProxyInfo(false, tvb, offset, &asn1_ctx, tree, hf_pkixac_ProxyInfo_PDU);
  return offset;
}


/*--- proto_register_pkixac ----------------------------------------------*/
void proto_register_pkixac(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_pkixac_Targets_PDU,
      { "Targets", "pkixac.Targets",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pkixac_IetfAttrSyntax_PDU,
      { "IetfAttrSyntax", "pkixac.IetfAttrSyntax_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkixac_SvceAuthInfo_PDU,
      { "SvceAuthInfo", "pkixac.SvceAuthInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkixac_RoleSyntax_PDU,
      { "RoleSyntax", "pkixac.RoleSyntax_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkixac_Clearance_PDU,
      { "Clearance", "pkixac.Clearance_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkixac_RFC3281Clearance_PDU,
      { "RFC3281Clearance", "pkixac.RFC3281Clearance_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkixac_AAControls_PDU,
      { "AAControls", "pkixac.AAControls_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkixac_ProxyInfo_PDU,
      { "ProxyInfo", "pkixac.ProxyInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pkixac_digestedObjectType,
      { "digestedObjectType", "pkixac.digestedObjectType",
        FT_UINT32, BASE_DEC, VALS(pkixac_T_digestedObjectType_vals), 0,
        NULL, HFILL }},
    { &hf_pkixac_otherObjectTypeID,
      { "otherObjectTypeID", "pkixac.otherObjectTypeID",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_pkixac_digestAlgorithm,
      { "digestAlgorithm", "pkixac.digestAlgorithm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_pkixac_objectDigest,
      { "objectDigest", "pkixac.objectDigest",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_pkixac_issuer,
      { "issuer", "pkixac.issuer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GeneralNames", HFILL }},
    { &hf_pkixac_serial,
      { "serial", "pkixac.serial",
        FT_INT32, BASE_DEC, NULL, 0,
        "CertificateSerialNumber", HFILL }},
    { &hf_pkixac_issuerUID,
      { "issuerUID", "pkixac.issuerUID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "UniqueIdentifier", HFILL }},
    { &hf_pkixac_Targets_item,
      { "Target", "pkixac.Target",
        FT_UINT32, BASE_DEC, VALS(pkixac_Target_vals), 0,
        NULL, HFILL }},
    { &hf_pkixac_targetName,
      { "targetName", "pkixac.targetName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GeneralName", HFILL }},
    { &hf_pkixac_targetGroup,
      { "targetGroup", "pkixac.targetGroup",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GeneralName", HFILL }},
    { &hf_pkixac_targetCert,
      { "targetCert", "pkixac.targetCert_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkixac_targetCertificate,
      { "targetCertificate", "pkixac.targetCertificate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IssuerSerial", HFILL }},
    { &hf_pkixac_certDigestInfo,
      { "certDigestInfo", "pkixac.certDigestInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ObjectDigestInfo", HFILL }},
    { &hf_pkixac_policyAuthority,
      { "policyAuthority", "pkixac.policyAuthority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GeneralNames", HFILL }},
    { &hf_pkixac_values,
      { "values", "pkixac.values",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pkixac_values_item,
      { "values item", "pkixac.values_item",
        FT_UINT32, BASE_DEC, VALS(pkixac_T_values_item_vals), 0,
        NULL, HFILL }},
    { &hf_pkixac_octets,
      { "octets", "pkixac.octets",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_pkixac_oid,
      { "oid", "pkixac.oid",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_pkixac_string,
      { "string", "pkixac.string",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_pkixac_service,
      { "service", "pkixac.service",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GeneralName", HFILL }},
    { &hf_pkixac_ident,
      { "ident", "pkixac.ident",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GeneralName", HFILL }},
    { &hf_pkixac_authInfo,
      { "authInfo", "pkixac.authInfo",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_pkixac_roleAuthority,
      { "roleAuthority", "pkixac.roleAuthority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GeneralNames", HFILL }},
    { &hf_pkixac_roleName,
      { "roleName", "pkixac.roleName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GeneralName", HFILL }},
    { &hf_pkixac_policyId,
      { "policyId", "pkixac.policyId",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_pkixac_classList,
      { "classList", "pkixac.classList",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkixac_securityCategories,
      { "securityCategories", "pkixac.securityCategories",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_SecurityCategory", HFILL }},
    { &hf_pkixac_securityCategories_item,
      { "SecurityCategory", "pkixac.SecurityCategory_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkixac_type,
      { "type", "pkixac.type",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkixac_value,
      { "value", "pkixac.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkixac_pathLenConstraint,
      { "pathLenConstraint", "pkixac.pathLenConstraint",
        FT_UINT64, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_pkixac_permittedAttrs,
      { "permittedAttrs", "pkixac.permittedAttrs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AttrSpec", HFILL }},
    { &hf_pkixac_excludedAttrs,
      { "excludedAttrs", "pkixac.excludedAttrs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AttrSpec", HFILL }},
    { &hf_pkixac_permitUnSpecified,
      { "permitUnSpecified", "pkixac.permitUnSpecified",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_pkixac_AttrSpec_item,
      { "AttrSpec item", "pkixac.AttrSpec_item",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_pkixac_ProxyInfo_item,
      { "Targets", "pkixac.Targets",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pkixac_ClassList_unmarked,
      { "unmarked", "pkixac.ClassList.unmarked",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_pkixac_ClassList_unclassified,
      { "unclassified", "pkixac.ClassList.unclassified",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_pkixac_ClassList_restricted,
      { "restricted", "pkixac.ClassList.restricted",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_pkixac_ClassList_confidential,
      { "confidential", "pkixac.ClassList.confidential",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_pkixac_ClassList_secret,
      { "secret", "pkixac.ClassList.secret",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_pkixac_ClassList_topSecret,
      { "topSecret", "pkixac.ClassList.topSecret",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
	&ett_pkixac,
    &ett_pkixac_ObjectDigestInfo,
    &ett_pkixac_IssuerSerial,
    &ett_pkixac_Targets,
    &ett_pkixac_Target,
    &ett_pkixac_TargetCert,
    &ett_pkixac_IetfAttrSyntax,
    &ett_pkixac_T_values,
    &ett_pkixac_T_values_item,
    &ett_pkixac_SvceAuthInfo,
    &ett_pkixac_RoleSyntax,
    &ett_pkixac_Clearance,
    &ett_pkixac_SET_OF_SecurityCategory,
    &ett_pkixac_RFC3281Clearance,
    &ett_pkixac_ClassList,
    &ett_pkixac_SecurityCategory,
    &ett_pkixac_AAControls,
    &ett_pkixac_AttrSpec,
    &ett_pkixac_ProxyInfo,
  };

  /* Register protocol */
  proto_pkixac = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_pkixac, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /*--- Syntax registrations ---*/
  register_ber_syntax_dissector("Clearance", proto_pkixac, dissect_Clearance_PDU);
  register_ber_syntax_dissector("RFC3281Clearance", proto_pkixac, dissect_RFC3281Clearance_PDU);

}


/*--- proto_reg_handoff_pkixac -------------------------------------------*/
void proto_reg_handoff_pkixac(void) {
  register_ber_oid_dissector("1.3.6.1.5.5.7.1.6", dissect_AAControls_PDU, proto_pkixac, "id-pe-aaControls");
  register_ber_oid_dissector("1.3.6.1.5.5.7.1.10", dissect_ProxyInfo_PDU, proto_pkixac, "id-pe-ac-proxying");
  register_ber_oid_dissector("1.3.6.1.5.5.7.10.1", dissect_SvceAuthInfo_PDU, proto_pkixac, "id-aca-authenticationInfo");
  register_ber_oid_dissector("1.3.6.1.5.5.7.10.2", dissect_SvceAuthInfo_PDU, proto_pkixac, "id-aca-accessIdentity");
  register_ber_oid_dissector("1.3.6.1.5.5.7.10.3", dissect_IetfAttrSyntax_PDU, proto_pkixac, "id-aca-chargingIdentity");
  register_ber_oid_dissector("1.3.6.1.5.5.7.10.4", dissect_IetfAttrSyntax_PDU, proto_pkixac, "id-aca-group");
  register_ber_oid_dissector("2.5.1.5.55", dissect_Clearance_PDU, proto_pkixac, "id-at-clearance");
  register_ber_oid_dissector("2.5.4.55", dissect_Clearance_PDU, proto_pkixac, "id-at-clearance");
  register_ber_oid_dissector("2.5.4.72", dissect_RoleSyntax_PDU, proto_pkixac, "id-at-role");
  register_ber_oid_dissector("2.5.29.55", dissect_Targets_PDU, proto_pkixac, "id-ce-targetInformation");

}

