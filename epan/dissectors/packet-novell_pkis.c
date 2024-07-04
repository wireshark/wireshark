/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-novell_pkis.c                                                       */
/* asn2wrs.py -b -u -q -L -p novell_pkis -c ./novell_pkis.cnf -s ./packet-novell_pkis-template -D . -O ../.. novell_pkis.asn */

/* packet-novell_pkis.c
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
#include <epan/prefs.h>
#include <epan/oids.h>
#include <epan/conversation.h>
#include <epan/asn1.h>

#include "packet-per.h"
#include "packet-ber.h"

static int hf_novell_pkis_SecurityAttributes_PDU;  /* SecurityAttributes */
static int hf_novell_pkis_RelianceLimits_PDU;     /* RelianceLimits */
static int hf_novell_pkis_versionNumber;          /* OCTET_STRING_SIZE_2 */
static int hf_novell_pkis_nSI;                    /* BOOLEAN */
static int hf_novell_pkis_securityTM;             /* T_securityTM */
static int hf_novell_pkis_uriReference;           /* IA5String */
static int hf_novell_pkis_gLBExtensions;          /* GLBExtensions */
static int hf_novell_pkis_keyQuality;             /* KeyQuality */
static int hf_novell_pkis_cryptoProcessQuality;   /* CryptoProcessQuality */
static int hf_novell_pkis_certificateClass;       /* CertificateClass */
static int hf_novell_pkis_enterpriseId;           /* EnterpriseId */
static int hf_novell_pkis_enforceQuality;         /* BOOLEAN */
static int hf_novell_pkis_compusecQuality;        /* CompusecQuality */
static int hf_novell_pkis_cryptoQuality;          /* CryptoQuality */
static int hf_novell_pkis_keyStorageQuality;      /* INTEGER_0_255 */
static int hf_novell_pkis_CompusecQuality_item;   /* CompusecQualityPair */
static int hf_novell_pkis_compusecCriteria;       /* INTEGER_0_255 */
static int hf_novell_pkis_compusecRating;         /* INTEGER_0_255 */
static int hf_novell_pkis_CryptoQuality_item;     /* CryptoQualityPair */
static int hf_novell_pkis_cryptoModuleCriteria;   /* INTEGER_0_255 */
static int hf_novell_pkis_cryptoModuleRating;     /* INTEGER_0_255 */
static int hf_novell_pkis_classValue;             /* INTEGER_0_255 */
static int hf_novell_pkis_certificateValid;       /* BOOLEAN */
static int hf_novell_pkis_rootLabel;              /* SecurityLabelType1 */
static int hf_novell_pkis_registryLabel;          /* SecurityLabelType1 */
static int hf_novell_pkis_enterpriseLabel;        /* SEQUENCE_SIZE_1_1_OF_SecurityLabelType1 */
static int hf_novell_pkis_enterpriseLabel_item;   /* SecurityLabelType1 */
static int hf_novell_pkis_labelType1;             /* INTEGER_0_255 */
static int hf_novell_pkis_secrecyLevel1;          /* INTEGER_0_255 */
static int hf_novell_pkis_integrityLevel1;        /* INTEGER_0_255 */
static int hf_novell_pkis_secrecyCategories1;     /* BIT_STRING_SIZE_96 */
static int hf_novell_pkis_integrityCategories1;   /* BIT_STRING_SIZE_64 */
static int hf_novell_pkis_secrecySingletons1;     /* Singletons */
static int hf_novell_pkis_integritySingletons1;   /* Singletons */
static int hf_novell_pkis_Singletons_item;        /* SingletonChoice */
static int hf_novell_pkis_uniqueSingleton;        /* INTEGER_0_9223372036854775807 */
static int hf_novell_pkis_singletonRange;         /* SingletonRange */
static int hf_novell_pkis_singletonLowerBound;    /* INTEGER_0_9223372036854775807 */
static int hf_novell_pkis_singletonUpperBound;    /* INTEGER_0_9223372036854775807 */
static int hf_novell_pkis_singletonValue;         /* BOOLEAN */
static int hf_novell_pkis_perTransactionLimit;    /* MonetaryValue */
static int hf_novell_pkis_perCertificateLimit;    /* MonetaryValue */
static int hf_novell_pkis_currency;               /* Currency */
static int hf_novell_pkis_amount;                 /* INTEGER */
static int hf_novell_pkis_amtExp10;               /* INTEGER */
static int ett_novell_pkis_SecurityAttributes;
static int ett_novell_pkis_GLBExtensions;
static int ett_novell_pkis_Quality;
static int ett_novell_pkis_CompusecQuality;
static int ett_novell_pkis_CompusecQualityPair;
static int ett_novell_pkis_CryptoQuality;
static int ett_novell_pkis_CryptoQualityPair;
static int ett_novell_pkis_CertificateClass;
static int ett_novell_pkis_EnterpriseId;
static int ett_novell_pkis_SEQUENCE_SIZE_1_1_OF_SecurityLabelType1;
static int ett_novell_pkis_SecurityLabelType1;
static int ett_novell_pkis_Singletons;
static int ett_novell_pkis_SingletonChoice;
static int ett_novell_pkis_SingletonRange;
static int ett_novell_pkis_RelianceLimits;
static int ett_novell_pkis_MonetaryValue;


static int
dissect_novell_pkis_OCTET_STRING_SIZE_2(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_novell_pkis_BOOLEAN(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_novell_pkis_T_securityTM(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_novell_pkis_IA5String(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_novell_pkis_INTEGER_0_255(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t CompusecQualityPair_sequence[] = {
  { &hf_novell_pkis_compusecCriteria, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_INTEGER_0_255 },
  { &hf_novell_pkis_compusecRating, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_INTEGER_0_255 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_novell_pkis_CompusecQualityPair(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CompusecQualityPair_sequence, hf_index, ett_novell_pkis_CompusecQualityPair);

  return offset;
}


static const ber_sequence_t CompusecQuality_sequence_of[1] = {
  { &hf_novell_pkis_CompusecQuality_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_CompusecQualityPair },
};

static int
dissect_novell_pkis_CompusecQuality(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      CompusecQuality_sequence_of, hf_index, ett_novell_pkis_CompusecQuality);

  return offset;
}


static const ber_sequence_t CryptoQualityPair_sequence[] = {
  { &hf_novell_pkis_cryptoModuleCriteria, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_INTEGER_0_255 },
  { &hf_novell_pkis_cryptoModuleRating, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_INTEGER_0_255 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_novell_pkis_CryptoQualityPair(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CryptoQualityPair_sequence, hf_index, ett_novell_pkis_CryptoQualityPair);

  return offset;
}


static const ber_sequence_t CryptoQuality_sequence_of[1] = {
  { &hf_novell_pkis_CryptoQuality_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_CryptoQualityPair },
};

static int
dissect_novell_pkis_CryptoQuality(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      CryptoQuality_sequence_of, hf_index, ett_novell_pkis_CryptoQuality);

  return offset;
}


static const ber_sequence_t Quality_sequence[] = {
  { &hf_novell_pkis_enforceQuality, BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_BOOLEAN },
  { &hf_novell_pkis_compusecQuality, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_CompusecQuality },
  { &hf_novell_pkis_cryptoQuality, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_CryptoQuality },
  { &hf_novell_pkis_keyStorageQuality, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_INTEGER_0_255 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_novell_pkis_Quality(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Quality_sequence, hf_index, ett_novell_pkis_Quality);

  return offset;
}



static int
dissect_novell_pkis_KeyQuality(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_novell_pkis_Quality(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_novell_pkis_CryptoProcessQuality(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_novell_pkis_Quality(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t CertificateClass_sequence[] = {
  { &hf_novell_pkis_classValue, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_INTEGER_0_255 },
  { &hf_novell_pkis_certificateValid, BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_novell_pkis_CertificateClass(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CertificateClass_sequence, hf_index, ett_novell_pkis_CertificateClass);

  return offset;
}



static int
dissect_novell_pkis_BIT_STRING_SIZE_96(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
                                    NULL);

  return offset;
}



static int
dissect_novell_pkis_BIT_STRING_SIZE_64(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
                                    NULL);

  return offset;
}



static int
dissect_novell_pkis_INTEGER_0_9223372036854775807(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer64(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t SingletonRange_sequence[] = {
  { &hf_novell_pkis_singletonLowerBound, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_INTEGER_0_9223372036854775807 },
  { &hf_novell_pkis_singletonUpperBound, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_INTEGER_0_9223372036854775807 },
  { &hf_novell_pkis_singletonValue, BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_novell_pkis_SingletonRange(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SingletonRange_sequence, hf_index, ett_novell_pkis_SingletonRange);

  return offset;
}


static const value_string novell_pkis_SingletonChoice_vals[] = {
  {   0, "uniqueSingleton" },
  {   1, "singletonRange" },
  { 0, NULL }
};

static const ber_choice_t SingletonChoice_choice[] = {
  {   0, &hf_novell_pkis_uniqueSingleton, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_INTEGER_0_9223372036854775807 },
  {   1, &hf_novell_pkis_singletonRange, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_SingletonRange },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_novell_pkis_SingletonChoice(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SingletonChoice_choice, hf_index, ett_novell_pkis_SingletonChoice,
                                 NULL);

  return offset;
}


static const ber_sequence_t Singletons_sequence_of[1] = {
  { &hf_novell_pkis_Singletons_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_novell_pkis_SingletonChoice },
};

static int
dissect_novell_pkis_Singletons(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Singletons_sequence_of, hf_index, ett_novell_pkis_Singletons);

  return offset;
}


static const ber_sequence_t SecurityLabelType1_sequence[] = {
  { &hf_novell_pkis_labelType1, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_INTEGER_0_255 },
  { &hf_novell_pkis_secrecyLevel1, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_INTEGER_0_255 },
  { &hf_novell_pkis_integrityLevel1, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_INTEGER_0_255 },
  { &hf_novell_pkis_secrecyCategories1, BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_BIT_STRING_SIZE_96 },
  { &hf_novell_pkis_integrityCategories1, BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_BIT_STRING_SIZE_64 },
  { &hf_novell_pkis_secrecySingletons1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_Singletons },
  { &hf_novell_pkis_integritySingletons1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_Singletons },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_novell_pkis_SecurityLabelType1(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SecurityLabelType1_sequence, hf_index, ett_novell_pkis_SecurityLabelType1);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_1_OF_SecurityLabelType1_sequence_of[1] = {
  { &hf_novell_pkis_enterpriseLabel_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_SecurityLabelType1 },
};

static int
dissect_novell_pkis_SEQUENCE_SIZE_1_1_OF_SecurityLabelType1(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_1_OF_SecurityLabelType1_sequence_of, hf_index, ett_novell_pkis_SEQUENCE_SIZE_1_1_OF_SecurityLabelType1);

  return offset;
}


static const ber_sequence_t EnterpriseId_sequence[] = {
  { &hf_novell_pkis_rootLabel, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_novell_pkis_SecurityLabelType1 },
  { &hf_novell_pkis_registryLabel, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_novell_pkis_SecurityLabelType1 },
  { &hf_novell_pkis_enterpriseLabel, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_novell_pkis_SEQUENCE_SIZE_1_1_OF_SecurityLabelType1 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_novell_pkis_EnterpriseId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EnterpriseId_sequence, hf_index, ett_novell_pkis_EnterpriseId);

  return offset;
}


static const ber_sequence_t GLBExtensions_sequence[] = {
  { &hf_novell_pkis_keyQuality, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_novell_pkis_KeyQuality },
  { &hf_novell_pkis_cryptoProcessQuality, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_novell_pkis_CryptoProcessQuality },
  { &hf_novell_pkis_certificateClass, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_novell_pkis_CertificateClass },
  { &hf_novell_pkis_enterpriseId, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_novell_pkis_EnterpriseId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_novell_pkis_GLBExtensions(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GLBExtensions_sequence, hf_index, ett_novell_pkis_GLBExtensions);

  return offset;
}


static const ber_sequence_t SecurityAttributes_sequence[] = {
  { &hf_novell_pkis_versionNumber, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_OCTET_STRING_SIZE_2 },
  { &hf_novell_pkis_nSI     , BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_BOOLEAN },
  { &hf_novell_pkis_securityTM, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_T_securityTM },
  { &hf_novell_pkis_uriReference, BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_IA5String },
  { &hf_novell_pkis_gLBExtensions, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_GLBExtensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_novell_pkis_SecurityAttributes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SecurityAttributes_sequence, hf_index, ett_novell_pkis_SecurityAttributes);

  return offset;
}



static int
dissect_novell_pkis_Currency(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_novell_pkis_INTEGER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t MonetaryValue_sequence[] = {
  { &hf_novell_pkis_currency, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_Currency },
  { &hf_novell_pkis_amount  , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_INTEGER },
  { &hf_novell_pkis_amtExp10, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_novell_pkis_MonetaryValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MonetaryValue_sequence, hf_index, ett_novell_pkis_MonetaryValue);

  return offset;
}


static const ber_sequence_t RelianceLimits_sequence[] = {
  { &hf_novell_pkis_perTransactionLimit, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_MonetaryValue },
  { &hf_novell_pkis_perCertificateLimit, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_MonetaryValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_novell_pkis_RelianceLimits(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RelianceLimits_sequence, hf_index, ett_novell_pkis_RelianceLimits);

  return offset;
}

/*--- PDUs ---*/

static int dissect_SecurityAttributes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_novell_pkis_SecurityAttributes(false, tvb, offset, &asn1_ctx, tree, hf_novell_pkis_SecurityAttributes_PDU);
  return offset;
}
static int dissect_RelianceLimits_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_novell_pkis_RelianceLimits(false, tvb, offset, &asn1_ctx, tree, hf_novell_pkis_RelianceLimits_PDU);
  return offset;
}


void proto_register_novell_pkis (void);
void proto_reg_handoff_novell_pkis(void);

static int proto_novell_pkis;

void proto_reg_handoff_novell_pkis(void)
{
  register_ber_oid_dissector("2.16.840.1.113719.1.9.4.1", dissect_SecurityAttributes_PDU, proto_novell_pkis, "pa-sa");
  register_ber_oid_dissector("2.16.840.1.113719.1.9.4.2", dissect_RelianceLimits_PDU, proto_novell_pkis, "pa-rl");

}

void proto_register_novell_pkis (void)
{
  static hf_register_info hf[] = {
    { &hf_novell_pkis_SecurityAttributes_PDU,
      { "SecurityAttributes", "novell_pkis.SecurityAttributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_novell_pkis_RelianceLimits_PDU,
      { "RelianceLimits", "novell_pkis.RelianceLimits_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_novell_pkis_versionNumber,
      { "versionNumber", "novell_pkis.versionNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_2", HFILL }},
    { &hf_novell_pkis_nSI,
      { "nSI", "novell_pkis.nSI",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_novell_pkis_securityTM,
      { "securityTM", "novell_pkis.securityTM",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_novell_pkis_uriReference,
      { "uriReference", "novell_pkis.uriReference",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String", HFILL }},
    { &hf_novell_pkis_gLBExtensions,
      { "gLBExtensions", "novell_pkis.gLBExtensions_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_novell_pkis_keyQuality,
      { "keyQuality", "novell_pkis.keyQuality_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_novell_pkis_cryptoProcessQuality,
      { "cryptoProcessQuality", "novell_pkis.cryptoProcessQuality_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_novell_pkis_certificateClass,
      { "certificateClass", "novell_pkis.certificateClass_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_novell_pkis_enterpriseId,
      { "enterpriseId", "novell_pkis.enterpriseId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_novell_pkis_enforceQuality,
      { "enforceQuality", "novell_pkis.enforceQuality",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_novell_pkis_compusecQuality,
      { "compusecQuality", "novell_pkis.compusecQuality",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_novell_pkis_cryptoQuality,
      { "cryptoQuality", "novell_pkis.cryptoQuality",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_novell_pkis_keyStorageQuality,
      { "keyStorageQuality", "novell_pkis.keyStorageQuality",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_novell_pkis_CompusecQuality_item,
      { "CompusecQualityPair", "novell_pkis.CompusecQualityPair_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_novell_pkis_compusecCriteria,
      { "compusecCriteria", "novell_pkis.compusecCriteria",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_novell_pkis_compusecRating,
      { "compusecRating", "novell_pkis.compusecRating",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_novell_pkis_CryptoQuality_item,
      { "CryptoQualityPair", "novell_pkis.CryptoQualityPair_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_novell_pkis_cryptoModuleCriteria,
      { "cryptoModuleCriteria", "novell_pkis.cryptoModuleCriteria",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_novell_pkis_cryptoModuleRating,
      { "cryptoModuleRating", "novell_pkis.cryptoModuleRating",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_novell_pkis_classValue,
      { "classValue", "novell_pkis.classValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_novell_pkis_certificateValid,
      { "certificateValid", "novell_pkis.certificateValid",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_novell_pkis_rootLabel,
      { "rootLabel", "novell_pkis.rootLabel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SecurityLabelType1", HFILL }},
    { &hf_novell_pkis_registryLabel,
      { "registryLabel", "novell_pkis.registryLabel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SecurityLabelType1", HFILL }},
    { &hf_novell_pkis_enterpriseLabel,
      { "enterpriseLabel", "novell_pkis.enterpriseLabel",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_1_OF_SecurityLabelType1", HFILL }},
    { &hf_novell_pkis_enterpriseLabel_item,
      { "SecurityLabelType1", "novell_pkis.SecurityLabelType1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_novell_pkis_labelType1,
      { "labelType1", "novell_pkis.labelType1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_novell_pkis_secrecyLevel1,
      { "secrecyLevel1", "novell_pkis.secrecyLevel1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_novell_pkis_integrityLevel1,
      { "integrityLevel1", "novell_pkis.integrityLevel1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_novell_pkis_secrecyCategories1,
      { "secrecyCategories1", "novell_pkis.secrecyCategories1",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_96", HFILL }},
    { &hf_novell_pkis_integrityCategories1,
      { "integrityCategories1", "novell_pkis.integrityCategories1",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_64", HFILL }},
    { &hf_novell_pkis_secrecySingletons1,
      { "secrecySingletons1", "novell_pkis.secrecySingletons1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Singletons", HFILL }},
    { &hf_novell_pkis_integritySingletons1,
      { "integritySingletons1", "novell_pkis.integritySingletons1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Singletons", HFILL }},
    { &hf_novell_pkis_Singletons_item,
      { "SingletonChoice", "novell_pkis.SingletonChoice",
        FT_UINT32, BASE_DEC, VALS(novell_pkis_SingletonChoice_vals), 0,
        NULL, HFILL }},
    { &hf_novell_pkis_uniqueSingleton,
      { "uniqueSingleton", "novell_pkis.uniqueSingleton",
        FT_UINT64, BASE_DEC, NULL, 0,
        "INTEGER_0_9223372036854775807", HFILL }},
    { &hf_novell_pkis_singletonRange,
      { "singletonRange", "novell_pkis.singletonRange_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_novell_pkis_singletonLowerBound,
      { "singletonLowerBound", "novell_pkis.singletonLowerBound",
        FT_UINT64, BASE_DEC, NULL, 0,
        "INTEGER_0_9223372036854775807", HFILL }},
    { &hf_novell_pkis_singletonUpperBound,
      { "singletonUpperBound", "novell_pkis.singletonUpperBound",
        FT_UINT64, BASE_DEC, NULL, 0,
        "INTEGER_0_9223372036854775807", HFILL }},
    { &hf_novell_pkis_singletonValue,
      { "singletonValue", "novell_pkis.singletonValue",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_novell_pkis_perTransactionLimit,
      { "perTransactionLimit", "novell_pkis.perTransactionLimit_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MonetaryValue", HFILL }},
    { &hf_novell_pkis_perCertificateLimit,
      { "perCertificateLimit", "novell_pkis.perCertificateLimit_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MonetaryValue", HFILL }},
    { &hf_novell_pkis_currency,
      { "currency", "novell_pkis.currency",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_novell_pkis_amount,
      { "amount", "novell_pkis.amount",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_novell_pkis_amtExp10,
      { "amtExp10", "novell_pkis.amtExp10",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
  };
  static int *ett[] = {
    &ett_novell_pkis_SecurityAttributes,
    &ett_novell_pkis_GLBExtensions,
    &ett_novell_pkis_Quality,
    &ett_novell_pkis_CompusecQuality,
    &ett_novell_pkis_CompusecQualityPair,
    &ett_novell_pkis_CryptoQuality,
    &ett_novell_pkis_CryptoQualityPair,
    &ett_novell_pkis_CertificateClass,
    &ett_novell_pkis_EnterpriseId,
    &ett_novell_pkis_SEQUENCE_SIZE_1_1_OF_SecurityLabelType1,
    &ett_novell_pkis_SecurityLabelType1,
    &ett_novell_pkis_Singletons,
    &ett_novell_pkis_SingletonChoice,
    &ett_novell_pkis_SingletonRange,
    &ett_novell_pkis_RelianceLimits,
    &ett_novell_pkis_MonetaryValue,
  };

  /* execute protocol initialization only once */
  if (proto_novell_pkis > 0) return;

  proto_novell_pkis = proto_register_protocol("Novell PKIS ASN.1 type", "novell_pkis", "novell_pkis");
  proto_register_field_array (proto_novell_pkis, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
}
