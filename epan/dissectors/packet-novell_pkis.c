/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-novell_pkis.c                                                       */
/* asn2wrs.py -b -u -p novell_pkis -c ./novell_pkis.cnf -s ./packet-novell_pkis-template -D . -O ../.. novell_pkis.asn */

/* Input file: packet-novell_pkis-template.c */

#line 1 "./asn1/novell_pkis/packet-novell_pkis-template.c"
/* packet-novell_pkis.c
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

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/oids.h>
#include <epan/conversation.h>
#include <epan/asn1.h>

#include "packet-per.h"
#include "packet-ber.h"


/*--- Included file: packet-novell_pkis-hf.c ---*/
#line 1 "./asn1/novell_pkis/packet-novell_pkis-hf.c"
static int hf_novell_pkis_SecurityAttributes_PDU = -1;  /* SecurityAttributes */
static int hf_novell_pkis_RelianceLimits_PDU = -1;  /* RelianceLimits */
static int hf_novell_pkis_versionNumber = -1;     /* OCTET_STRING_SIZE_2 */
static int hf_novell_pkis_nSI = -1;               /* BOOLEAN */
static int hf_novell_pkis_securityTM = -1;        /* T_securityTM */
static int hf_novell_pkis_uriReference = -1;      /* IA5String */
static int hf_novell_pkis_gLBExtensions = -1;     /* GLBExtensions */
static int hf_novell_pkis_keyQuality = -1;        /* KeyQuality */
static int hf_novell_pkis_cryptoProcessQuality = -1;  /* CryptoProcessQuality */
static int hf_novell_pkis_certificateClass = -1;  /* CertificateClass */
static int hf_novell_pkis_enterpriseId = -1;      /* EnterpriseId */
static int hf_novell_pkis_enforceQuality = -1;    /* BOOLEAN */
static int hf_novell_pkis_compusecQuality = -1;   /* CompusecQuality */
static int hf_novell_pkis_cryptoQuality = -1;     /* CryptoQuality */
static int hf_novell_pkis_keyStorageQuality = -1;  /* INTEGER_0_255 */
static int hf_novell_pkis_CompusecQuality_item = -1;  /* CompusecQualityPair */
static int hf_novell_pkis_compusecCriteria = -1;  /* INTEGER_0_255 */
static int hf_novell_pkis_compusecRating = -1;    /* INTEGER_0_255 */
static int hf_novell_pkis_CryptoQuality_item = -1;  /* CryptoQualityPair */
static int hf_novell_pkis_cryptoModuleCriteria = -1;  /* INTEGER_0_255 */
static int hf_novell_pkis_cryptoModuleRating = -1;  /* INTEGER_0_255 */
static int hf_novell_pkis_classValue = -1;        /* INTEGER_0_255 */
static int hf_novell_pkis_certificateValid = -1;  /* BOOLEAN */
static int hf_novell_pkis_rootLabel = -1;         /* SecurityLabelType1 */
static int hf_novell_pkis_registryLabel = -1;     /* SecurityLabelType1 */
static int hf_novell_pkis_enterpriseLabel = -1;   /* SEQUENCE_SIZE_1_1_OF_SecurityLabelType1 */
static int hf_novell_pkis_enterpriseLabel_item = -1;  /* SecurityLabelType1 */
static int hf_novell_pkis_labelType1 = -1;        /* INTEGER_0_255 */
static int hf_novell_pkis_secrecyLevel1 = -1;     /* INTEGER_0_255 */
static int hf_novell_pkis_integrityLevel1 = -1;   /* INTEGER_0_255 */
static int hf_novell_pkis_secrecyCategories1 = -1;  /* BIT_STRING_SIZE_96 */
static int hf_novell_pkis_integrityCategories1 = -1;  /* BIT_STRING_SIZE_64 */
static int hf_novell_pkis_secrecySingletons1 = -1;  /* Singletons */
static int hf_novell_pkis_integritySingletons1 = -1;  /* Singletons */
static int hf_novell_pkis_Singletons_item = -1;   /* SingletonChoice */
static int hf_novell_pkis_uniqueSingleton = -1;   /* INTEGER_0_9223372036854775807 */
static int hf_novell_pkis_singletonRange = -1;    /* SingletonRange */
static int hf_novell_pkis_singletonLowerBound = -1;  /* INTEGER_0_9223372036854775807 */
static int hf_novell_pkis_singletonUpperBound = -1;  /* INTEGER_0_9223372036854775807 */
static int hf_novell_pkis_singletonValue = -1;    /* BOOLEAN */
static int hf_novell_pkis_perTransactionLimit = -1;  /* MonetaryValue */
static int hf_novell_pkis_perCertificateLimit = -1;  /* MonetaryValue */
static int hf_novell_pkis_currency = -1;          /* Currency */
static int hf_novell_pkis_amount = -1;            /* INTEGER */
static int hf_novell_pkis_amtExp10 = -1;          /* INTEGER */

/*--- End of included file: packet-novell_pkis-hf.c ---*/
#line 35 "./asn1/novell_pkis/packet-novell_pkis-template.c"

/*--- Included file: packet-novell_pkis-ett.c ---*/
#line 1 "./asn1/novell_pkis/packet-novell_pkis-ett.c"
static gint ett_novell_pkis_SecurityAttributes = -1;
static gint ett_novell_pkis_GLBExtensions = -1;
static gint ett_novell_pkis_Quality = -1;
static gint ett_novell_pkis_CompusecQuality = -1;
static gint ett_novell_pkis_CompusecQualityPair = -1;
static gint ett_novell_pkis_CryptoQuality = -1;
static gint ett_novell_pkis_CryptoQualityPair = -1;
static gint ett_novell_pkis_CertificateClass = -1;
static gint ett_novell_pkis_EnterpriseId = -1;
static gint ett_novell_pkis_SEQUENCE_SIZE_1_1_OF_SecurityLabelType1 = -1;
static gint ett_novell_pkis_SecurityLabelType1 = -1;
static gint ett_novell_pkis_Singletons = -1;
static gint ett_novell_pkis_SingletonChoice = -1;
static gint ett_novell_pkis_SingletonRange = -1;
static gint ett_novell_pkis_RelianceLimits = -1;
static gint ett_novell_pkis_MonetaryValue = -1;

/*--- End of included file: packet-novell_pkis-ett.c ---*/
#line 36 "./asn1/novell_pkis/packet-novell_pkis-template.c"

/*--- Included file: packet-novell_pkis-fn.c ---*/
#line 1 "./asn1/novell_pkis/packet-novell_pkis-fn.c"


static int
dissect_novell_pkis_OCTET_STRING_SIZE_2(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_novell_pkis_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_novell_pkis_T_securityTM(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_novell_pkis_IA5String(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_novell_pkis_INTEGER_0_255(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_novell_pkis_CompusecQualityPair(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CompusecQualityPair_sequence, hf_index, ett_novell_pkis_CompusecQualityPair);

  return offset;
}


static const ber_sequence_t CompusecQuality_sequence_of[1] = {
  { &hf_novell_pkis_CompusecQuality_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_CompusecQualityPair },
};

static int
dissect_novell_pkis_CompusecQuality(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_novell_pkis_CryptoQualityPair(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CryptoQualityPair_sequence, hf_index, ett_novell_pkis_CryptoQualityPair);

  return offset;
}


static const ber_sequence_t CryptoQuality_sequence_of[1] = {
  { &hf_novell_pkis_CryptoQuality_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_CryptoQualityPair },
};

static int
dissect_novell_pkis_CryptoQuality(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_novell_pkis_Quality(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Quality_sequence, hf_index, ett_novell_pkis_Quality);

  return offset;
}



static int
dissect_novell_pkis_KeyQuality(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_novell_pkis_Quality(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_novell_pkis_CryptoProcessQuality(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_novell_pkis_Quality(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t CertificateClass_sequence[] = {
  { &hf_novell_pkis_classValue, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_INTEGER_0_255 },
  { &hf_novell_pkis_certificateValid, BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_novell_pkis_CertificateClass(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CertificateClass_sequence, hf_index, ett_novell_pkis_CertificateClass);

  return offset;
}



static int
dissect_novell_pkis_BIT_STRING_SIZE_96(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}



static int
dissect_novell_pkis_BIT_STRING_SIZE_64(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}



static int
dissect_novell_pkis_INTEGER_0_9223372036854775807(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_novell_pkis_SingletonRange(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_novell_pkis_SingletonChoice(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SingletonChoice_choice, hf_index, ett_novell_pkis_SingletonChoice,
                                 NULL);

  return offset;
}


static const ber_sequence_t Singletons_sequence_of[1] = {
  { &hf_novell_pkis_Singletons_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_novell_pkis_SingletonChoice },
};

static int
dissect_novell_pkis_Singletons(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_novell_pkis_SecurityLabelType1(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SecurityLabelType1_sequence, hf_index, ett_novell_pkis_SecurityLabelType1);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_1_OF_SecurityLabelType1_sequence_of[1] = {
  { &hf_novell_pkis_enterpriseLabel_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_novell_pkis_SecurityLabelType1 },
};

static int
dissect_novell_pkis_SEQUENCE_SIZE_1_1_OF_SecurityLabelType1(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_novell_pkis_EnterpriseId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_novell_pkis_GLBExtensions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_novell_pkis_SecurityAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SecurityAttributes_sequence, hf_index, ett_novell_pkis_SecurityAttributes);

  return offset;
}



static int
dissect_novell_pkis_Currency(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_novell_pkis_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_novell_pkis_MonetaryValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_novell_pkis_RelianceLimits(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RelianceLimits_sequence, hf_index, ett_novell_pkis_RelianceLimits);

  return offset;
}

/*--- PDUs ---*/

static int dissect_SecurityAttributes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_novell_pkis_SecurityAttributes(FALSE, tvb, offset, &asn1_ctx, tree, hf_novell_pkis_SecurityAttributes_PDU);
  return offset;
}
static int dissect_RelianceLimits_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_novell_pkis_RelianceLimits(FALSE, tvb, offset, &asn1_ctx, tree, hf_novell_pkis_RelianceLimits_PDU);
  return offset;
}


/*--- End of included file: packet-novell_pkis-fn.c ---*/
#line 37 "./asn1/novell_pkis/packet-novell_pkis-template.c"

void proto_register_novell_pkis (void);
void proto_reg_handoff_novell_pkis(void);

static int proto_novell_pkis = -1;

void proto_reg_handoff_novell_pkis(void)
{

/*--- Included file: packet-novell_pkis-dis-tab.c ---*/
#line 1 "./asn1/novell_pkis/packet-novell_pkis-dis-tab.c"
  register_ber_oid_dissector("2.16.840.1.113719.1.9.4.1", dissect_SecurityAttributes_PDU, proto_novell_pkis, "pa-sa");
  register_ber_oid_dissector("2.16.840.1.113719.1.9.4.2", dissect_RelianceLimits_PDU, proto_novell_pkis, "pa-rl");


/*--- End of included file: packet-novell_pkis-dis-tab.c ---*/
#line 46 "./asn1/novell_pkis/packet-novell_pkis-template.c"
}

void proto_register_novell_pkis (void)
{
  static hf_register_info hf[] = {

/*--- Included file: packet-novell_pkis-hfarr.c ---*/
#line 1 "./asn1/novell_pkis/packet-novell_pkis-hfarr.c"
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

/*--- End of included file: packet-novell_pkis-hfarr.c ---*/
#line 52 "./asn1/novell_pkis/packet-novell_pkis-template.c"
  };
  static gint *ett[] = {

/*--- Included file: packet-novell_pkis-ettarr.c ---*/
#line 1 "./asn1/novell_pkis/packet-novell_pkis-ettarr.c"
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

/*--- End of included file: packet-novell_pkis-ettarr.c ---*/
#line 55 "./asn1/novell_pkis/packet-novell_pkis-template.c"
  };

  /* execute protocol initialization only once */
  if (proto_novell_pkis != -1) return;

  proto_novell_pkis = proto_register_protocol("Novell PKIS ASN.1 type", "novell_pkis", "novell_pkis");
  proto_register_field_array (proto_novell_pkis, hf, array_length (hf));
  proto_register_subtree_array (ett, array_length (ett));
}
