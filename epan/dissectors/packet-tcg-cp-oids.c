/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-tcg-cp-oids.c                                                       */
/* asn2wrs.py -b -p tcg-cp-oids -c ./tcg-cp-oids.cnf -s ./packet-tcg-cp-oids-template -D . -O ../.. tcg-cp-oids.asn */

/* Input file: packet-tcg-cp-oids-template.c */

#line 1 "./asn1/tcg-cp-oids/packet-tcg-cp-oids-template.c"
/* packet-tcg-cp-oids.c
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

#include "packet-tcg-cp-oids.h"
#include "packet-ber.h"
#include "packet-pkix1explicit.h"
#include "packet-pkix1implicit.h"

#define PNAME  "TCG_CP_OIDS"
#define PSNAME "TCG_CP_OIDS"
#define PFNAME "tcg_cp_oids"

void proto_register_tcg_cp_oids(void);
void proto_reg_handoff_tcg_cp_oids(void);

/* Initialize the protocol and registered fields */
static int proto_tcg_cp_oids = -1;

/*--- Included file: packet-tcg-cp-oids-hf.c ---*/
#line 1 "./asn1/tcg-cp-oids/packet-tcg-cp-oids-hf.c"
static int hf_tcg_cp_oids_TPMSpecification_PDU = -1;  /* TPMSpecification */
static int hf_tcg_cp_oids_TCGPlatformSpecification_PDU = -1;  /* TCGPlatformSpecification */
static int hf_tcg_cp_oids_TCPASpecVersion_PDU = -1;  /* TCPASpecVersion */
static int hf_tcg_cp_oids_TPMSecurityAssertions_PDU = -1;  /* TPMSecurityAssertions */
static int hf_tcg_cp_oids_TBBSecurityAssertions_PDU = -1;  /* TBBSecurityAssertions */
static int hf_tcg_cp_oids_ProtectionProfile_PDU = -1;  /* ProtectionProfile */
static int hf_tcg_cp_oids_SecurityTarget_PDU = -1;  /* SecurityTarget */
static int hf_tcg_cp_oids_TCGRelevantCredentials_PDU = -1;  /* TCGRelevantCredentials */
static int hf_tcg_cp_oids_TCGRelevantManifests_PDU = -1;  /* TCGRelevantManifests */
static int hf_tcg_cp_oids_VirtualPlatformAttestationServiceURI_PDU = -1;  /* VirtualPlatformAttestationServiceURI */
static int hf_tcg_cp_oids_MigrationControllerAttestationServiceURI_PDU = -1;  /* MigrationControllerAttestationServiceURI */
static int hf_tcg_cp_oids_MigrationControllerRegistrationServiceURI_PDU = -1;  /* MigrationControllerRegistrationServiceURI */
static int hf_tcg_cp_oids_VirtualPlatformBackupServiceURI_PDU = -1;  /* VirtualPlatformBackupServiceURI */
static int hf_tcg_cp_oids_family = -1;            /* UTF8String */
static int hf_tcg_cp_oids_tpm_specification_level = -1;  /* INTEGER */
static int hf_tcg_cp_oids_revision = -1;          /* INTEGER */
static int hf_tcg_cp_oids_majorVersion = -1;      /* INTEGER */
static int hf_tcg_cp_oids_minorVersion = -1;      /* INTEGER */
static int hf_tcg_cp_oids_tcg_specification_vesion = -1;  /* TCGSpecificationVersion */
static int hf_tcg_cp_oids_platformClass = -1;     /* OCTET_STRING */
static int hf_tcg_cp_oids_major = -1;             /* INTEGER */
static int hf_tcg_cp_oids_minor = -1;             /* INTEGER */
static int hf_tcg_cp_oids_security_assertions_version = -1;  /* Version */
static int hf_tcg_cp_oids_fieldUpgradable = -1;   /* BOOLEAN */
static int hf_tcg_cp_oids_ekGenerationType = -1;  /* EKGenerationType */
static int hf_tcg_cp_oids_ekGenerationLocation = -1;  /* EKGenerationLocation */
static int hf_tcg_cp_oids_ekCertificateGenerationLocation = -1;  /* EKCertificateGenerationLocation */
static int hf_tcg_cp_oids_ccInfo = -1;            /* CommonCriteriaMeasures */
static int hf_tcg_cp_oids_fipsLevel = -1;         /* FIPSLevel */
static int hf_tcg_cp_oids_iso9000Certified = -1;  /* BOOLEAN */
static int hf_tcg_cp_oids_iso9000Uri = -1;        /* IA5String */
static int hf_tcg_cp_oids_rtmType = -1;           /* MeasurementRootType */
static int hf_tcg_cp_oids_cc_measures_version_string = -1;  /* IA5String */
static int hf_tcg_cp_oids_assurancelevel = -1;    /* EvaluationAssuranceLevel */
static int hf_tcg_cp_oids_evaluationStatus = -1;  /* EvaluationStatus */
static int hf_tcg_cp_oids_plus = -1;              /* BOOLEAN */
static int hf_tcg_cp_oids_strengthOfFunction = -1;  /* StrengthOfFunction */
static int hf_tcg_cp_oids_profileOid = -1;        /* OBJECT_IDENTIFIER */
static int hf_tcg_cp_oids_profileUri = -1;        /* URIReference */
static int hf_tcg_cp_oids_targetOid = -1;         /* OBJECT_IDENTIFIER */
static int hf_tcg_cp_oids_targetUri = -1;         /* URIReference */
static int hf_tcg_cp_oids_uniformResourceIdentifier = -1;  /* IA5String */
static int hf_tcg_cp_oids_hashAlgorithm = -1;     /* AlgorithmIdentifier */
static int hf_tcg_cp_oids_uri_reference_hashvalue = -1;  /* BIT_STRING */
static int hf_tcg_cp_oids_fips_level_version_string = -1;  /* IA5String */
static int hf_tcg_cp_oids_fips_security_level = -1;  /* SecurityLevel */
static int hf_tcg_cp_oids_hashAlg = -1;           /* AlgorithmIdentifier */
static int hf_tcg_cp_oids_hash_alg_and_value_hashvalue = -1;  /* OCTET_STRING */
static int hf_tcg_cp_oids_documentURI = -1;       /* IA5String */
static int hf_tcg_cp_oids_documentAccessInfo = -1;  /* OBJECT_IDENTIFIER */
static int hf_tcg_cp_oids_documentHashInfo = -1;  /* HashAlgAndValue */
static int hf_tcg_cp_oids_TCGRelevantCredentials_item = -1;  /* HashedSubjectInfoURI */
static int hf_tcg_cp_oids_TCGRelevantManifests_item = -1;  /* HashedSubjectInfoURI */
static int hf_tcg_cp_oids_restoreAllowed = -1;    /* BOOLEAN */
static int hf_tcg_cp_oids_backupServiceURI = -1;  /* IA5String */

/*--- End of included file: packet-tcg-cp-oids-hf.c ---*/
#line 31 "./asn1/tcg-cp-oids/packet-tcg-cp-oids-template.c"
static int hf_tcg_cp_oids_UTF8String_PDU = -1;

/* Initialize the subtree pointers */

/*--- Included file: packet-tcg-cp-oids-ett.c ---*/
#line 1 "./asn1/tcg-cp-oids/packet-tcg-cp-oids-ett.c"
static gint ett_tcg_cp_oids_TPMSpecification = -1;
static gint ett_tcg_cp_oids_TCGSpecificationVersion = -1;
static gint ett_tcg_cp_oids_TCGPlatformSpecification = -1;
static gint ett_tcg_cp_oids_TCPASpecVersion = -1;
static gint ett_tcg_cp_oids_TPMSecurityAssertions = -1;
static gint ett_tcg_cp_oids_TBBSecurityAssertions = -1;
static gint ett_tcg_cp_oids_CommonCriteriaMeasures = -1;
static gint ett_tcg_cp_oids_URIReference = -1;
static gint ett_tcg_cp_oids_FIPSLevel = -1;
static gint ett_tcg_cp_oids_HashAlgAndValue = -1;
static gint ett_tcg_cp_oids_HashedSubjectInfoURI = -1;
static gint ett_tcg_cp_oids_TCGRelevantCredentials = -1;
static gint ett_tcg_cp_oids_TCGRelevantManifests = -1;
static gint ett_tcg_cp_oids_VirtualPlatformBackupServiceURI = -1;

/*--- End of included file: packet-tcg-cp-oids-ett.c ---*/
#line 35 "./asn1/tcg-cp-oids/packet-tcg-cp-oids-template.c"

/*--- Included file: packet-tcg-cp-oids-fn.c ---*/
#line 1 "./asn1/tcg-cp-oids/packet-tcg-cp-oids-fn.c"


static int
dissect_tcg_cp_oids_UTF8String(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_tcg_cp_oids_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t TPMSpecification_sequence[] = {
  { &hf_tcg_cp_oids_family  , BER_CLASS_UNI, BER_UNI_TAG_UTF8String, BER_FLAGS_NOOWNTAG, dissect_tcg_cp_oids_UTF8String },
  { &hf_tcg_cp_oids_tpm_specification_level, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_tcg_cp_oids_INTEGER },
  { &hf_tcg_cp_oids_revision, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_tcg_cp_oids_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_tcg_cp_oids_TPMSpecification(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TPMSpecification_sequence, hf_index, ett_tcg_cp_oids_TPMSpecification);

  return offset;
}


static const ber_sequence_t TCGSpecificationVersion_sequence[] = {
  { &hf_tcg_cp_oids_majorVersion, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_tcg_cp_oids_INTEGER },
  { &hf_tcg_cp_oids_minorVersion, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_tcg_cp_oids_INTEGER },
  { &hf_tcg_cp_oids_revision, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_tcg_cp_oids_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_tcg_cp_oids_TCGSpecificationVersion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TCGSpecificationVersion_sequence, hf_index, ett_tcg_cp_oids_TCGSpecificationVersion);

  return offset;
}



static int
dissect_tcg_cp_oids_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t TCGPlatformSpecification_sequence[] = {
  { &hf_tcg_cp_oids_tcg_specification_vesion, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_tcg_cp_oids_TCGSpecificationVersion },
  { &hf_tcg_cp_oids_platformClass, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_tcg_cp_oids_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_tcg_cp_oids_TCGPlatformSpecification(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TCGPlatformSpecification_sequence, hf_index, ett_tcg_cp_oids_TCGPlatformSpecification);

  return offset;
}


static const ber_sequence_t TCPASpecVersion_sequence[] = {
  { &hf_tcg_cp_oids_major   , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_tcg_cp_oids_INTEGER },
  { &hf_tcg_cp_oids_minor   , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_tcg_cp_oids_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_tcg_cp_oids_TCPASpecVersion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TCPASpecVersion_sequence, hf_index, ett_tcg_cp_oids_TCPASpecVersion);

  return offset;
}



static int
dissect_tcg_cp_oids_Version(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_tcg_cp_oids_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const value_string tcg_cp_oids_EKGenerationType_vals[] = {
  {   0, "internal" },
  {   1, "injected" },
  {   2, "internalRevocable" },
  {   3, "injectedRevocable" },
  { 0, NULL }
};


static int
dissect_tcg_cp_oids_EKGenerationType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string tcg_cp_oids_EKGenerationLocation_vals[] = {
  {   0, "tpmManufacturer" },
  {   1, "platformManufacturer" },
  {   2, "ekCertSigner" },
  { 0, NULL }
};


static int
dissect_tcg_cp_oids_EKGenerationLocation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string tcg_cp_oids_EKCertificateGenerationLocation_vals[] = {
  {   0, "tpmManufacturer" },
  {   1, "platformManufacturer" },
  {   2, "ekCertSigner" },
  { 0, NULL }
};


static int
dissect_tcg_cp_oids_EKCertificateGenerationLocation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_tcg_cp_oids_IA5String(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string tcg_cp_oids_EvaluationAssuranceLevel_vals[] = {
  {   1, "levell" },
  {   2, "level2" },
  {   3, "level3" },
  {   4, "level4" },
  {   5, "level5" },
  {   6, "level6" },
  {   7, "level7" },
  { 0, NULL }
};


static int
dissect_tcg_cp_oids_EvaluationAssuranceLevel(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string tcg_cp_oids_EvaluationStatus_vals[] = {
  {   0, "designedToMeet" },
  {   1, "evaluationInProgress" },
  {   2, "evaluationCompleted" },
  { 0, NULL }
};


static int
dissect_tcg_cp_oids_EvaluationStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string tcg_cp_oids_StrengthOfFunction_vals[] = {
  {   0, "basic" },
  {   1, "medium" },
  {   2, "high" },
  { 0, NULL }
};


static int
dissect_tcg_cp_oids_StrengthOfFunction(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_tcg_cp_oids_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_tcg_cp_oids_BIT_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
                                    NULL);

  return offset;
}


static const ber_sequence_t URIReference_sequence[] = {
  { &hf_tcg_cp_oids_uniformResourceIdentifier, BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_NOOWNTAG, dissect_tcg_cp_oids_IA5String },
  { &hf_tcg_cp_oids_hashAlgorithm, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_AlgorithmIdentifier },
  { &hf_tcg_cp_oids_uri_reference_hashvalue, BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcg_cp_oids_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_tcg_cp_oids_URIReference(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   URIReference_sequence, hf_index, ett_tcg_cp_oids_URIReference);

  return offset;
}


static const ber_sequence_t CommonCriteriaMeasures_sequence[] = {
  { &hf_tcg_cp_oids_cc_measures_version_string, BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_NOOWNTAG, dissect_tcg_cp_oids_IA5String },
  { &hf_tcg_cp_oids_assurancelevel, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_tcg_cp_oids_EvaluationAssuranceLevel },
  { &hf_tcg_cp_oids_evaluationStatus, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_tcg_cp_oids_EvaluationStatus },
  { &hf_tcg_cp_oids_plus    , BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcg_cp_oids_BOOLEAN },
  { &hf_tcg_cp_oids_strengthOfFunction, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tcg_cp_oids_StrengthOfFunction },
  { &hf_tcg_cp_oids_profileOid, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tcg_cp_oids_OBJECT_IDENTIFIER },
  { &hf_tcg_cp_oids_profileUri, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tcg_cp_oids_URIReference },
  { &hf_tcg_cp_oids_targetOid, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tcg_cp_oids_OBJECT_IDENTIFIER },
  { &hf_tcg_cp_oids_targetUri, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tcg_cp_oids_URIReference },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_tcg_cp_oids_CommonCriteriaMeasures(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CommonCriteriaMeasures_sequence, hf_index, ett_tcg_cp_oids_CommonCriteriaMeasures);

  return offset;
}


static const value_string tcg_cp_oids_SecurityLevel_vals[] = {
  {   1, "level1" },
  {   2, "level2" },
  {   3, "level3" },
  {   4, "level4" },
  { 0, NULL }
};


static int
dissect_tcg_cp_oids_SecurityLevel(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t FIPSLevel_sequence[] = {
  { &hf_tcg_cp_oids_fips_level_version_string, BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_NOOWNTAG, dissect_tcg_cp_oids_IA5String },
  { &hf_tcg_cp_oids_fips_security_level, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_tcg_cp_oids_SecurityLevel },
  { &hf_tcg_cp_oids_plus    , BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcg_cp_oids_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_tcg_cp_oids_FIPSLevel(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   FIPSLevel_sequence, hf_index, ett_tcg_cp_oids_FIPSLevel);

  return offset;
}


static const ber_sequence_t TPMSecurityAssertions_sequence[] = {
  { &hf_tcg_cp_oids_security_assertions_version, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcg_cp_oids_Version },
  { &hf_tcg_cp_oids_fieldUpgradable, BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcg_cp_oids_BOOLEAN },
  { &hf_tcg_cp_oids_ekGenerationType, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tcg_cp_oids_EKGenerationType },
  { &hf_tcg_cp_oids_ekGenerationLocation, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tcg_cp_oids_EKGenerationLocation },
  { &hf_tcg_cp_oids_ekCertificateGenerationLocation, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tcg_cp_oids_EKCertificateGenerationLocation },
  { &hf_tcg_cp_oids_ccInfo  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tcg_cp_oids_CommonCriteriaMeasures },
  { &hf_tcg_cp_oids_fipsLevel, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tcg_cp_oids_FIPSLevel },
  { &hf_tcg_cp_oids_iso9000Certified, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tcg_cp_oids_BOOLEAN },
  { &hf_tcg_cp_oids_iso9000Uri, BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcg_cp_oids_IA5String },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_tcg_cp_oids_TPMSecurityAssertions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TPMSecurityAssertions_sequence, hf_index, ett_tcg_cp_oids_TPMSecurityAssertions);

  return offset;
}


static const value_string tcg_cp_oids_MeasurementRootType_vals[] = {
  {   0, "static" },
  {   1, "dynamic" },
  {   2, "nonHost" },
  {   3, "hybrid" },
  {   4, "physical" },
  {   5, "virtual" },
  { 0, NULL }
};


static int
dissect_tcg_cp_oids_MeasurementRootType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t TBBSecurityAssertions_sequence[] = {
  { &hf_tcg_cp_oids_security_assertions_version, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcg_cp_oids_Version },
  { &hf_tcg_cp_oids_ccInfo  , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tcg_cp_oids_CommonCriteriaMeasures },
  { &hf_tcg_cp_oids_fipsLevel, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tcg_cp_oids_FIPSLevel },
  { &hf_tcg_cp_oids_rtmType , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tcg_cp_oids_MeasurementRootType },
  { &hf_tcg_cp_oids_iso9000Certified, BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcg_cp_oids_BOOLEAN },
  { &hf_tcg_cp_oids_iso9000Uri, BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcg_cp_oids_IA5String },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_tcg_cp_oids_TBBSecurityAssertions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TBBSecurityAssertions_sequence, hf_index, ett_tcg_cp_oids_TBBSecurityAssertions);

  return offset;
}



static int
dissect_tcg_cp_oids_ProtectionProfile(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_tcg_cp_oids_SecurityTarget(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t HashAlgAndValue_sequence[] = {
  { &hf_tcg_cp_oids_hashAlg , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_AlgorithmIdentifier },
  { &hf_tcg_cp_oids_hash_alg_and_value_hashvalue, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_tcg_cp_oids_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_tcg_cp_oids_HashAlgAndValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   HashAlgAndValue_sequence, hf_index, ett_tcg_cp_oids_HashAlgAndValue);

  return offset;
}


static const ber_sequence_t HashedSubjectInfoURI_sequence[] = {
  { &hf_tcg_cp_oids_documentURI, BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_NOOWNTAG, dissect_tcg_cp_oids_IA5String },
  { &hf_tcg_cp_oids_documentAccessInfo, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcg_cp_oids_OBJECT_IDENTIFIER },
  { &hf_tcg_cp_oids_documentHashInfo, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcg_cp_oids_HashAlgAndValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_tcg_cp_oids_HashedSubjectInfoURI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   HashedSubjectInfoURI_sequence, hf_index, ett_tcg_cp_oids_HashedSubjectInfoURI);

  return offset;
}


static const ber_sequence_t TCGRelevantCredentials_sequence_of[1] = {
  { &hf_tcg_cp_oids_TCGRelevantCredentials_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_tcg_cp_oids_HashedSubjectInfoURI },
};

static int
dissect_tcg_cp_oids_TCGRelevantCredentials(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      TCGRelevantCredentials_sequence_of, hf_index, ett_tcg_cp_oids_TCGRelevantCredentials);

  return offset;
}


static const ber_sequence_t TCGRelevantManifests_sequence_of[1] = {
  { &hf_tcg_cp_oids_TCGRelevantManifests_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_tcg_cp_oids_HashedSubjectInfoURI },
};

static int
dissect_tcg_cp_oids_TCGRelevantManifests(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      TCGRelevantManifests_sequence_of, hf_index, ett_tcg_cp_oids_TCGRelevantManifests);

  return offset;
}



static int
dissect_tcg_cp_oids_VirtualPlatformAttestationServiceURI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_tcg_cp_oids_MigrationControllerAttestationServiceURI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_tcg_cp_oids_MigrationControllerRegistrationServiceURI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t VirtualPlatformBackupServiceURI_sequence[] = {
  { &hf_tcg_cp_oids_restoreAllowed, BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_tcg_cp_oids_BOOLEAN },
  { &hf_tcg_cp_oids_backupServiceURI, BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_NOOWNTAG, dissect_tcg_cp_oids_IA5String },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_tcg_cp_oids_VirtualPlatformBackupServiceURI(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   VirtualPlatformBackupServiceURI_sequence, hf_index, ett_tcg_cp_oids_VirtualPlatformBackupServiceURI);

  return offset;
}

/*--- PDUs ---*/

static int dissect_TPMSpecification_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_tcg_cp_oids_TPMSpecification(FALSE, tvb, offset, &asn1_ctx, tree, hf_tcg_cp_oids_TPMSpecification_PDU);
  return offset;
}
static int dissect_TCGPlatformSpecification_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_tcg_cp_oids_TCGPlatformSpecification(FALSE, tvb, offset, &asn1_ctx, tree, hf_tcg_cp_oids_TCGPlatformSpecification_PDU);
  return offset;
}
static int dissect_TCPASpecVersion_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_tcg_cp_oids_TCPASpecVersion(FALSE, tvb, offset, &asn1_ctx, tree, hf_tcg_cp_oids_TCPASpecVersion_PDU);
  return offset;
}
static int dissect_TPMSecurityAssertions_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_tcg_cp_oids_TPMSecurityAssertions(FALSE, tvb, offset, &asn1_ctx, tree, hf_tcg_cp_oids_TPMSecurityAssertions_PDU);
  return offset;
}
static int dissect_TBBSecurityAssertions_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_tcg_cp_oids_TBBSecurityAssertions(FALSE, tvb, offset, &asn1_ctx, tree, hf_tcg_cp_oids_TBBSecurityAssertions_PDU);
  return offset;
}
static int dissect_ProtectionProfile_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_tcg_cp_oids_ProtectionProfile(FALSE, tvb, offset, &asn1_ctx, tree, hf_tcg_cp_oids_ProtectionProfile_PDU);
  return offset;
}
static int dissect_SecurityTarget_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_tcg_cp_oids_SecurityTarget(FALSE, tvb, offset, &asn1_ctx, tree, hf_tcg_cp_oids_SecurityTarget_PDU);
  return offset;
}
static int dissect_TCGRelevantCredentials_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_tcg_cp_oids_TCGRelevantCredentials(FALSE, tvb, offset, &asn1_ctx, tree, hf_tcg_cp_oids_TCGRelevantCredentials_PDU);
  return offset;
}
static int dissect_TCGRelevantManifests_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_tcg_cp_oids_TCGRelevantManifests(FALSE, tvb, offset, &asn1_ctx, tree, hf_tcg_cp_oids_TCGRelevantManifests_PDU);
  return offset;
}
static int dissect_VirtualPlatformAttestationServiceURI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_tcg_cp_oids_VirtualPlatformAttestationServiceURI(FALSE, tvb, offset, &asn1_ctx, tree, hf_tcg_cp_oids_VirtualPlatformAttestationServiceURI_PDU);
  return offset;
}
static int dissect_MigrationControllerAttestationServiceURI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_tcg_cp_oids_MigrationControllerAttestationServiceURI(FALSE, tvb, offset, &asn1_ctx, tree, hf_tcg_cp_oids_MigrationControllerAttestationServiceURI_PDU);
  return offset;
}
static int dissect_MigrationControllerRegistrationServiceURI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_tcg_cp_oids_MigrationControllerRegistrationServiceURI(FALSE, tvb, offset, &asn1_ctx, tree, hf_tcg_cp_oids_MigrationControllerRegistrationServiceURI_PDU);
  return offset;
}
static int dissect_VirtualPlatformBackupServiceURI_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_tcg_cp_oids_VirtualPlatformBackupServiceURI(FALSE, tvb, offset, &asn1_ctx, tree, hf_tcg_cp_oids_VirtualPlatformBackupServiceURI_PDU);
  return offset;
}


/*--- End of included file: packet-tcg-cp-oids-fn.c ---*/
#line 36 "./asn1/tcg-cp-oids/packet-tcg-cp-oids-template.c"


/*--- proto_register_tcg_cp_oids ----------------------------------------------*/
void proto_register_tcg_cp_oids(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_tcg_cp_oids_UTF8String_PDU,
      { "UTF8String", "tcg-cp-oids.UTF8String",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/*--- Included file: packet-tcg-cp-oids-hfarr.c ---*/
#line 1 "./asn1/tcg-cp-oids/packet-tcg-cp-oids-hfarr.c"
    { &hf_tcg_cp_oids_TPMSpecification_PDU,
      { "TPMSpecification", "tcg-cp-oids.TPMSpecification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tcg_cp_oids_TCGPlatformSpecification_PDU,
      { "TCGPlatformSpecification", "tcg-cp-oids.TCGPlatformSpecification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tcg_cp_oids_TCPASpecVersion_PDU,
      { "TCPASpecVersion", "tcg-cp-oids.TCPASpecVersion_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tcg_cp_oids_TPMSecurityAssertions_PDU,
      { "TPMSecurityAssertions", "tcg-cp-oids.TPMSecurityAssertions_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tcg_cp_oids_TBBSecurityAssertions_PDU,
      { "TBBSecurityAssertions", "tcg-cp-oids.TBBSecurityAssertions_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tcg_cp_oids_ProtectionProfile_PDU,
      { "ProtectionProfile", "tcg-cp-oids.ProtectionProfile",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tcg_cp_oids_SecurityTarget_PDU,
      { "SecurityTarget", "tcg-cp-oids.SecurityTarget",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tcg_cp_oids_TCGRelevantCredentials_PDU,
      { "TCGRelevantCredentials", "tcg-cp-oids.TCGRelevantCredentials",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tcg_cp_oids_TCGRelevantManifests_PDU,
      { "TCGRelevantManifests", "tcg-cp-oids.TCGRelevantManifests",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_tcg_cp_oids_VirtualPlatformAttestationServiceURI_PDU,
      { "VirtualPlatformAttestationServiceURI", "tcg-cp-oids.VirtualPlatformAttestationServiceURI",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tcg_cp_oids_MigrationControllerAttestationServiceURI_PDU,
      { "MigrationControllerAttestationServiceURI", "tcg-cp-oids.MigrationControllerAttestationServiceURI",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tcg_cp_oids_MigrationControllerRegistrationServiceURI_PDU,
      { "MigrationControllerRegistrationServiceURI", "tcg-cp-oids.MigrationControllerRegistrationServiceURI",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tcg_cp_oids_VirtualPlatformBackupServiceURI_PDU,
      { "VirtualPlatformBackupServiceURI", "tcg-cp-oids.VirtualPlatformBackupServiceURI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tcg_cp_oids_family,
      { "family", "tcg-cp-oids.family",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_tcg_cp_oids_tpm_specification_level,
      { "level", "tcg-cp-oids.level",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_tcg_cp_oids_revision,
      { "revision", "tcg-cp-oids.revision",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_tcg_cp_oids_majorVersion,
      { "majorVersion", "tcg-cp-oids.majorVersion",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_tcg_cp_oids_minorVersion,
      { "minorVersion", "tcg-cp-oids.minorVersion",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_tcg_cp_oids_tcg_specification_vesion,
      { "version", "tcg-cp-oids.version_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TCGSpecificationVersion", HFILL }},
    { &hf_tcg_cp_oids_platformClass,
      { "platformClass", "tcg-cp-oids.platformClass",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_tcg_cp_oids_major,
      { "major", "tcg-cp-oids.major",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_tcg_cp_oids_minor,
      { "minor", "tcg-cp-oids.minor",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_tcg_cp_oids_security_assertions_version,
      { "version", "tcg-cp-oids.version",
        FT_INT32, BASE_DEC, VALS(pkix1explicit_Version_vals), 0,
        NULL, HFILL }},
    { &hf_tcg_cp_oids_fieldUpgradable,
      { "fieldUpgradable", "tcg-cp-oids.fieldUpgradable",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_tcg_cp_oids_ekGenerationType,
      { "ekGenerationType", "tcg-cp-oids.ekGenerationType",
        FT_UINT32, BASE_DEC, VALS(tcg_cp_oids_EKGenerationType_vals), 0,
        NULL, HFILL }},
    { &hf_tcg_cp_oids_ekGenerationLocation,
      { "ekGenerationLocation", "tcg-cp-oids.ekGenerationLocation",
        FT_UINT32, BASE_DEC, VALS(tcg_cp_oids_EKGenerationLocation_vals), 0,
        NULL, HFILL }},
    { &hf_tcg_cp_oids_ekCertificateGenerationLocation,
      { "ekCertificateGenerationLocation", "tcg-cp-oids.ekCertificateGenerationLocation",
        FT_UINT32, BASE_DEC, VALS(tcg_cp_oids_EKCertificateGenerationLocation_vals), 0,
        NULL, HFILL }},
    { &hf_tcg_cp_oids_ccInfo,
      { "ccInfo", "tcg-cp-oids.ccInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CommonCriteriaMeasures", HFILL }},
    { &hf_tcg_cp_oids_fipsLevel,
      { "fipsLevel", "tcg-cp-oids.fipsLevel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tcg_cp_oids_iso9000Certified,
      { "iso9000Certified", "tcg-cp-oids.iso9000Certified",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_tcg_cp_oids_iso9000Uri,
      { "iso9000Uri", "tcg-cp-oids.iso9000Uri",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String", HFILL }},
    { &hf_tcg_cp_oids_rtmType,
      { "rtmType", "tcg-cp-oids.rtmType",
        FT_UINT32, BASE_DEC, VALS(tcg_cp_oids_MeasurementRootType_vals), 0,
        "MeasurementRootType", HFILL }},
    { &hf_tcg_cp_oids_cc_measures_version_string,
      { "version", "tcg-cp-oids.version",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String", HFILL }},
    { &hf_tcg_cp_oids_assurancelevel,
      { "assurancelevel", "tcg-cp-oids.assurancelevel",
        FT_UINT32, BASE_DEC, VALS(tcg_cp_oids_EvaluationAssuranceLevel_vals), 0,
        "EvaluationAssuranceLevel", HFILL }},
    { &hf_tcg_cp_oids_evaluationStatus,
      { "evaluationStatus", "tcg-cp-oids.evaluationStatus",
        FT_UINT32, BASE_DEC, VALS(tcg_cp_oids_EvaluationStatus_vals), 0,
        NULL, HFILL }},
    { &hf_tcg_cp_oids_plus,
      { "plus", "tcg-cp-oids.plus",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_tcg_cp_oids_strengthOfFunction,
      { "strengthOfFunction", "tcg-cp-oids.strengthOfFunction",
        FT_UINT32, BASE_DEC, VALS(tcg_cp_oids_StrengthOfFunction_vals), 0,
        NULL, HFILL }},
    { &hf_tcg_cp_oids_profileOid,
      { "profileOid", "tcg-cp-oids.profileOid",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_tcg_cp_oids_profileUri,
      { "profileUri", "tcg-cp-oids.profileUri_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "URIReference", HFILL }},
    { &hf_tcg_cp_oids_targetOid,
      { "targetOid", "tcg-cp-oids.targetOid",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_tcg_cp_oids_targetUri,
      { "targetUri", "tcg-cp-oids.targetUri_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "URIReference", HFILL }},
    { &hf_tcg_cp_oids_uniformResourceIdentifier,
      { "uniformResourceIdentifier", "tcg-cp-oids.uniformResourceIdentifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String", HFILL }},
    { &hf_tcg_cp_oids_hashAlgorithm,
      { "hashAlgorithm", "tcg-cp-oids.hashAlgorithm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_tcg_cp_oids_uri_reference_hashvalue,
      { "hashValue", "tcg-cp-oids.hashValue",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_tcg_cp_oids_fips_level_version_string,
      { "version", "tcg-cp-oids.version",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String", HFILL }},
    { &hf_tcg_cp_oids_fips_security_level,
      { "level", "tcg-cp-oids.level",
        FT_UINT32, BASE_DEC, VALS(tcg_cp_oids_SecurityLevel_vals), 0,
        "SecurityLevel", HFILL }},
    { &hf_tcg_cp_oids_hashAlg,
      { "hashAlg", "tcg-cp-oids.hashAlg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_tcg_cp_oids_hash_alg_and_value_hashvalue,
      { "hashValue", "tcg-cp-oids.hashValue",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_tcg_cp_oids_documentURI,
      { "documentURI", "tcg-cp-oids.documentURI",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String", HFILL }},
    { &hf_tcg_cp_oids_documentAccessInfo,
      { "documentAccessInfo", "tcg-cp-oids.documentAccessInfo",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_tcg_cp_oids_documentHashInfo,
      { "documentHashInfo", "tcg-cp-oids.documentHashInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "HashAlgAndValue", HFILL }},
    { &hf_tcg_cp_oids_TCGRelevantCredentials_item,
      { "HashedSubjectInfoURI", "tcg-cp-oids.HashedSubjectInfoURI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tcg_cp_oids_TCGRelevantManifests_item,
      { "HashedSubjectInfoURI", "tcg-cp-oids.HashedSubjectInfoURI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_tcg_cp_oids_restoreAllowed,
      { "restoreAllowed", "tcg-cp-oids.restoreAllowed",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_tcg_cp_oids_backupServiceURI,
      { "backupServiceURI", "tcg-cp-oids.backupServiceURI",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String", HFILL }},

/*--- End of included file: packet-tcg-cp-oids-hfarr.c ---*/
#line 48 "./asn1/tcg-cp-oids/packet-tcg-cp-oids-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-tcg-cp-oids-ettarr.c ---*/
#line 1 "./asn1/tcg-cp-oids/packet-tcg-cp-oids-ettarr.c"
    &ett_tcg_cp_oids_TPMSpecification,
    &ett_tcg_cp_oids_TCGSpecificationVersion,
    &ett_tcg_cp_oids_TCGPlatformSpecification,
    &ett_tcg_cp_oids_TCPASpecVersion,
    &ett_tcg_cp_oids_TPMSecurityAssertions,
    &ett_tcg_cp_oids_TBBSecurityAssertions,
    &ett_tcg_cp_oids_CommonCriteriaMeasures,
    &ett_tcg_cp_oids_URIReference,
    &ett_tcg_cp_oids_FIPSLevel,
    &ett_tcg_cp_oids_HashAlgAndValue,
    &ett_tcg_cp_oids_HashedSubjectInfoURI,
    &ett_tcg_cp_oids_TCGRelevantCredentials,
    &ett_tcg_cp_oids_TCGRelevantManifests,
    &ett_tcg_cp_oids_VirtualPlatformBackupServiceURI,

/*--- End of included file: packet-tcg-cp-oids-ettarr.c ---*/
#line 53 "./asn1/tcg-cp-oids/packet-tcg-cp-oids-template.c"
  };

  /* Register protocol */
  proto_tcg_cp_oids = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_tcg_cp_oids, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

/* to be able to register OIDs for UTF8String */
static int
dissect_tcg_cp_oids_UTF8String_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
    int offset = 0;
    asn1_ctx_t actx;
    asn1_ctx_init(&actx, ASN1_ENC_BER, TRUE, pinfo);
    offset = dissect_ber_restricted_string(FALSE, BER_UNI_TAG_UTF8String, &actx, tree, tvb, offset, hf_tcg_cp_oids_UTF8String_PDU, NULL);
    return offset;
}

/*--- proto_reg_handoff_tcg_cp_oids -------------------------------------------*/
void proto_reg_handoff_tcg_cp_oids(void) {

/*--- Included file: packet-tcg-cp-oids-dis-tab.c ---*/
#line 1 "./asn1/tcg-cp-oids/packet-tcg-cp-oids-dis-tab.c"
  register_ber_oid_dissector("2.23.133.1", dissect_TCPASpecVersion_PDU, proto_tcg_cp_oids, "tcg-tcpaSpecVersion");
  register_ber_oid_dissector("2.23.133.2.11", dissect_ProtectionProfile_PDU, proto_tcg_cp_oids, "tcg-at-tpmProtectionProfile");
  register_ber_oid_dissector("2.23.133.2.12", dissect_SecurityTarget_PDU, proto_tcg_cp_oids, "tcg-at-tpmSecurityTarget");
  register_ber_oid_dissector("2.23.133.2.13", dissect_ProtectionProfile_PDU, proto_tcg_cp_oids, "tcg-at-tbbProtectionProfile");
  register_ber_oid_dissector("2.23.133.2.14", dissect_SecurityTarget_PDU, proto_tcg_cp_oids, "tcg-at-tbbSecurityTarget");
  register_ber_oid_dissector("2.23.133.2.16", dissect_TPMSpecification_PDU, proto_tcg_cp_oids, "tcg-at-tpmSpecification");
  register_ber_oid_dissector("2.23.133.2.17", dissect_TCGPlatformSpecification_PDU, proto_tcg_cp_oids, "tcg-at-tcgPlatformSpecification");
  register_ber_oid_dissector("2.23.133.2.18", dissect_TPMSecurityAssertions_PDU, proto_tcg_cp_oids, "tcg-at-tpmSecurityAssertions");
  register_ber_oid_dissector("2.23.133.2.19", dissect_TBBSecurityAssertions_PDU, proto_tcg_cp_oids, "tcg-at-tbbSecurityAssertions");
  register_ber_oid_dissector("2.23.133.6.2", dissect_TCGRelevantCredentials_PDU, proto_tcg_cp_oids, "tcg-ce-relevantCredentials");
  register_ber_oid_dissector("2.23.133.6.3", dissect_TCGRelevantManifests_PDU, proto_tcg_cp_oids, "tcg-ce-relevantManifests");
  register_ber_oid_dissector("2.23.133.6.4", dissect_VirtualPlatformAttestationServiceURI_PDU, proto_tcg_cp_oids, "tcg-ce-virtualPlatformAttestationService");
  register_ber_oid_dissector("2.23.133.6.5", dissect_MigrationControllerAttestationServiceURI_PDU, proto_tcg_cp_oids, "tcg-ce-migrationControllerAttestationService");
  register_ber_oid_dissector("2.23.133.6.6", dissect_MigrationControllerRegistrationServiceURI_PDU, proto_tcg_cp_oids, "tcg-ce-migrationControllerRegistrationService");
  register_ber_oid_dissector("2.23.133.6.7", dissect_VirtualPlatformBackupServiceURI_PDU, proto_tcg_cp_oids, "tcg-ce-virtualPlatformBackupService");


/*--- End of included file: packet-tcg-cp-oids-dis-tab.c ---*/
#line 76 "./asn1/tcg-cp-oids/packet-tcg-cp-oids-template.c"
  oid_add_from_string("tcg","2.23.133");
  oid_add_from_string("tcg-attribute","2.23.133.2");
  oid_add_from_string("tcg-protocol","2.23.133.3");
  oid_add_from_string("tcg-algorithm","2.23.133.4");
  oid_add_from_string("tcg-ce","2.23.133.6");
  oid_add_from_string("tcg-kp","2.23.133.8");
  /* TCG Spec Version OIDs */
  oid_add_from_string("tcg-sv-tpm12","2.23.133.1.1");
  oid_add_from_string("tcg-sv-tpm20","2.23.133.1.2");
  /* TCG Attribute OIDs */
  oid_add_from_string("tcg-at-securityQualities","2.23.133.2.10");
  /* TCG Algorithm OIDs */
  oid_add_from_string("tcg-algorithm-null","2.23.133.4.1");
  /* TCG Key Purposes OIDs */
  oid_add_from_string("tcg-kp-EKCertificate","2.23.133.8.1");
  oid_add_from_string("tcg-kp-PlatformCertificate","2.23.133.8.2");
  oid_add_from_string("tcg-kp-AIKCertificate","2.23.133.8.3");
  /* TCG Protocol OIDs */
  oid_add_from_string("tcg-prt-tpmIdProtocol","2.23.133.3.1");

  register_ber_oid_dissector("2.23.133.2.1", dissect_tcg_cp_oids_UTF8String_PDU, proto_tcg_cp_oids, "tcg-at-tpmManufacturer");
  register_ber_oid_dissector("2.23.133.2.2", dissect_tcg_cp_oids_UTF8String_PDU, proto_tcg_cp_oids, "tcg-at-tpmModel");
  register_ber_oid_dissector("2.23.133.2.3", dissect_tcg_cp_oids_UTF8String_PDU, proto_tcg_cp_oids, "tcg-at-tpmVersion");
  register_ber_oid_dissector("2.23.133.2.4", dissect_tcg_cp_oids_UTF8String_PDU, proto_tcg_cp_oids, "tcg-at-platformManufacturer");
  register_ber_oid_dissector("2.23.133.2.5", dissect_tcg_cp_oids_UTF8String_PDU, proto_tcg_cp_oids, "tcg-at-platformModel");
  register_ber_oid_dissector("2.23.133.2.6", dissect_tcg_cp_oids_UTF8String_PDU, proto_tcg_cp_oids, "tcg-at-platformVersion");
  register_ber_oid_dissector("2.23.133.2.15", dissect_tcg_cp_oids_UTF8String_PDU, proto_tcg_cp_oids, "tcg-at-tpmIdLabel");
}
