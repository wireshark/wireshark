/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-acp133.c                                                            */
/* asn2wrs.py -b -q -L -p acp133 -c ./acp133.cnf -s ./packet-acp133-template -D . -O ../.. acp133.asn MHSDirectoryObjectsAndAttributes.asn */

/* packet-acp133.c
 * Routines for ACP133 specific syntaxes in X.500 packet dissection
 * Graeme Lunt 2005
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
#include <epan/oids.h>

#include "packet-ber.h"

#include "packet-p1.h"
#include "packet-x509af.h"
#include "packet-x509ce.h"
#include "packet-x509if.h"
#include "packet-x509sat.h"

#include "packet-acp133.h"

#define PNAME  "ACP133 Attribute Syntaxes"
#define PSNAME "ACP133"
#define PFNAME "acp133"

void proto_register_acp133(void);
void proto_reg_handoff_acp133(void);

/* Initialize the protocol and registered fields */
static int proto_acp133;


static int hf_acp133_ACPPreferredDelivery_PDU;    /* ACPPreferredDelivery */
static int hf_acp133_ALType_PDU;                  /* ALType */
static int hf_acp133_Community_PDU;               /* Community */
static int hf_acp133_OnSupported_PDU;             /* OnSupported */
static int hf_acp133_ACPLegacyFormat_PDU;         /* ACPLegacyFormat */
static int hf_acp133_ACPNoAttachments_PDU;        /* ACPNoAttachments */
static int hf_acp133_Active_PDU;                  /* Active */
static int hf_acp133_Addressees_PDU;              /* Addressees */
static int hf_acp133_Classification_PDU;          /* Classification */
static int hf_acp133_DistributionCode_PDU;        /* DistributionCode */
static int hf_acp133_EmConCapability_PDU;         /* EmConCapability */
static int hf_acp133_EmConState_PDU;              /* EmConState */
static int hf_acp133_JPEG_PDU;                    /* JPEG */
static int hf_acp133_MaxMessageSize_PDU;          /* MaxMessageSize */
static int hf_acp133_MonthlyUKMs_PDU;             /* MonthlyUKMs */
static int hf_acp133_MsgProtocolInfoCapability_PDU;  /* MsgProtocolInfoCapability */
static int hf_acp133_Remarks_PDU;                 /* Remarks */
static int hf_acp133_RIParameters_PDU;            /* RIParameters */
static int hf_acp133_WebAccessCapability_PDU;     /* WebAccessCapability */
static int hf_acp133_Kmid_PDU;                    /* Kmid */
static int hf_acp133_MLReceiptPolicy_PDU;         /* MLReceiptPolicy */
static int hf_acp133_DLSubmitPermission_PDU;      /* DLSubmitPermission */
static int hf_acp133_DLPolicy_PDU;                /* DLPolicy */
static int hf_acp133_AddressCapabilities_PDU;     /* AddressCapabilities */
static int hf_acp133_Capability_PDU;              /* Capability */
static int hf_acp133_Addressees_item;             /* PrintableString_SIZE_1_55 */
static int hf_acp133_ukm_entries;                 /* SEQUENCE_OF_UKMEntry */
static int hf_acp133_ukm_entries_item;            /* UKMEntry */
static int hf_acp133_algorithm_identifier;        /* AlgorithmIdentifier */
static int hf_acp133_encrypted;                   /* BIT_STRING */
static int hf_acp133_Remarks_item;                /* PrintableString */
static int hf_acp133_ri_parameters;               /* DirectoryString */
static int hf_acp133_ri_parameters_deprecated;    /* RIParametersDeprecated */
static int hf_acp133_rI;                          /* PrintableString */
static int hf_acp133_rIType;                      /* T_rIType */
static int hf_acp133_minimize;                    /* BOOLEAN */
static int hf_acp133_sHD;                         /* PrintableString */
static int hf_acp133_classification;              /* Classification */
static int hf_acp133_tag;                         /* PairwiseTag */
static int hf_acp133_ukm;                         /* OCTET_STRING */
static int hf_acp133_kmid;                        /* Kmid */
static int hf_acp133_edition;                     /* INTEGER */
static int hf_acp133_date;                        /* UTCTime */
static int hf_acp133_none;                        /* NULL */
static int hf_acp133_insteadOf;                   /* SEQUENCE_OF_GeneralNames */
static int hf_acp133_insteadOf_item;              /* GeneralNames */
static int hf_acp133_inAdditionTo;                /* SEQUENCE_OF_GeneralNames */
static int hf_acp133_inAdditionTo_item;           /* GeneralNames */
static int hf_acp133_individual;                  /* ORName */
static int hf_acp133_member_of_dl;                /* ORName */
static int hf_acp133_pattern_match;               /* ORNamePattern */
static int hf_acp133_member_of_group;             /* Name */
static int hf_acp133_report_propagation;          /* T_report_propagation */
static int hf_acp133_report_from_dl;              /* T_report_from_dl */
static int hf_acp133_originating_MTA_report;      /* T_originating_MTA_report */
static int hf_acp133_originator_report;           /* T_originator_report */
static int hf_acp133_return_of_content;           /* T_return_of_content */
static int hf_acp133_priority;                    /* T_priority */
static int hf_acp133_disclosure_of_other_recipients;  /* T_disclosure_of_other_recipients */
static int hf_acp133_implicit_conversion_prohibited;  /* T_implicit_conversion_prohibited */
static int hf_acp133_conversion_with_loss_prohibited;  /* T_conversion_with_loss_prohibited */
static int hf_acp133_further_dl_expansion_allowed;  /* BOOLEAN */
static int hf_acp133_originator_requested_alternate_recipient_removed;  /* BOOLEAN */
static int hf_acp133_proof_of_delivery;           /* T_proof_of_delivery */
static int hf_acp133_requested_delivery_method;   /* T_requested_delivery_method */
static int hf_acp133_unchanged;                   /* NULL */
static int hf_acp133_removed;                     /* NULL */
static int hf_acp133_replaced;                    /* RequestedDeliveryMethod */
static int hf_acp133_token_encryption_algorithm_preference;  /* SEQUENCE_OF_AlgorithmInformation */
static int hf_acp133_token_encryption_algorithm_preference_item;  /* AlgorithmInformation */
static int hf_acp133_token_signature_algorithm_preference;  /* SEQUENCE_OF_AlgorithmInformation */
static int hf_acp133_token_signature_algorithm_preference_item;  /* AlgorithmInformation */
static int hf_acp133_originator_certificate_selector;  /* CertificateAssertion */
static int hf_acp133_recipient_certificate_selector;  /* CertificateAssertion */
static int hf_acp133_description;                 /* GeneralString */
static int hf_acp133_address;                     /* ORAddress */
static int hf_acp133_capabilities;                /* SET_OF_Capability */
static int hf_acp133_capabilities_item;           /* Capability */
static int hf_acp133_content_types;               /* SET_OF_ExtendedContentType */
static int hf_acp133_content_types_item;          /* ExtendedContentType */
static int hf_acp133_maximum_content_length;      /* ContentLength */
static int hf_acp133_encoded_information_types_constraints;  /* EncodedInformationTypesConstraints */
static int hf_acp133_security_labels;             /* SecurityContext */
/* named bits */
static int hf_acp133_OnSupported_acp127_nn;
static int hf_acp133_OnSupported_acp127_pn;
static int hf_acp133_OnSupported_acp127_tn;

/* Initialize the subtree pointers */
static int ett_acp133;
static int ett_acp133_OnSupported;
static int ett_acp133_Addressees;
static int ett_acp133_MonthlyUKMs;
static int ett_acp133_SEQUENCE_OF_UKMEntry;
static int ett_acp133_Remarks;
static int ett_acp133_RIParameters;
static int ett_acp133_RIParametersDeprecated;
static int ett_acp133_UKMEntry;
static int ett_acp133_PairwiseTag;
static int ett_acp133_MLReceiptPolicy;
static int ett_acp133_SEQUENCE_OF_GeneralNames;
static int ett_acp133_DLSubmitPermission;
static int ett_acp133_DLPolicy;
static int ett_acp133_T_requested_delivery_method;
static int ett_acp133_SEQUENCE_OF_AlgorithmInformation;
static int ett_acp133_AlgorithmInformation;
static int ett_acp133_AddressCapabilities;
static int ett_acp133_SET_OF_Capability;
static int ett_acp133_Capability;
static int ett_acp133_SET_OF_ExtendedContentType;


static const value_string acp133_ACPPreferredDelivery_vals[] = {
  {   0, "smtp" },
  {   1, "acp127" },
  {   2, "mhs" },
  { 0, NULL }
};


static int
dissect_acp133_ACPPreferredDelivery(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string acp133_ALType_vals[] = {
  {   0, "aig" },
  {   1, "type" },
  {   2, "cad" },
  {   3, "taskforce" },
  {   4, "dag" },
  { 0, NULL }
};


static int
dissect_acp133_ALType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string acp133_Community_vals[] = {
  {   0, "genser" },
  {   1, "si" },
  {   2, "both" },
  { 0, NULL }
};


static int
dissect_acp133_Community(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static int * const OnSupported_bits[] = {
  &hf_acp133_OnSupported_acp127_nn,
  &hf_acp133_OnSupported_acp127_pn,
  &hf_acp133_OnSupported_acp127_tn,
  NULL
};

static int
dissect_acp133_OnSupported(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    OnSupported_bits, 3, hf_index, ett_acp133_OnSupported,
                                    NULL);

  return offset;
}


static const value_string acp133_ACPLegacyFormat_vals[] = {
  {   0, "janap128" },
  {   1, "acp127" },
  {   2, "doi103" },
  {   3, "doi103-special" },
  {   4, "acp127" },
  {   5, "acp127-converted" },
  {   6, "reserved-1" },
  {   7, "acp127-state" },
  {   8, "acp127-modified" },
  {   9, "socomm-special" },
  {  10, "socomm-narrative" },
  {  11, "reserved-2" },
  {  12, "socomm-narrative-special" },
  {  13, "socomm-data" },
  {  14, "socomm-internal" },
  {  15, "socomm-external" },
  {  16, "mfi-default" },
  {  17, "acp-legacy-format-smtp" },
  {  18, "p22" },
  {  32, "acp145-united-states" },
  {  33, "acp145-australia" },
  {  34, "acp145-canada" },
  {  35, "acp145-united-kingdom" },
  {  36, "acp145-new-zealand" },
  { 0, NULL }
};


static int
dissect_acp133_ACPLegacyFormat(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_acp133_ACPNoAttachments(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_acp133_Active(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_acp133_PrintableString_SIZE_1_55(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t Addressees_sequence_of[1] = {
  { &hf_acp133_Addressees_item, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_acp133_PrintableString_SIZE_1_55 },
};

static int
dissect_acp133_Addressees(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Addressees_sequence_of, hf_index, ett_acp133_Addressees);

  return offset;
}


static const value_string acp133_Classification_vals[] = {
  {   0, "unmarked" },
  {   1, "unclassified" },
  {   2, "restricted" },
  {   3, "confidential" },
  {   4, "secret" },
  {   5, "top-secret" },
  { 0, NULL }
};


static int
dissect_acp133_Classification(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_acp133_DistributionCode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_acp133_EmConCapability(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const value_string acp133_EmConState_vals[] = {
  {   0, "enabled" },
  {   1, "receive-only" },
  {   2, "electronic-silence" },
  {   3, "disabled" },
  { 0, NULL }
};


static int
dissect_acp133_EmConState(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_acp133_JPEG(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_acp133_MaxMessageSize(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_acp133_Kmid(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_acp133_INTEGER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_acp133_UTCTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_UTCTime(implicit_tag, actx, tree, tvb, offset, hf_index, NULL, NULL);

  return offset;
}


static const ber_sequence_t PairwiseTag_sequence[] = {
  { &hf_acp133_kmid         , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_acp133_Kmid },
  { &hf_acp133_edition      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_acp133_INTEGER },
  { &hf_acp133_date         , BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_acp133_UTCTime },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_acp133_PairwiseTag(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PairwiseTag_sequence, hf_index, ett_acp133_PairwiseTag);

  return offset;
}



static int
dissect_acp133_OCTET_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t UKMEntry_sequence[] = {
  { &hf_acp133_tag          , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_acp133_PairwiseTag },
  { &hf_acp133_ukm          , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_acp133_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_acp133_UKMEntry(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UKMEntry_sequence, hf_index, ett_acp133_UKMEntry);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_UKMEntry_sequence_of[1] = {
  { &hf_acp133_ukm_entries_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_acp133_UKMEntry },
};

static int
dissect_acp133_SEQUENCE_OF_UKMEntry(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_UKMEntry_sequence_of, hf_index, ett_acp133_SEQUENCE_OF_UKMEntry);

  return offset;
}



static int
dissect_acp133_BIT_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
                                    NULL);

  return offset;
}


static const ber_sequence_t MonthlyUKMs_sequence[] = {
  { &hf_acp133_ukm_entries  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_acp133_SEQUENCE_OF_UKMEntry },
  { &hf_acp133_algorithm_identifier, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_acp133_encrypted    , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_acp133_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_acp133_MonthlyUKMs(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MonthlyUKMs_sequence, hf_index, ett_acp133_MonthlyUKMs);

  return offset;
}


static const value_string acp133_MsgProtocolInfoCapability_vals[] = {
  {   0, "acp-127" },
  {   1, "acp-123" },
  { 0, NULL }
};


static int
dissect_acp133_MsgProtocolInfoCapability(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_acp133_PrintableString(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t Remarks_sequence_of[1] = {
  { &hf_acp133_Remarks_item , BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_acp133_PrintableString },
};

static int
dissect_acp133_Remarks(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      Remarks_sequence_of, hf_index, ett_acp133_Remarks);

  return offset;
}


static const value_string acp133_T_rIType_vals[] = {
  {   0, "normal" },
  {   1, "off-line" },
  {   2, "partTimeTerminal" },
  { 0, NULL }
};


static int
dissect_acp133_T_rIType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_acp133_BOOLEAN(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t RIParametersDeprecated_set[] = {
  { &hf_acp133_rI           , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_acp133_PrintableString },
  { &hf_acp133_rIType       , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_acp133_T_rIType },
  { &hf_acp133_minimize     , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_acp133_BOOLEAN },
  { &hf_acp133_sHD          , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_acp133_PrintableString },
  { &hf_acp133_classification, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_acp133_Classification },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_acp133_RIParametersDeprecated(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              RIParametersDeprecated_set, hf_index, ett_acp133_RIParametersDeprecated);

  return offset;
}


static const value_string acp133_RIParameters_vals[] = {
  {   0, "ri-parameters" },
  {   1, "ri-parameters-deprecated" },
  { 0, NULL }
};

static const ber_choice_t RIParameters_choice[] = {
  {   0, &hf_acp133_ri_parameters, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_x509sat_DirectoryString },
  {   1, &hf_acp133_ri_parameters_deprecated, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_acp133_RIParametersDeprecated },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_acp133_RIParameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RIParameters_choice, hf_index, ett_acp133_RIParameters,
                                 NULL);

  return offset;
}



static int
dissect_acp133_WebAccessCapability(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_acp133_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_GeneralNames_sequence_of[1] = {
  { &hf_acp133_insteadOf_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509ce_GeneralNames },
};

static int
dissect_acp133_SEQUENCE_OF_GeneralNames(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_GeneralNames_sequence_of, hf_index, ett_acp133_SEQUENCE_OF_GeneralNames);

  return offset;
}


static const value_string acp133_MLReceiptPolicy_vals[] = {
  {   0, "none" },
  {   1, "insteadOf" },
  {   2, "inAdditionTo" },
  { 0, NULL }
};

static const ber_choice_t MLReceiptPolicy_choice[] = {
  {   0, &hf_acp133_none         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_acp133_NULL },
  {   1, &hf_acp133_insteadOf    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_acp133_SEQUENCE_OF_GeneralNames },
  {   2, &hf_acp133_inAdditionTo , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_acp133_SEQUENCE_OF_GeneralNames },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_acp133_MLReceiptPolicy(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 MLReceiptPolicy_choice, hf_index, ett_acp133_MLReceiptPolicy,
                                 NULL);

  return offset;
}



static int
dissect_acp133_ORNamePattern(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_p1_ORName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string acp133_DLSubmitPermission_vals[] = {
  {   0, "individual" },
  {   1, "member-of-dl" },
  {   2, "pattern-match" },
  {   3, "member-of-group" },
  { 0, NULL }
};

static const ber_choice_t DLSubmitPermission_choice[] = {
  {   0, &hf_acp133_individual   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_p1_ORName },
  {   1, &hf_acp133_member_of_dl , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_p1_ORName },
  {   2, &hf_acp133_pattern_match, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_acp133_ORNamePattern },
  {   3, &hf_acp133_member_of_group, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_x509if_Name },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_acp133_DLSubmitPermission(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 DLSubmitPermission_choice, hf_index, ett_acp133_DLSubmitPermission,
                                 NULL);

  return offset;
}


static const value_string acp133_T_report_propagation_vals[] = {
  {   0, "previous-dl-or-originator" },
  {   1, "dl-owner" },
  {   2, "both-previous-and-owner" },
  { 0, NULL }
};


static int
dissect_acp133_T_report_propagation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string acp133_T_report_from_dl_vals[] = {
  {   0, "whenever-requested" },
  {   1, "when-no-propagation" },
  { 0, NULL }
};


static int
dissect_acp133_T_report_from_dl(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string acp133_T_originating_MTA_report_vals[] = {
  {   0, "unchanged" },
  {   2, "report" },
  {   3, "non-delivery-report" },
  {   4, "audited-report" },
  { 0, NULL }
};


static int
dissect_acp133_T_originating_MTA_report(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string acp133_T_originator_report_vals[] = {
  {   0, "unchanged" },
  {   1, "no-report" },
  {   2, "report" },
  {   3, "non-delivery-report" },
  { 0, NULL }
};


static int
dissect_acp133_T_originator_report(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string acp133_T_return_of_content_vals[] = {
  {   0, "unchanged" },
  {   1, "content-return-not-requested" },
  {   2, "content-return-requested" },
  { 0, NULL }
};


static int
dissect_acp133_T_return_of_content(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string acp133_T_priority_vals[] = {
  {   0, "unchanged" },
  {   1, "normal" },
  {   2, "non-urgent" },
  {   3, "urgent" },
  { 0, NULL }
};


static int
dissect_acp133_T_priority(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string acp133_T_disclosure_of_other_recipients_vals[] = {
  {   0, "unchanged" },
  {   1, "disclosure-of-other-recipients-prohibited" },
  {   2, "disclosure-of-other-recipients-allowed" },
  { 0, NULL }
};


static int
dissect_acp133_T_disclosure_of_other_recipients(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string acp133_T_implicit_conversion_prohibited_vals[] = {
  {   0, "unchanged" },
  {   1, "implicit-conversion-allowed" },
  {   2, "implicit-conversion-prohibited" },
  { 0, NULL }
};


static int
dissect_acp133_T_implicit_conversion_prohibited(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string acp133_T_conversion_with_loss_prohibited_vals[] = {
  {   0, "unchanged" },
  {   1, "conversion-with-loss-allowed" },
  {   2, "conversion-with-loss-prohibited" },
  { 0, NULL }
};


static int
dissect_acp133_T_conversion_with_loss_prohibited(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string acp133_T_proof_of_delivery_vals[] = {
  {   0, "dl-expansion-point" },
  {   1, "dl-members" },
  {   2, "both" },
  {   3, "neither" },
  { 0, NULL }
};


static int
dissect_acp133_T_proof_of_delivery(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string acp133_T_requested_delivery_method_vals[] = {
  {   0, "unchanged" },
  {   1, "removed" },
  {   2, "replaced" },
  { 0, NULL }
};

static const ber_choice_t T_requested_delivery_method_choice[] = {
  {   0, &hf_acp133_unchanged    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_acp133_NULL },
  {   1, &hf_acp133_removed      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_acp133_NULL },
  {   2, &hf_acp133_replaced     , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_p1_RequestedDeliveryMethod },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_acp133_T_requested_delivery_method(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_requested_delivery_method_choice, hf_index, ett_acp133_T_requested_delivery_method,
                                 NULL);

  return offset;
}


static const ber_sequence_t AlgorithmInformation_sequence[] = {
  { &hf_acp133_algorithm_identifier, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_acp133_originator_certificate_selector, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_CertificateAssertion },
  { &hf_acp133_recipient_certificate_selector, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_CertificateAssertion },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_acp133_AlgorithmInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AlgorithmInformation_sequence, hf_index, ett_acp133_AlgorithmInformation);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_AlgorithmInformation_sequence_of[1] = {
  { &hf_acp133_token_encryption_algorithm_preference_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_acp133_AlgorithmInformation },
};

static int
dissect_acp133_SEQUENCE_OF_AlgorithmInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_AlgorithmInformation_sequence_of, hf_index, ett_acp133_SEQUENCE_OF_AlgorithmInformation);

  return offset;
}


static const ber_sequence_t DLPolicy_set[] = {
  { &hf_acp133_report_propagation, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acp133_T_report_propagation },
  { &hf_acp133_report_from_dl, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acp133_T_report_from_dl },
  { &hf_acp133_originating_MTA_report, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acp133_T_originating_MTA_report },
  { &hf_acp133_originator_report, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acp133_T_originator_report },
  { &hf_acp133_return_of_content, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acp133_T_return_of_content },
  { &hf_acp133_priority     , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acp133_T_priority },
  { &hf_acp133_disclosure_of_other_recipients, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acp133_T_disclosure_of_other_recipients },
  { &hf_acp133_implicit_conversion_prohibited, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acp133_T_implicit_conversion_prohibited },
  { &hf_acp133_conversion_with_loss_prohibited, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acp133_T_conversion_with_loss_prohibited },
  { &hf_acp133_further_dl_expansion_allowed, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acp133_BOOLEAN },
  { &hf_acp133_originator_requested_alternate_recipient_removed, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acp133_BOOLEAN },
  { &hf_acp133_proof_of_delivery, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acp133_T_proof_of_delivery },
  { &hf_acp133_requested_delivery_method, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acp133_T_requested_delivery_method },
  { &hf_acp133_token_encryption_algorithm_preference, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acp133_SEQUENCE_OF_AlgorithmInformation },
  { &hf_acp133_token_signature_algorithm_preference, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acp133_SEQUENCE_OF_AlgorithmInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_acp133_DLPolicy(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              DLPolicy_set, hf_index, ett_acp133_DLPolicy);

  return offset;
}



static int
dissect_acp133_GeneralString(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GeneralString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t SET_OF_ExtendedContentType_set_of[1] = {
  { &hf_acp133_content_types_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_p1_ExtendedContentType },
};

static int
dissect_acp133_SET_OF_ExtendedContentType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_ExtendedContentType_set_of, hf_index, ett_acp133_SET_OF_ExtendedContentType);

  return offset;
}


static const ber_sequence_t Capability_set[] = {
  { &hf_acp133_content_types, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_acp133_SET_OF_ExtendedContentType },
  { &hf_acp133_maximum_content_length, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_ContentLength },
  { &hf_acp133_encoded_information_types_constraints, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_EncodedInformationTypesConstraints },
  { &hf_acp133_security_labels, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_p1_SecurityContext },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_acp133_Capability(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              Capability_set, hf_index, ett_acp133_Capability);

  return offset;
}


static const ber_sequence_t SET_OF_Capability_set_of[1] = {
  { &hf_acp133_capabilities_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_acp133_Capability },
};

static int
dissect_acp133_SET_OF_Capability(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_Capability_set_of, hf_index, ett_acp133_SET_OF_Capability);

  return offset;
}


static const ber_sequence_t AddressCapabilities_sequence[] = {
  { &hf_acp133_description  , BER_CLASS_UNI, BER_UNI_TAG_GeneralString, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_acp133_GeneralString },
  { &hf_acp133_address      , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_p1_ORAddress },
  { &hf_acp133_capabilities , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_acp133_SET_OF_Capability },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_acp133_AddressCapabilities(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AddressCapabilities_sequence, hf_index, ett_acp133_AddressCapabilities);

  return offset;
}

/*--- PDUs ---*/

static int dissect_ACPPreferredDelivery_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_acp133_ACPPreferredDelivery(false, tvb, offset, &asn1_ctx, tree, hf_acp133_ACPPreferredDelivery_PDU);
  return offset;
}
static int dissect_ALType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_acp133_ALType(false, tvb, offset, &asn1_ctx, tree, hf_acp133_ALType_PDU);
  return offset;
}
static int dissect_Community_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_acp133_Community(false, tvb, offset, &asn1_ctx, tree, hf_acp133_Community_PDU);
  return offset;
}
static int dissect_OnSupported_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_acp133_OnSupported(false, tvb, offset, &asn1_ctx, tree, hf_acp133_OnSupported_PDU);
  return offset;
}
static int dissect_ACPLegacyFormat_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_acp133_ACPLegacyFormat(false, tvb, offset, &asn1_ctx, tree, hf_acp133_ACPLegacyFormat_PDU);
  return offset;
}
static int dissect_ACPNoAttachments_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_acp133_ACPNoAttachments(false, tvb, offset, &asn1_ctx, tree, hf_acp133_ACPNoAttachments_PDU);
  return offset;
}
static int dissect_Active_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_acp133_Active(false, tvb, offset, &asn1_ctx, tree, hf_acp133_Active_PDU);
  return offset;
}
static int dissect_Addressees_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_acp133_Addressees(false, tvb, offset, &asn1_ctx, tree, hf_acp133_Addressees_PDU);
  return offset;
}
static int dissect_Classification_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_acp133_Classification(false, tvb, offset, &asn1_ctx, tree, hf_acp133_Classification_PDU);
  return offset;
}
static int dissect_DistributionCode_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_acp133_DistributionCode(false, tvb, offset, &asn1_ctx, tree, hf_acp133_DistributionCode_PDU);
  return offset;
}
static int dissect_EmConCapability_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_acp133_EmConCapability(false, tvb, offset, &asn1_ctx, tree, hf_acp133_EmConCapability_PDU);
  return offset;
}
static int dissect_EmConState_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_acp133_EmConState(false, tvb, offset, &asn1_ctx, tree, hf_acp133_EmConState_PDU);
  return offset;
}
static int dissect_JPEG_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_acp133_JPEG(false, tvb, offset, &asn1_ctx, tree, hf_acp133_JPEG_PDU);
  return offset;
}
static int dissect_MaxMessageSize_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_acp133_MaxMessageSize(false, tvb, offset, &asn1_ctx, tree, hf_acp133_MaxMessageSize_PDU);
  return offset;
}
static int dissect_MonthlyUKMs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_acp133_MonthlyUKMs(false, tvb, offset, &asn1_ctx, tree, hf_acp133_MonthlyUKMs_PDU);
  return offset;
}
static int dissect_MsgProtocolInfoCapability_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_acp133_MsgProtocolInfoCapability(false, tvb, offset, &asn1_ctx, tree, hf_acp133_MsgProtocolInfoCapability_PDU);
  return offset;
}
static int dissect_Remarks_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_acp133_Remarks(false, tvb, offset, &asn1_ctx, tree, hf_acp133_Remarks_PDU);
  return offset;
}
static int dissect_RIParameters_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_acp133_RIParameters(false, tvb, offset, &asn1_ctx, tree, hf_acp133_RIParameters_PDU);
  return offset;
}
static int dissect_WebAccessCapability_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_acp133_WebAccessCapability(false, tvb, offset, &asn1_ctx, tree, hf_acp133_WebAccessCapability_PDU);
  return offset;
}
static int dissect_Kmid_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_acp133_Kmid(false, tvb, offset, &asn1_ctx, tree, hf_acp133_Kmid_PDU);
  return offset;
}
static int dissect_MLReceiptPolicy_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_acp133_MLReceiptPolicy(false, tvb, offset, &asn1_ctx, tree, hf_acp133_MLReceiptPolicy_PDU);
  return offset;
}
static int dissect_DLSubmitPermission_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_acp133_DLSubmitPermission(false, tvb, offset, &asn1_ctx, tree, hf_acp133_DLSubmitPermission_PDU);
  return offset;
}
static int dissect_DLPolicy_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_acp133_DLPolicy(false, tvb, offset, &asn1_ctx, tree, hf_acp133_DLPolicy_PDU);
  return offset;
}
static int dissect_AddressCapabilities_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_acp133_AddressCapabilities(false, tvb, offset, &asn1_ctx, tree, hf_acp133_AddressCapabilities_PDU);
  return offset;
}
static int dissect_Capability_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_acp133_Capability(false, tvb, offset, &asn1_ctx, tree, hf_acp133_Capability_PDU);
  return offset;
}



/*--- proto_register_acp133 -------------------------------------------*/
void proto_register_acp133(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {
    { &hf_acp133_ACPPreferredDelivery_PDU,
      { "ACPPreferredDelivery", "acp133.ACPPreferredDelivery",
        FT_UINT32, BASE_DEC, VALS(acp133_ACPPreferredDelivery_vals), 0,
        NULL, HFILL }},
    { &hf_acp133_ALType_PDU,
      { "ALType", "acp133.ALType",
        FT_INT32, BASE_DEC, VALS(acp133_ALType_vals), 0,
        NULL, HFILL }},
    { &hf_acp133_Community_PDU,
      { "Community", "acp133.Community",
        FT_UINT32, BASE_DEC, VALS(acp133_Community_vals), 0,
        NULL, HFILL }},
    { &hf_acp133_OnSupported_PDU,
      { "OnSupported", "acp133.OnSupported",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acp133_ACPLegacyFormat_PDU,
      { "ACPLegacyFormat", "acp133.ACPLegacyFormat",
        FT_INT32, BASE_DEC, VALS(acp133_ACPLegacyFormat_vals), 0,
        NULL, HFILL }},
    { &hf_acp133_ACPNoAttachments_PDU,
      { "ACPNoAttachments", "acp133.ACPNoAttachments",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acp133_Active_PDU,
      { "Active", "acp133.Active",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acp133_Addressees_PDU,
      { "Addressees", "acp133.Addressees",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_acp133_Classification_PDU,
      { "Classification", "acp133.Classification",
        FT_UINT32, BASE_DEC, VALS(acp133_Classification_vals), 0,
        NULL, HFILL }},
    { &hf_acp133_DistributionCode_PDU,
      { "DistributionCode", "acp133.DistributionCode",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acp133_EmConCapability_PDU,
      { "EmConCapability", "acp133.EmConCapability",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acp133_EmConState_PDU,
      { "EmConState", "acp133.EmConState",
        FT_UINT32, BASE_DEC, VALS(acp133_EmConState_vals), 0,
        NULL, HFILL }},
    { &hf_acp133_JPEG_PDU,
      { "JPEG", "acp133.JPEG",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acp133_MaxMessageSize_PDU,
      { "MaxMessageSize", "acp133.MaxMessageSize",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_acp133_MonthlyUKMs_PDU,
      { "MonthlyUKMs", "acp133.MonthlyUKMs_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acp133_MsgProtocolInfoCapability_PDU,
      { "MsgProtocolInfoCapability", "acp133.MsgProtocolInfoCapability",
        FT_UINT32, BASE_DEC, VALS(acp133_MsgProtocolInfoCapability_vals), 0,
        NULL, HFILL }},
    { &hf_acp133_Remarks_PDU,
      { "Remarks", "acp133.Remarks",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_acp133_RIParameters_PDU,
      { "RIParameters", "acp133.RIParameters",
        FT_UINT32, BASE_DEC, VALS(acp133_RIParameters_vals), 0,
        NULL, HFILL }},
    { &hf_acp133_WebAccessCapability_PDU,
      { "WebAccessCapability", "acp133.WebAccessCapability",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acp133_Kmid_PDU,
      { "Kmid", "acp133.Kmid",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acp133_MLReceiptPolicy_PDU,
      { "MLReceiptPolicy", "acp133.MLReceiptPolicy",
        FT_UINT32, BASE_DEC, VALS(acp133_MLReceiptPolicy_vals), 0,
        NULL, HFILL }},
    { &hf_acp133_DLSubmitPermission_PDU,
      { "DLSubmitPermission", "acp133.DLSubmitPermission",
        FT_UINT32, BASE_DEC, VALS(acp133_DLSubmitPermission_vals), 0,
        NULL, HFILL }},
    { &hf_acp133_DLPolicy_PDU,
      { "DLPolicy", "acp133.DLPolicy_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acp133_AddressCapabilities_PDU,
      { "AddressCapabilities", "acp133.AddressCapabilities_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acp133_Capability_PDU,
      { "Capability", "acp133.Capability_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acp133_Addressees_item,
      { "Addressees item", "acp133.Addressees_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString_SIZE_1_55", HFILL }},
    { &hf_acp133_ukm_entries,
      { "ukm-entries", "acp133.ukm_entries",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_UKMEntry", HFILL }},
    { &hf_acp133_ukm_entries_item,
      { "UKMEntry", "acp133.UKMEntry_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acp133_algorithm_identifier,
      { "algorithm-identifier", "acp133.algorithm_identifier_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_acp133_encrypted,
      { "encrypted", "acp133.encrypted",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_acp133_Remarks_item,
      { "Remarks item", "acp133.Remarks_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString", HFILL }},
    { &hf_acp133_ri_parameters,
      { "ri-parameters", "acp133.ri_parameters",
        FT_UINT32, BASE_DEC, VALS(x509sat_DirectoryString_vals), 0,
        "DirectoryString", HFILL }},
    { &hf_acp133_ri_parameters_deprecated,
      { "ri-parameters-deprecated", "acp133.ri_parameters_deprecated_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RIParametersDeprecated", HFILL }},
    { &hf_acp133_rI,
      { "rI", "acp133.rI",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString", HFILL }},
    { &hf_acp133_rIType,
      { "rIType", "acp133.rIType",
        FT_UINT32, BASE_DEC, VALS(acp133_T_rIType_vals), 0,
        NULL, HFILL }},
    { &hf_acp133_minimize,
      { "minimize", "acp133.minimize",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_acp133_sHD,
      { "sHD", "acp133.sHD",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString", HFILL }},
    { &hf_acp133_classification,
      { "classification", "acp133.classification",
        FT_UINT32, BASE_DEC, VALS(acp133_Classification_vals), 0,
        NULL, HFILL }},
    { &hf_acp133_tag,
      { "tag", "acp133.tag_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PairwiseTag", HFILL }},
    { &hf_acp133_ukm,
      { "ukm", "acp133.ukm",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_acp133_kmid,
      { "kmid", "acp133.kmid",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acp133_edition,
      { "edition", "acp133.edition",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_acp133_date,
      { "date", "acp133.date",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTCTime", HFILL }},
    { &hf_acp133_none,
      { "none", "acp133.none_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acp133_insteadOf,
      { "insteadOf", "acp133.insteadOf",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_GeneralNames", HFILL }},
    { &hf_acp133_insteadOf_item,
      { "GeneralNames", "acp133.GeneralNames",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_acp133_inAdditionTo,
      { "inAdditionTo", "acp133.inAdditionTo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_GeneralNames", HFILL }},
    { &hf_acp133_inAdditionTo_item,
      { "GeneralNames", "acp133.GeneralNames",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_acp133_individual,
      { "individual", "acp133.individual_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ORName", HFILL }},
    { &hf_acp133_member_of_dl,
      { "member-of-dl", "acp133.member_of_dl_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ORName", HFILL }},
    { &hf_acp133_pattern_match,
      { "pattern-match", "acp133.pattern_match_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ORNamePattern", HFILL }},
    { &hf_acp133_member_of_group,
      { "member-of-group", "acp133.member_of_group",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "Name", HFILL }},
    { &hf_acp133_report_propagation,
      { "report-propagation", "acp133.report_propagation",
        FT_INT32, BASE_DEC, VALS(acp133_T_report_propagation_vals), 0,
        "T_report_propagation", HFILL }},
    { &hf_acp133_report_from_dl,
      { "report-from-dl", "acp133.report_from_dl",
        FT_INT32, BASE_DEC, VALS(acp133_T_report_from_dl_vals), 0,
        "T_report_from_dl", HFILL }},
    { &hf_acp133_originating_MTA_report,
      { "originating-MTA-report", "acp133.originating_MTA_report",
        FT_INT32, BASE_DEC, VALS(acp133_T_originating_MTA_report_vals), 0,
        NULL, HFILL }},
    { &hf_acp133_originator_report,
      { "originator-report", "acp133.originator_report",
        FT_INT32, BASE_DEC, VALS(acp133_T_originator_report_vals), 0,
        NULL, HFILL }},
    { &hf_acp133_return_of_content,
      { "return-of-content", "acp133.return_of_content",
        FT_UINT32, BASE_DEC, VALS(acp133_T_return_of_content_vals), 0,
        NULL, HFILL }},
    { &hf_acp133_priority,
      { "priority", "acp133.priority",
        FT_INT32, BASE_DEC, VALS(acp133_T_priority_vals), 0,
        NULL, HFILL }},
    { &hf_acp133_disclosure_of_other_recipients,
      { "disclosure-of-other-recipients", "acp133.disclosure_of_other_recipients",
        FT_UINT32, BASE_DEC, VALS(acp133_T_disclosure_of_other_recipients_vals), 0,
        NULL, HFILL }},
    { &hf_acp133_implicit_conversion_prohibited,
      { "implicit-conversion-prohibited", "acp133.implicit_conversion_prohibited",
        FT_UINT32, BASE_DEC, VALS(acp133_T_implicit_conversion_prohibited_vals), 0,
        "T_implicit_conversion_prohibited", HFILL }},
    { &hf_acp133_conversion_with_loss_prohibited,
      { "conversion-with-loss-prohibited", "acp133.conversion_with_loss_prohibited",
        FT_UINT32, BASE_DEC, VALS(acp133_T_conversion_with_loss_prohibited_vals), 0,
        NULL, HFILL }},
    { &hf_acp133_further_dl_expansion_allowed,
      { "further-dl-expansion-allowed", "acp133.further_dl_expansion_allowed",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_acp133_originator_requested_alternate_recipient_removed,
      { "originator-requested-alternate-recipient-removed", "acp133.originator_requested_alternate_recipient_removed",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_acp133_proof_of_delivery,
      { "proof-of-delivery", "acp133.proof_of_delivery",
        FT_INT32, BASE_DEC, VALS(acp133_T_proof_of_delivery_vals), 0,
        NULL, HFILL }},
    { &hf_acp133_requested_delivery_method,
      { "requested-delivery-method", "acp133.requested_delivery_method",
        FT_UINT32, BASE_DEC, VALS(acp133_T_requested_delivery_method_vals), 0,
        NULL, HFILL }},
    { &hf_acp133_unchanged,
      { "unchanged", "acp133.unchanged_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acp133_removed,
      { "removed", "acp133.removed_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acp133_replaced,
      { "replaced", "acp133.replaced",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RequestedDeliveryMethod", HFILL }},
    { &hf_acp133_token_encryption_algorithm_preference,
      { "token-encryption-algorithm-preference", "acp133.token_encryption_algorithm_preference",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_AlgorithmInformation", HFILL }},
    { &hf_acp133_token_encryption_algorithm_preference_item,
      { "AlgorithmInformation", "acp133.AlgorithmInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acp133_token_signature_algorithm_preference,
      { "token-signature-algorithm-preference", "acp133.token_signature_algorithm_preference",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_AlgorithmInformation", HFILL }},
    { &hf_acp133_token_signature_algorithm_preference_item,
      { "AlgorithmInformation", "acp133.AlgorithmInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acp133_originator_certificate_selector,
      { "originator-certificate-selector", "acp133.originator_certificate_selector_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertificateAssertion", HFILL }},
    { &hf_acp133_recipient_certificate_selector,
      { "recipient-certificate-selector", "acp133.recipient_certificate_selector_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertificateAssertion", HFILL }},
    { &hf_acp133_description,
      { "description", "acp133.description",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralString", HFILL }},
    { &hf_acp133_address,
      { "address", "acp133.address_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ORAddress", HFILL }},
    { &hf_acp133_capabilities,
      { "capabilities", "acp133.capabilities",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_Capability", HFILL }},
    { &hf_acp133_capabilities_item,
      { "Capability", "acp133.Capability_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acp133_content_types,
      { "content-types", "acp133.content_types",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_ExtendedContentType", HFILL }},
    { &hf_acp133_content_types_item,
      { "ExtendedContentType", "acp133.ExtendedContentType",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acp133_maximum_content_length,
      { "maximum-content-length", "acp133.maximum_content_length",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ContentLength", HFILL }},
    { &hf_acp133_encoded_information_types_constraints,
      { "encoded-information-types-constraints", "acp133.encoded_information_types_constraints_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EncodedInformationTypesConstraints", HFILL }},
    { &hf_acp133_security_labels,
      { "security-labels", "acp133.security_labels",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SecurityContext", HFILL }},
    { &hf_acp133_OnSupported_acp127_nn,
      { "acp127-nn", "acp133.OnSupported.acp127.nn",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_acp133_OnSupported_acp127_pn,
      { "acp127-pn", "acp133.OnSupported.acp127.pn",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_acp133_OnSupported_acp127_tn,
      { "acp127-tn", "acp133.OnSupported.acp127.tn",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_acp133,
    &ett_acp133_OnSupported,
    &ett_acp133_Addressees,
    &ett_acp133_MonthlyUKMs,
    &ett_acp133_SEQUENCE_OF_UKMEntry,
    &ett_acp133_Remarks,
    &ett_acp133_RIParameters,
    &ett_acp133_RIParametersDeprecated,
    &ett_acp133_UKMEntry,
    &ett_acp133_PairwiseTag,
    &ett_acp133_MLReceiptPolicy,
    &ett_acp133_SEQUENCE_OF_GeneralNames,
    &ett_acp133_DLSubmitPermission,
    &ett_acp133_DLPolicy,
    &ett_acp133_T_requested_delivery_method,
    &ett_acp133_SEQUENCE_OF_AlgorithmInformation,
    &ett_acp133_AlgorithmInformation,
    &ett_acp133_AddressCapabilities,
    &ett_acp133_SET_OF_Capability,
    &ett_acp133_Capability,
    &ett_acp133_SET_OF_ExtendedContentType,
  };

  /* Register protocol */
  proto_acp133 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_acp133, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_acp133 --- */
void proto_reg_handoff_acp133(void) {

  register_ber_oid_dissector("2.6.5.2.4", dissect_DLSubmitPermission_PDU, proto_acp133, "id-at-mhs-dl-submit-permissions");
  register_ber_oid_dissector("2.6.5.2.13", dissect_DLPolicy_PDU, proto_acp133, "id-at-mhs-dl-policy");
  register_ber_oid_dissector("2.6.5.2.16", dissect_AddressCapabilities_PDU, proto_acp133, "id-at-mhs-or-addresses-with-capabilities");
  register_ber_oid_dissector("2.6.5.2.19", dissect_Capability_PDU, proto_acp133, "id-at-mhs-deliverable-classes");
  register_ber_oid_dissector("2.16.840.1.101.2.1.5.14", dissect_Kmid_PDU, proto_acp133, "id-at-alid");
  register_ber_oid_dissector("2.16.840.1.101.2.1.5.20", dissect_MonthlyUKMs_PDU, proto_acp133, "id-at-janUKMs");
  register_ber_oid_dissector("2.16.840.1.101.2.1.5.21", dissect_MonthlyUKMs_PDU, proto_acp133, "id-at-febUKMs");
  register_ber_oid_dissector("2.16.840.1.101.2.1.5.22", dissect_MonthlyUKMs_PDU, proto_acp133, "id-at-marUKMs");
  register_ber_oid_dissector("2.16.840.1.101.2.1.5.23", dissect_MonthlyUKMs_PDU, proto_acp133, "id-at-aprUKMs");
  register_ber_oid_dissector("2.16.840.1.101.2.1.5.24", dissect_MonthlyUKMs_PDU, proto_acp133, "id-at-mayUKMs");
  register_ber_oid_dissector("2.16.840.1.101.2.1.5.25", dissect_MonthlyUKMs_PDU, proto_acp133, "id-at-junUKMs");
  register_ber_oid_dissector("2.16.840.1.101.2.1.5.26", dissect_MonthlyUKMs_PDU, proto_acp133, "id-at-julUKMs");
  register_ber_oid_dissector("2.16.840.1.101.2.1.5.27", dissect_MonthlyUKMs_PDU, proto_acp133, "id-at-augUKMs");
  register_ber_oid_dissector("2.16.840.1.101.2.1.5.28", dissect_MonthlyUKMs_PDU, proto_acp133, "id-at-sepUKMs");
  register_ber_oid_dissector("2.16.840.1.101.2.1.5.29", dissect_MonthlyUKMs_PDU, proto_acp133, "id-at-octUKMs");
  register_ber_oid_dissector("2.16.840.1.101.2.1.5.30", dissect_MonthlyUKMs_PDU, proto_acp133, "id-at-novUKMs");
  register_ber_oid_dissector("2.16.840.1.101.2.1.5.31", dissect_MonthlyUKMs_PDU, proto_acp133, "id-at-decUKMs");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.46", dissect_Addressees_PDU, proto_acp133, "id-at-actionAddressees");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.47", dissect_Addressees_PDU, proto_acp133, "id-at-additionalAddressees");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.48", dissect_Addressees_PDU, proto_acp133, "id-at-additionalSecondPartyAddressees");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.50", dissect_Addressees_PDU, proto_acp133, "id-at-allowableOriginators");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.52", dissect_Community_PDU, proto_acp133, "id-at-community");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.56", dissect_Classification_PDU, proto_acp133, "id-at-entryClassification");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.59", dissect_Addressees_PDU, proto_acp133, "id-at-infoAddressees");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.67", dissect_Classification_PDU, proto_acp133, "id-at-nameClassification");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.71", dissect_Addressees_PDU, proto_acp133, "id-at-plaAddressees");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.76", dissect_Remarks_PDU, proto_acp133, "id-at-remarks");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.78", dissect_Classification_PDU, proto_acp133, "id-at-rIClassification");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.79", dissect_RIParameters_PDU, proto_acp133, "id-at-rIInfo");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.80", dissect_Addressees_PDU, proto_acp133, "id-at-secondPartyAddressees");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.104", dissect_DistributionCode_PDU, proto_acp133, "id-at-distributionCodeAction");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.105", dissect_DistributionCode_PDU, proto_acp133, "id-at-distributionCodeInfo");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.108", dissect_ACPPreferredDelivery_PDU, proto_acp133, "id-at-aCPPreferredDelivery");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.112", dissect_ALType_PDU, proto_acp133, "id-at-aLType");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.123", dissect_OnSupported_PDU, proto_acp133, "id-at-onSupported");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.135", dissect_MLReceiptPolicy_PDU, proto_acp133, "id-at-aLReceiptPolicy");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.142", dissect_ACPLegacyFormat_PDU, proto_acp133, "id-at-aCPLegacyFormat");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.146", dissect_JPEG_PDU, proto_acp133, "id-at-aCPNetwAccessSchemaEdB");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.147", dissect_JPEG_PDU, proto_acp133, "id-at-aCPNetworkSchemaEdB");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.162", dissect_MaxMessageSize_PDU, proto_acp133, "id-at-maxMessageSize");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.163", dissect_MsgProtocolInfoCapability_PDU, proto_acp133, "id-at-msgProtocolInfoCapability");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.164", dissect_Active_PDU, proto_acp133, "id-at-active");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.165", dissect_EmConCapability_PDU, proto_acp133, "id-at-emConCapability");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.166", dissect_EmConState_PDU, proto_acp133, "id-at-emConState");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.167", dissect_WebAccessCapability_PDU, proto_acp133, "id-at-webAccessCapability");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.168", dissect_DistributionCode_PDU, proto_acp133, "id-at-distributionExemptAction");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.169", dissect_DistributionCode_PDU, proto_acp133, "id-at-distributionExemptInfo");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.170", dissect_DistributionCode_PDU, proto_acp133, "id-at-distributionKeywordAction");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.171", dissect_DistributionCode_PDU, proto_acp133, "id-at-distributionKeywordInfo");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.189", dissect_ACPNoAttachments_PDU, proto_acp133, "id-at-aCPNoAttachments");


  /* X.402 Object Classes */
  oid_add_from_string("id-oc-mhs-distribution-list","2.6.5.1.0");
  oid_add_from_string("id-oc-mhs-message-store","2.6.5.1.1");
  oid_add_from_string("id-oc-mhs-message-transfer-agent","2.6.5.1.2");
  oid_add_from_string("id-oc-mhs-user","2.6.5.1.3");

  /* SDN.701 Object Classes */
  oid_add_from_string("id-oc-secure-user","2.16.840.1.101.2.1.4.13");
  oid_add_from_string("id-oc-ukms","2.16.840.1.101.2.1.4.16");

  /* ACP133 Object Classes */
  oid_add_from_string("id-oc-plaData","2.16.840.1.101.2.2.3.26");
  oid_add_from_string("id-oc-cadACP127","2.16.840.1.101.2.2.3.28");
  oid_add_from_string("id-oc-mLA","2.16.840.1.101.2.2.3.31");
  oid_add_from_string("id-oc-orgACP127","2.16.840.1.101.2.2.3.34");
  oid_add_from_string("id-oc-plaCollectiveACP127","2.16.840.1.101.2.2.3.35");
  oid_add_from_string("id-oc-routingIndicator","2.16.840.1.101.2.2.3.37");
  oid_add_from_string("id-oc-sigintPLA","2.16.840.1.101.2.2.3.38");
  oid_add_from_string("id-oc-sIPLA","2.16.840.1.101.2.2.3.39");
  oid_add_from_string("id-oc-spotPLA","2.16.840.1.101.2.2.3.40");
  oid_add_from_string("id-oc-taskForceACP127","2.16.840.1.101.2.2.3.41");
  oid_add_from_string("id-oc-tenantACP127","2.16.840.1.101.2.2.3.42");
  oid_add_from_string("id-oc-plaACP127","2.16.840.1.101.2.2.3.47");
  oid_add_from_string("id-oc-aliasCommonName","2.16.840.1.101.2.2.3.52");
  oid_add_from_string("id-oc-aliasOrganizationalUnit","2.16.840.1.101.2.2.3.53");
  oid_add_from_string("id-oc-distributionCodesHandled","2.16.840.1.101.2.2.3.54");
  oid_add_from_string("id-oc-distributionCodeDescription","2.16.840.1.101.2.2.3.55");
  oid_add_from_string("id-oc-plaUser","2.16.840.1.101.2.2.3.56");
  oid_add_from_string("id-oc-addressList","2.16.840.1.101.2.2.3.57");
  oid_add_from_string("id-oc-altSpellingACP127","2.16.840.1.101.2.2.3.58");
  oid_add_from_string("id-oc-messagingGateway","2.16.840.1.101.2.2.3.59");
  oid_add_from_string("id-oc-network","2.16.840.1.101.2.2.3.60");
  oid_add_from_string("id-oc-networkInstructions","2.16.840.1.101.2.2.3.61");
  oid_add_from_string("id-oc-otherContactInformation","2.16.840.1.101.2.2.3.62");
  oid_add_from_string("id-oc-releaseAuthorityPerson","2.16.840.1.101.2.2.3.63");
  oid_add_from_string("id-oc-mLAgent","2.16.840.1.101.2.2.3.64");
  oid_add_from_string("id-oc-releaseAuthorityPersonA","2.16.840.1.101.2.2.3.65");
  oid_add_from_string("id-oc-securePkiUser","2.16.840.1.101.2.2.3.66");
  oid_add_from_string("id-oc-dSSCSPLA","2.16.840.1.101.2.2.3.67");
  oid_add_from_string("id-oc-aCPNetworkEdB","2.16.840.1.101.2.2.3.68");
  oid_add_from_string("id-oc-aCPNetworkInstructionsEdB","2.16.840.1.101.2.2.3.69");
  oid_add_from_string("id-oc-aCPAddressList","2.16.840.1.101.2.2.3.70");
  oid_add_from_string("id-oc-aCPAliasCommonName","2.16.840.1.101.2.2.3.71");
  oid_add_from_string("id-oc-aCPAliasOrganizationalUnit","2.16.840.1.101.2.2.3.72");
  oid_add_from_string("id-oc-aCPDevice","2.16.840.1.101.2.2.3.73");
  oid_add_from_string("id-oc-aCPDistributionCodeDescription","2.16.840.1.101.2.2.3.74");
  oid_add_from_string("id-oc-aCPGroupOfNames","2.16.840.1.101.2.2.3.75");
  oid_add_from_string("id-oc-aCPLocality","2.16.840.1.101.2.2.3.76");
  oid_add_from_string("id-oc-aCPOrganization","2.16.840.1.101.2.2.3.77");
  oid_add_from_string("id-oc-aCPOrganizationalPerson","2.16.840.1.101.2.2.3.78");
  oid_add_from_string("id-oc-aCPOrganizationalRole","2.16.840.1.101.2.2.3.79");
  oid_add_from_string("id-oc-aCPOrganizationalUnit","2.16.840.1.101.2.2.3.80");
  oid_add_from_string("id-oc-aCPDistributionCodesHandled","2.16.840.1.101.2.2.3.81");
  oid_add_from_string("id-oc-aCPMhsCapabilitiesInformation","2.16.840.1.101.2.2.3.82");
  oid_add_from_string("id-oc-aCPOtherContactInformation","2.16.840.1.101.2.2.3.83");
  oid_add_from_string("id-oc-aCPPlaUser","2.16.840.1.101.2.2.3.84");
  oid_add_from_string("id-oc-aCPCRLDistributionPoint","2.16.840.1.101.2.2.3.85");
  oid_add_from_string("id-oc-aCPSecurePKIUser","2.16.840.1.101.2.2.3.86");
  oid_add_from_string("id-oc-aCPAltSpellingACP127","2.16.840.1.101.2.2.3.87");
  oid_add_from_string("id-oc-aCPCadACP127","2.16.840.1.101.2.2.3.88");
  oid_add_from_string("id-oc-aCPDSSCSPLA","2.16.840.1.101.2.2.3.89");
  oid_add_from_string("id-oc-aCPOrgACP127","2.16.840.1.101.2.2.3.90");
  oid_add_from_string("id-oc-aCPPLACollectiveACP127","2.16.840.1.101.2.2.3.91");
  oid_add_from_string("id-oc-aCPRoutingIndicator","2.16.840.1.101.2.2.3.92");
  oid_add_from_string("id-oc-aCPSigIntPLA","2.16.840.1.101.2.2.3.93");
  oid_add_from_string("id-oc-aCPSIPLA","2.16.840.1.101.2.2.3.94");
  oid_add_from_string("id-oc-aCPSpotPLA","2.16.840.1.101.2.2.3.95");
  oid_add_from_string("id-oc-aCPTaskForceACP127","2.16.840.1.101.2.2.3.96");
  oid_add_from_string("id-oc-aCPTenantACP127","2.16.840.1.101.2.2.3.97");
  oid_add_from_string("id-oc-aCPPlaACP127","2.16.840.1.101.2.2.3.98");
  oid_add_from_string("id-oc-aCPPlaData","2.16.840.1.101.2.2.3.99");
  oid_add_from_string("id-oc-aCPEntryAdmin","2.16.840.1.101.2.2.3.102");
  oid_add_from_string("id-oc-aCPOrganizationalLocation","2.16.840.1.101.2.2.3.103");
  oid_add_from_string("id-oc-aCPEntryCharacteristics","2.16.840.1.101.2.2.3.104");
  oid_add_from_string("id-oc-aCPPrivilege","2.16.840.1.101.2.2.3.105");

  /* gateway types */
  oid_add_from_string("acp120-acp127","2.16.840.1.101.2.2.5.0");
  oid_add_from_string("acp120-janap128","2.16.840.1.101.2.2.5.1");
  oid_add_from_string("acp120-mhs","2.16.840.1.101.2.2.5.2");
  oid_add_from_string("acp120-mmhs","2.16.840.1.101.2.2.5.3");
  oid_add_from_string("acp120-rfc822","2.16.840.1.101.2.2.5.4");
  oid_add_from_string("boundaryMTA","2.16.840.1.101.2.2.5.5");
  oid_add_from_string("mmhs-mhs","2.16.840.1.101.2.2.5.6");
  oid_add_from_string("mmhs-rfc822","2.16.840.1.101.2.2.5.7");
  oid_add_from_string("mta-acp127","2.16.840.1.101.2.2.5.8");

}
