/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-acp133.c                                                            */
/* ../../tools/asn2wrs.py -b -p acp133 -c ./acp133.cnf -s ./packet-acp133-template -D . acp133.asn MHSDirectoryObjectsAndAttributes.asn */

/* Input file: packet-acp133-template.c */

#line 1 "../../asn1/acp133/packet-acp133-template.c"
/* packet-acp133.c
 * Routines for ACP133 specific syntaxes in X.500 packet dissection
 * Graeme Lunt 2005
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/asn1.h>
#include <epan/oids.h>

#include "packet-ber.h"

#include "packet-x509af.h"
#include "packet-x509if.h"
#include "packet-x509ce.h"
#include "packet-p1.h"

#include "packet-acp133.h"

#define PNAME  "ACP133 Attribute Syntaxes"
#define PSNAME "ACP133"
#define PFNAME "acp133"

/* Initialize the protocol and registered fields */
static int proto_acp133 = -1;



/*--- Included file: packet-acp133-hf.c ---*/
#line 1 "../../asn1/acp133/packet-acp133-hf.c"
static int hf_acp133_ACPPreferredDelivery_PDU = -1;  /* ACPPreferredDelivery */
static int hf_acp133_ALType_PDU = -1;             /* ALType */
static int hf_acp133_Community_PDU = -1;          /* Community */
static int hf_acp133_OnSupported_PDU = -1;        /* OnSupported */
static int hf_acp133_ACPLegacyFormat_PDU = -1;    /* ACPLegacyFormat */
static int hf_acp133_Addressees_PDU = -1;         /* Addressees */
static int hf_acp133_Classification_PDU = -1;     /* Classification */
static int hf_acp133_DistributionCode_PDU = -1;   /* DistributionCode */
static int hf_acp133_JPEG_PDU = -1;               /* JPEG */
static int hf_acp133_MonthlyUKMs_PDU = -1;        /* MonthlyUKMs */
static int hf_acp133_Remarks_PDU = -1;            /* Remarks */
static int hf_acp133_RIParameters_PDU = -1;       /* RIParameters */
static int hf_acp133_Kmid_PDU = -1;               /* Kmid */
static int hf_acp133_MLReceiptPolicy_PDU = -1;    /* MLReceiptPolicy */
static int hf_acp133_DLSubmitPermission_PDU = -1;  /* DLSubmitPermission */
static int hf_acp133_DLPolicy_PDU = -1;           /* DLPolicy */
static int hf_acp133_AddressCapabilities_PDU = -1;  /* AddressCapabilities */
static int hf_acp133_Capability_PDU = -1;         /* Capability */
static int hf_acp133_Addressees_item = -1;        /* PrintableString_SIZE_1_55 */
static int hf_acp133_ukm_entries = -1;            /* SEQUENCE_OF_UKMEntry */
static int hf_acp133_ukm_entries_item = -1;       /* UKMEntry */
static int hf_acp133_algorithm_identifier = -1;   /* AlgorithmIdentifier */
static int hf_acp133_encrypted = -1;              /* BIT_STRING */
static int hf_acp133_Remarks_item = -1;           /* PrintableString */
static int hf_acp133_rI = -1;                     /* PrintableString */
static int hf_acp133_rIType = -1;                 /* T_rIType */
static int hf_acp133_minimize = -1;               /* BOOLEAN */
static int hf_acp133_sHD = -1;                    /* PrintableString */
static int hf_acp133_classification = -1;         /* Classification */
static int hf_acp133_tag = -1;                    /* PairwiseTag */
static int hf_acp133_ukm = -1;                    /* OCTET_STRING */
static int hf_acp133_kmid = -1;                   /* Kmid */
static int hf_acp133_edition = -1;                /* INTEGER */
static int hf_acp133_date = -1;                   /* UTCTime */
static int hf_acp133_none = -1;                   /* NULL */
static int hf_acp133_insteadOf = -1;              /* SEQUENCE_OF_GeneralNames */
static int hf_acp133_insteadOf_item = -1;         /* GeneralNames */
static int hf_acp133_inAdditionTo = -1;           /* SEQUENCE_OF_GeneralNames */
static int hf_acp133_inAdditionTo_item = -1;      /* GeneralNames */
static int hf_acp133_individual = -1;             /* ORName */
static int hf_acp133_member_of_dl = -1;           /* ORName */
static int hf_acp133_pattern_match = -1;          /* ORNamePattern */
static int hf_acp133_member_of_group = -1;        /* Name */
static int hf_acp133_report_propagation = -1;     /* T_report_propagation */
static int hf_acp133_report_from_dl = -1;         /* T_report_from_dl */
static int hf_acp133_originating_MTA_report = -1;  /* T_originating_MTA_report */
static int hf_acp133_originator_report = -1;      /* T_originator_report */
static int hf_acp133_return_of_content = -1;      /* T_return_of_content */
static int hf_acp133_priority = -1;               /* T_priority */
static int hf_acp133_disclosure_of_other_recipients = -1;  /* T_disclosure_of_other_recipients */
static int hf_acp133_implicit_conversion_prohibited = -1;  /* T_implicit_conversion_prohibited */
static int hf_acp133_conversion_with_loss_prohibited = -1;  /* T_conversion_with_loss_prohibited */
static int hf_acp133_further_dl_expansion_allowed = -1;  /* BOOLEAN */
static int hf_acp133_originator_requested_alternate_recipient_removed = -1;  /* BOOLEAN */
static int hf_acp133_proof_of_delivery = -1;      /* T_proof_of_delivery */
static int hf_acp133_requested_delivery_method = -1;  /* T_requested_delivery_method */
static int hf_acp133_unchanged = -1;              /* NULL */
static int hf_acp133_removed = -1;                /* NULL */
static int hf_acp133_replaced = -1;               /* RequestedDeliveryMethod */
static int hf_acp133_token_encryption_algorithm_preference = -1;  /* SEQUENCE_OF_AlgorithmInformation */
static int hf_acp133_token_encryption_algorithm_preference_item = -1;  /* AlgorithmInformation */
static int hf_acp133_token_signature_algorithm_preference = -1;  /* SEQUENCE_OF_AlgorithmInformation */
static int hf_acp133_token_signature_algorithm_preference_item = -1;  /* AlgorithmInformation */
static int hf_acp133_originator_certificate_selector = -1;  /* CertificateAssertion */
static int hf_acp133_recipient_certificate_selector = -1;  /* CertificateAssertion */
static int hf_acp133_description = -1;            /* GeneralString */
static int hf_acp133_address = -1;                /* ORAddress */
static int hf_acp133_capabilities = -1;           /* SET_OF_Capability */
static int hf_acp133_capabilities_item = -1;      /* Capability */
static int hf_acp133_content_types = -1;          /* SET_OF_ExtendedContentType */
static int hf_acp133_content_types_item = -1;     /* ExtendedContentType */
static int hf_acp133_maximum_content_length = -1;  /* ContentLength */
static int hf_acp133_encoded_information_types_constraints = -1;  /* EncodedInformationTypesConstraints */
static int hf_acp133_security_labels = -1;        /* SecurityContext */
/* named bits */
static int hf_acp133_OnSupported_acp127_nn = -1;
static int hf_acp133_OnSupported_acp127_pn = -1;
static int hf_acp133_OnSupported_acp127_tn = -1;

/*--- End of included file: packet-acp133-hf.c ---*/
#line 53 "../../asn1/acp133/packet-acp133-template.c"

/* Initialize the subtree pointers */
static gint ett_acp133 = -1;

/*--- Included file: packet-acp133-ett.c ---*/
#line 1 "../../asn1/acp133/packet-acp133-ett.c"
static gint ett_acp133_OnSupported = -1;
static gint ett_acp133_Addressees = -1;
static gint ett_acp133_MonthlyUKMs = -1;
static gint ett_acp133_SEQUENCE_OF_UKMEntry = -1;
static gint ett_acp133_Remarks = -1;
static gint ett_acp133_RIParameters = -1;
static gint ett_acp133_UKMEntry = -1;
static gint ett_acp133_PairwiseTag = -1;
static gint ett_acp133_MLReceiptPolicy = -1;
static gint ett_acp133_SEQUENCE_OF_GeneralNames = -1;
static gint ett_acp133_DLSubmitPermission = -1;
static gint ett_acp133_DLPolicy = -1;
static gint ett_acp133_T_requested_delivery_method = -1;
static gint ett_acp133_SEQUENCE_OF_AlgorithmInformation = -1;
static gint ett_acp133_AlgorithmInformation = -1;
static gint ett_acp133_AddressCapabilities = -1;
static gint ett_acp133_SET_OF_Capability = -1;
static gint ett_acp133_Capability = -1;
static gint ett_acp133_SET_OF_ExtendedContentType = -1;

/*--- End of included file: packet-acp133-ett.c ---*/
#line 57 "../../asn1/acp133/packet-acp133-template.c"


/*--- Included file: packet-acp133-fn.c ---*/
#line 1 "../../asn1/acp133/packet-acp133-fn.c"

static const value_string acp133_ACPPreferredDelivery_vals[] = {
  {   0, "smtp" },
  {   1, "acp127" },
  {   2, "mhs" },
  { 0, NULL }
};


static int
dissect_acp133_ACPPreferredDelivery(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_acp133_ALType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_acp133_Community(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const asn_namedbit OnSupported_bits[] = {
  {  0, &hf_acp133_OnSupported_acp127_nn, -1, -1, "acp127-nn", NULL },
  {  1, &hf_acp133_OnSupported_acp127_pn, -1, -1, "acp127-pn", NULL },
  {  2, &hf_acp133_OnSupported_acp127_tn, -1, -1, "acp127-tn", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_acp133_OnSupported(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    OnSupported_bits, hf_index, ett_acp133_OnSupported,
                                    NULL);

  return offset;
}


static const value_string acp133_ACPLegacyFormat_vals[] = {
  {   0, "janap128" },
  {   1, "acp126" },
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
  { 0, NULL }
};


static int
dissect_acp133_ACPLegacyFormat(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_acp133_PrintableString_SIZE_1_55(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t Addressees_sequence_of[1] = {
  { &hf_acp133_Addressees_item, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_acp133_PrintableString_SIZE_1_55 },
};

static int
dissect_acp133_Addressees(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_acp133_Classification(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_acp133_DistributionCode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_acp133_JPEG(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_acp133_Kmid(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_acp133_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_acp133_UTCTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_UTCTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t PairwiseTag_sequence[] = {
  { &hf_acp133_kmid         , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_acp133_Kmid },
  { &hf_acp133_edition      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_acp133_INTEGER },
  { &hf_acp133_date         , BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_acp133_UTCTime },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_acp133_PairwiseTag(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PairwiseTag_sequence, hf_index, ett_acp133_PairwiseTag);

  return offset;
}



static int
dissect_acp133_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_acp133_UKMEntry(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UKMEntry_sequence, hf_index, ett_acp133_UKMEntry);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_UKMEntry_sequence_of[1] = {
  { &hf_acp133_ukm_entries_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_acp133_UKMEntry },
};

static int
dissect_acp133_SEQUENCE_OF_UKMEntry(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_UKMEntry_sequence_of, hf_index, ett_acp133_SEQUENCE_OF_UKMEntry);

  return offset;
}



static int
dissect_acp133_BIT_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
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
dissect_acp133_MonthlyUKMs(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MonthlyUKMs_sequence, hf_index, ett_acp133_MonthlyUKMs);

  return offset;
}



static int
dissect_acp133_PrintableString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t Remarks_sequence_of[1] = {
  { &hf_acp133_Remarks_item , BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_acp133_PrintableString },
};

static int
dissect_acp133_Remarks(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_acp133_T_rIType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_acp133_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t RIParameters_set[] = {
  { &hf_acp133_rI           , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_acp133_PrintableString },
  { &hf_acp133_rIType       , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_acp133_T_rIType },
  { &hf_acp133_minimize     , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_acp133_BOOLEAN },
  { &hf_acp133_sHD          , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_acp133_PrintableString },
  { &hf_acp133_classification, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_acp133_Classification },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_acp133_RIParameters(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              RIParameters_set, hf_index, ett_acp133_RIParameters);

  return offset;
}



static int
dissect_acp133_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_GeneralNames_sequence_of[1] = {
  { &hf_acp133_insteadOf_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509ce_GeneralNames },
};

static int
dissect_acp133_SEQUENCE_OF_GeneralNames(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_acp133_MLReceiptPolicy(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 MLReceiptPolicy_choice, hf_index, ett_acp133_MLReceiptPolicy,
                                 NULL);

  return offset;
}



static int
dissect_acp133_ORNamePattern(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_acp133_DLSubmitPermission(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_acp133_T_report_propagation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_acp133_T_report_from_dl(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_acp133_T_originating_MTA_report(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_acp133_T_originator_report(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_acp133_T_return_of_content(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_acp133_T_priority(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_acp133_T_disclosure_of_other_recipients(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_acp133_T_implicit_conversion_prohibited(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_acp133_T_conversion_with_loss_prohibited(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_acp133_T_proof_of_delivery(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_acp133_T_requested_delivery_method(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_acp133_AlgorithmInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AlgorithmInformation_sequence, hf_index, ett_acp133_AlgorithmInformation);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_AlgorithmInformation_sequence_of[1] = {
  { &hf_acp133_token_encryption_algorithm_preference_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_acp133_AlgorithmInformation },
};

static int
dissect_acp133_SEQUENCE_OF_AlgorithmInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_acp133_DLPolicy(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              DLPolicy_set, hf_index, ett_acp133_DLPolicy);

  return offset;
}



static int
dissect_acp133_GeneralString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GeneralString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t SET_OF_ExtendedContentType_set_of[1] = {
  { &hf_acp133_content_types_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_p1_ExtendedContentType },
};

static int
dissect_acp133_SET_OF_ExtendedContentType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_acp133_Capability(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              Capability_set, hf_index, ett_acp133_Capability);

  return offset;
}


static const ber_sequence_t SET_OF_Capability_set_of[1] = {
  { &hf_acp133_capabilities_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_acp133_Capability },
};

static int
dissect_acp133_SET_OF_Capability(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_acp133_AddressCapabilities(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AddressCapabilities_sequence, hf_index, ett_acp133_AddressCapabilities);

  return offset;
}

/*--- PDUs ---*/

static void dissect_ACPPreferredDelivery_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_acp133_ACPPreferredDelivery(FALSE, tvb, 0, &asn1_ctx, tree, hf_acp133_ACPPreferredDelivery_PDU);
}
static void dissect_ALType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_acp133_ALType(FALSE, tvb, 0, &asn1_ctx, tree, hf_acp133_ALType_PDU);
}
static void dissect_Community_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_acp133_Community(FALSE, tvb, 0, &asn1_ctx, tree, hf_acp133_Community_PDU);
}
static void dissect_OnSupported_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_acp133_OnSupported(FALSE, tvb, 0, &asn1_ctx, tree, hf_acp133_OnSupported_PDU);
}
static void dissect_ACPLegacyFormat_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_acp133_ACPLegacyFormat(FALSE, tvb, 0, &asn1_ctx, tree, hf_acp133_ACPLegacyFormat_PDU);
}
static void dissect_Addressees_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_acp133_Addressees(FALSE, tvb, 0, &asn1_ctx, tree, hf_acp133_Addressees_PDU);
}
static void dissect_Classification_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_acp133_Classification(FALSE, tvb, 0, &asn1_ctx, tree, hf_acp133_Classification_PDU);
}
static void dissect_DistributionCode_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_acp133_DistributionCode(FALSE, tvb, 0, &asn1_ctx, tree, hf_acp133_DistributionCode_PDU);
}
static void dissect_JPEG_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_acp133_JPEG(FALSE, tvb, 0, &asn1_ctx, tree, hf_acp133_JPEG_PDU);
}
static void dissect_MonthlyUKMs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_acp133_MonthlyUKMs(FALSE, tvb, 0, &asn1_ctx, tree, hf_acp133_MonthlyUKMs_PDU);
}
static void dissect_Remarks_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_acp133_Remarks(FALSE, tvb, 0, &asn1_ctx, tree, hf_acp133_Remarks_PDU);
}
static void dissect_RIParameters_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_acp133_RIParameters(FALSE, tvb, 0, &asn1_ctx, tree, hf_acp133_RIParameters_PDU);
}
static void dissect_Kmid_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_acp133_Kmid(FALSE, tvb, 0, &asn1_ctx, tree, hf_acp133_Kmid_PDU);
}
static void dissect_MLReceiptPolicy_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_acp133_MLReceiptPolicy(FALSE, tvb, 0, &asn1_ctx, tree, hf_acp133_MLReceiptPolicy_PDU);
}
static void dissect_DLSubmitPermission_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_acp133_DLSubmitPermission(FALSE, tvb, 0, &asn1_ctx, tree, hf_acp133_DLSubmitPermission_PDU);
}
static void dissect_DLPolicy_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_acp133_DLPolicy(FALSE, tvb, 0, &asn1_ctx, tree, hf_acp133_DLPolicy_PDU);
}
static void dissect_AddressCapabilities_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_acp133_AddressCapabilities(FALSE, tvb, 0, &asn1_ctx, tree, hf_acp133_AddressCapabilities_PDU);
}
static void dissect_Capability_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_acp133_Capability(FALSE, tvb, 0, &asn1_ctx, tree, hf_acp133_Capability_PDU);
}


/*--- End of included file: packet-acp133-fn.c ---*/
#line 59 "../../asn1/acp133/packet-acp133-template.c"


/*--- proto_register_acp133 -------------------------------------------*/
void proto_register_acp133(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {

/*--- Included file: packet-acp133-hfarr.c ---*/
#line 1 "../../asn1/acp133/packet-acp133-hfarr.c"
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
    { &hf_acp133_JPEG_PDU,
      { "JPEG", "acp133.JPEG",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acp133_MonthlyUKMs_PDU,
      { "MonthlyUKMs", "acp133.MonthlyUKMs",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acp133_Remarks_PDU,
      { "Remarks", "acp133.Remarks",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_acp133_RIParameters_PDU,
      { "RIParameters", "acp133.RIParameters",
        FT_NONE, BASE_NONE, NULL, 0,
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
      { "DLPolicy", "acp133.DLPolicy",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acp133_AddressCapabilities_PDU,
      { "AddressCapabilities", "acp133.AddressCapabilities",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acp133_Capability_PDU,
      { "Capability", "acp133.Capability",
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
      { "UKMEntry", "acp133.UKMEntry",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acp133_algorithm_identifier,
      { "algorithm-identifier", "acp133.algorithm_identifier",
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
      { "tag", "acp133.tag",
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
      { "none", "acp133.none",
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
      { "individual", "acp133.individual",
        FT_NONE, BASE_NONE, NULL, 0,
        "ORName", HFILL }},
    { &hf_acp133_member_of_dl,
      { "member-of-dl", "acp133.member_of_dl",
        FT_NONE, BASE_NONE, NULL, 0,
        "ORName", HFILL }},
    { &hf_acp133_pattern_match,
      { "pattern-match", "acp133.pattern_match",
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
      { "unchanged", "acp133.unchanged",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acp133_removed,
      { "removed", "acp133.removed",
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
      { "AlgorithmInformation", "acp133.AlgorithmInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acp133_token_signature_algorithm_preference,
      { "token-signature-algorithm-preference", "acp133.token_signature_algorithm_preference",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_AlgorithmInformation", HFILL }},
    { &hf_acp133_token_signature_algorithm_preference_item,
      { "AlgorithmInformation", "acp133.AlgorithmInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_acp133_originator_certificate_selector,
      { "originator-certificate-selector", "acp133.originator_certificate_selector",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertificateAssertion", HFILL }},
    { &hf_acp133_recipient_certificate_selector,
      { "recipient-certificate-selector", "acp133.recipient_certificate_selector",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertificateAssertion", HFILL }},
    { &hf_acp133_description,
      { "description", "acp133.description",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralString", HFILL }},
    { &hf_acp133_address,
      { "address", "acp133.address",
        FT_NONE, BASE_NONE, NULL, 0,
        "ORAddress", HFILL }},
    { &hf_acp133_capabilities,
      { "capabilities", "acp133.capabilities",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_Capability", HFILL }},
    { &hf_acp133_capabilities_item,
      { "Capability", "acp133.Capability",
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
      { "encoded-information-types-constraints", "acp133.encoded_information_types_constraints",
        FT_NONE, BASE_NONE, NULL, 0,
        "EncodedInformationTypesConstraints", HFILL }},
    { &hf_acp133_security_labels,
      { "security-labels", "acp133.security_labels",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SecurityContext", HFILL }},
    { &hf_acp133_OnSupported_acp127_nn,
      { "acp127-nn", "acp133.acp127-nn",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_acp133_OnSupported_acp127_pn,
      { "acp127-pn", "acp133.acp127-pn",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_acp133_OnSupported_acp127_tn,
      { "acp127-tn", "acp133.acp127-tn",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},

/*--- End of included file: packet-acp133-hfarr.c ---*/
#line 68 "../../asn1/acp133/packet-acp133-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_acp133,

/*--- Included file: packet-acp133-ettarr.c ---*/
#line 1 "../../asn1/acp133/packet-acp133-ettarr.c"
    &ett_acp133_OnSupported,
    &ett_acp133_Addressees,
    &ett_acp133_MonthlyUKMs,
    &ett_acp133_SEQUENCE_OF_UKMEntry,
    &ett_acp133_Remarks,
    &ett_acp133_RIParameters,
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

/*--- End of included file: packet-acp133-ettarr.c ---*/
#line 74 "../../asn1/acp133/packet-acp133-template.c"
  };

  /* Register protocol */
  proto_acp133 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_acp133, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_acp133 --- */
void proto_reg_handoff_acp133(void) {


/*--- Included file: packet-acp133-dis-tab.c ---*/
#line 1 "../../asn1/acp133/packet-acp133-dis-tab.c"
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


/*--- End of included file: packet-acp133-dis-tab.c ---*/
#line 90 "../../asn1/acp133/packet-acp133-template.c"

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
