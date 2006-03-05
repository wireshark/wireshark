/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* .\packet-acp133.c                                                          */
/* ../../tools/asn2eth.py -X -b -e -p acp133 -c acp133.cnf -s packet-acp133-template acp133.asn */

/* Input file: packet-acp133-template.c */

#line 1 "packet-acp133-template.c"
/* packet-acp133.c
 * Routines for ACP133 specific syntaxes in X.500 packet dissection
 * Graeme Lunt 2005
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"

#include "packet-x509af.h"
#include "packet-x509if.h"
#include "packet-x509ce.h"
#include "packet-x411.h"

#include "packet-acp133.h"

#define PNAME  "ACP133 Attribute Syntaxes"
#define PSNAME "ACP133"
#define PFNAME "acp133"

/* Initialize the protocol and registered fields */
int proto_acp133 = -1;



/*--- Included file: packet-acp133-hf.c ---*/
#line 1 "packet-acp133-hf.c"
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
#line 55 "packet-acp133-template.c"

/* Initialize the subtree pointers */
static gint ett_acp133 = -1;

/*--- Included file: packet-acp133-ett.c ---*/
#line 1 "packet-acp133-ett.c"
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
#line 59 "packet-acp133-template.c"


/*--- Included file: packet-acp133-fn.c ---*/
#line 1 "packet-acp133-fn.c"
/*--- Fields for imported types ---*/

static int dissect_algorithm_identifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_AlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_acp133_algorithm_identifier);
}
static int dissect_insteadOf_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_GeneralNames(FALSE, tvb, offset, pinfo, tree, hf_acp133_insteadOf_item);
}
static int dissect_inAdditionTo_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_GeneralNames(FALSE, tvb, offset, pinfo, tree, hf_acp133_inAdditionTo_item);
}
static int dissect_individual(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ORName(FALSE, tvb, offset, pinfo, tree, hf_acp133_individual);
}
static int dissect_member_of_dl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ORName(FALSE, tvb, offset, pinfo, tree, hf_acp133_member_of_dl);
}
static int dissect_member_of_group(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Name(FALSE, tvb, offset, pinfo, tree, hf_acp133_member_of_group);
}
static int dissect_replaced(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_RequestedDeliveryMethod(FALSE, tvb, offset, pinfo, tree, hf_acp133_replaced);
}
static int dissect_originator_certificate_selector(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_CertificateAssertion(FALSE, tvb, offset, pinfo, tree, hf_acp133_originator_certificate_selector);
}
static int dissect_recipient_certificate_selector(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_CertificateAssertion(FALSE, tvb, offset, pinfo, tree, hf_acp133_recipient_certificate_selector);
}
static int dissect_address(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ORAddress(FALSE, tvb, offset, pinfo, tree, hf_acp133_address);
}
static int dissect_content_types_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ExtendedContentType(FALSE, tvb, offset, pinfo, tree, hf_acp133_content_types_item);
}
static int dissect_maximum_content_length(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_ContentLength(FALSE, tvb, offset, pinfo, tree, hf_acp133_maximum_content_length);
}
static int dissect_encoded_information_types_constraints(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_EncodedInformationTypesConstraints(FALSE, tvb, offset, pinfo, tree, hf_acp133_encoded_information_types_constraints);
}
static int dissect_security_labels(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x411_SecurityContext(FALSE, tvb, offset, pinfo, tree, hf_acp133_security_labels);
}


static const value_string acp133_ACPPreferredDelivery_vals[] = {
  {   0, "smtp" },
  {   1, "acp127" },
  {   2, "mhs" },
  { 0, NULL }
};


static int
dissect_acp133_ACPPreferredDelivery(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
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
dissect_acp133_ALType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
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
dissect_acp133_Community(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
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
dissect_acp133_OnSupported(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
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
dissect_acp133_ACPLegacyFormat(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_acp133_PrintableString_SIZE_1_55(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_Addressees_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_PrintableString_SIZE_1_55(FALSE, tvb, offset, pinfo, tree, hf_acp133_Addressees_item);
}


static const ber_sequence_t Addressees_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_Addressees_item },
};

static int
dissect_acp133_Addressees(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
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
dissect_acp133_Classification(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_classification(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_Classification(FALSE, tvb, offset, pinfo, tree, hf_acp133_classification);
}



static int
dissect_acp133_DistributionCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_acp133_JPEG(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_acp133_Kmid(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_kmid(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_Kmid(FALSE, tvb, offset, pinfo, tree, hf_acp133_kmid);
}



static int
dissect_acp133_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_edition(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_acp133_edition);
}



static int
dissect_acp133_UTCTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTCTime,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_date(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_UTCTime(FALSE, tvb, offset, pinfo, tree, hf_acp133_date);
}


static const ber_sequence_t PairwiseTag_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_kmid },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_edition },
  { BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_date },
  { 0, 0, 0, NULL }
};

static int
dissect_acp133_PairwiseTag(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PairwiseTag_sequence, hf_index, ett_acp133_PairwiseTag);

  return offset;
}
static int dissect_tag(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_PairwiseTag(FALSE, tvb, offset, pinfo, tree, hf_acp133_tag);
}



static int
dissect_acp133_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_ukm(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_acp133_ukm);
}


static const ber_sequence_t UKMEntry_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_tag },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ukm },
  { 0, 0, 0, NULL }
};

static int
dissect_acp133_UKMEntry(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   UKMEntry_sequence, hf_index, ett_acp133_UKMEntry);

  return offset;
}
static int dissect_ukm_entries_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_UKMEntry(FALSE, tvb, offset, pinfo, tree, hf_acp133_ukm_entries_item);
}


static const ber_sequence_t SEQUENCE_OF_UKMEntry_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ukm_entries_item },
};

static int
dissect_acp133_SEQUENCE_OF_UKMEntry(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_UKMEntry_sequence_of, hf_index, ett_acp133_SEQUENCE_OF_UKMEntry);

  return offset;
}
static int dissect_ukm_entries(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_SEQUENCE_OF_UKMEntry(FALSE, tvb, offset, pinfo, tree, hf_acp133_ukm_entries);
}



static int
dissect_acp133_BIT_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}
static int dissect_encrypted(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_BIT_STRING(FALSE, tvb, offset, pinfo, tree, hf_acp133_encrypted);
}


static const ber_sequence_t MonthlyUKMs_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ukm_entries },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithm_identifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encrypted },
  { 0, 0, 0, NULL }
};

static int
dissect_acp133_MonthlyUKMs(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   MonthlyUKMs_sequence, hf_index, ett_acp133_MonthlyUKMs);

  return offset;
}



static int
dissect_acp133_PrintableString(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_Remarks_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_PrintableString(FALSE, tvb, offset, pinfo, tree, hf_acp133_Remarks_item);
}
static int dissect_rI(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_PrintableString(FALSE, tvb, offset, pinfo, tree, hf_acp133_rI);
}
static int dissect_sHD(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_PrintableString(FALSE, tvb, offset, pinfo, tree, hf_acp133_sHD);
}


static const ber_sequence_t Remarks_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_Remarks_item },
};

static int
dissect_acp133_Remarks(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
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
dissect_acp133_T_rIType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_rIType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_T_rIType(FALSE, tvb, offset, pinfo, tree, hf_acp133_rIType);
}



static int
dissect_acp133_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_minimize(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_acp133_minimize);
}
static int dissect_further_dl_expansion_allowed(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_acp133_further_dl_expansion_allowed);
}
static int dissect_originator_requested_alternate_recipient_removed(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_acp133_originator_requested_alternate_recipient_removed);
}


static const ber_sequence_t RIParameters_set[] = {
  { BER_CLASS_CON, 0, 0, dissect_rI },
  { BER_CLASS_CON, 1, 0, dissect_rIType },
  { BER_CLASS_CON, 2, 0, dissect_minimize },
  { BER_CLASS_CON, 3, 0, dissect_sHD },
  { BER_CLASS_CON, 4, 0, dissect_classification },
  { 0, 0, 0, NULL }
};

static int
dissect_acp133_RIParameters(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              RIParameters_set, hf_index, ett_acp133_RIParameters);

  return offset;
}



static int
dissect_acp133_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_none(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_NULL(FALSE, tvb, offset, pinfo, tree, hf_acp133_none);
}
static int dissect_unchanged(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_NULL(FALSE, tvb, offset, pinfo, tree, hf_acp133_unchanged);
}
static int dissect_removed(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_NULL(FALSE, tvb, offset, pinfo, tree, hf_acp133_removed);
}


static const ber_sequence_t SEQUENCE_OF_GeneralNames_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_insteadOf_item },
};

static int
dissect_acp133_SEQUENCE_OF_GeneralNames(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_GeneralNames_sequence_of, hf_index, ett_acp133_SEQUENCE_OF_GeneralNames);

  return offset;
}
static int dissect_insteadOf(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_SEQUENCE_OF_GeneralNames(FALSE, tvb, offset, pinfo, tree, hf_acp133_insteadOf);
}
static int dissect_inAdditionTo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_SEQUENCE_OF_GeneralNames(FALSE, tvb, offset, pinfo, tree, hf_acp133_inAdditionTo);
}


static const value_string acp133_MLReceiptPolicy_vals[] = {
  {   0, "none" },
  {   1, "insteadOf" },
  {   2, "inAdditionTo" },
  { 0, NULL }
};

static const ber_choice_t MLReceiptPolicy_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_none },
  {   1, BER_CLASS_CON, 1, 0, dissect_insteadOf },
  {   2, BER_CLASS_CON, 2, 0, dissect_inAdditionTo },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_acp133_MLReceiptPolicy(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 MLReceiptPolicy_choice, hf_index, ett_acp133_MLReceiptPolicy,
                                 NULL);

  return offset;
}



static int
dissect_acp133_ORNamePattern(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x411_ORName(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_pattern_match(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_ORNamePattern(FALSE, tvb, offset, pinfo, tree, hf_acp133_pattern_match);
}


static const value_string acp133_DLSubmitPermission_vals[] = {
  {   0, "individual" },
  {   1, "member-of-dl" },
  {   2, "pattern-match" },
  {   3, "member-of-group" },
  { 0, NULL }
};

static const ber_choice_t DLSubmitPermission_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_individual },
  {   1, BER_CLASS_CON, 1, 0, dissect_member_of_dl },
  {   2, BER_CLASS_CON, 2, 0, dissect_pattern_match },
  {   3, BER_CLASS_CON, 3, 0, dissect_member_of_group },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_acp133_DLSubmitPermission(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
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
dissect_acp133_T_report_propagation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_report_propagation(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_T_report_propagation(FALSE, tvb, offset, pinfo, tree, hf_acp133_report_propagation);
}


static const value_string acp133_T_report_from_dl_vals[] = {
  {   0, "whenever-requested" },
  {   1, "when-no-propagation" },
  { 0, NULL }
};


static int
dissect_acp133_T_report_from_dl(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_report_from_dl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_T_report_from_dl(FALSE, tvb, offset, pinfo, tree, hf_acp133_report_from_dl);
}


static const value_string acp133_T_originating_MTA_report_vals[] = {
  {   0, "unchanged" },
  {   2, "report" },
  {   3, "non-delivery-report" },
  {   4, "audited-report" },
  { 0, NULL }
};


static int
dissect_acp133_T_originating_MTA_report(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_originating_MTA_report(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_T_originating_MTA_report(FALSE, tvb, offset, pinfo, tree, hf_acp133_originating_MTA_report);
}


static const value_string acp133_T_originator_report_vals[] = {
  {   0, "unchanged" },
  {   1, "no-report" },
  {   2, "report" },
  {   3, "non-delivery-report" },
  { 0, NULL }
};


static int
dissect_acp133_T_originator_report(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_originator_report(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_T_originator_report(FALSE, tvb, offset, pinfo, tree, hf_acp133_originator_report);
}


static const value_string acp133_T_return_of_content_vals[] = {
  {   0, "unchanged" },
  {   1, "content-return-not-requested" },
  {   2, "content-return-requested" },
  { 0, NULL }
};


static int
dissect_acp133_T_return_of_content(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_return_of_content(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_T_return_of_content(FALSE, tvb, offset, pinfo, tree, hf_acp133_return_of_content);
}


static const value_string acp133_T_priority_vals[] = {
  {   0, "unchanged" },
  {   1, "normal" },
  {   2, "non-urgent" },
  {   3, "urgent" },
  { 0, NULL }
};


static int
dissect_acp133_T_priority(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_priority(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_T_priority(FALSE, tvb, offset, pinfo, tree, hf_acp133_priority);
}


static const value_string acp133_T_disclosure_of_other_recipients_vals[] = {
  {   0, "unchanged" },
  {   1, "disclosure-of-other-recipients-prohibited" },
  {   2, "disclosure-of-other-recipients-allowed" },
  { 0, NULL }
};


static int
dissect_acp133_T_disclosure_of_other_recipients(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_disclosure_of_other_recipients(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_T_disclosure_of_other_recipients(FALSE, tvb, offset, pinfo, tree, hf_acp133_disclosure_of_other_recipients);
}


static const value_string acp133_T_implicit_conversion_prohibited_vals[] = {
  {   0, "unchanged" },
  {   1, "implicit-conversion-allowed" },
  {   2, "implicit-conversion-prohibited" },
  { 0, NULL }
};


static int
dissect_acp133_T_implicit_conversion_prohibited(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_implicit_conversion_prohibited(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_T_implicit_conversion_prohibited(FALSE, tvb, offset, pinfo, tree, hf_acp133_implicit_conversion_prohibited);
}


static const value_string acp133_T_conversion_with_loss_prohibited_vals[] = {
  {   0, "unchanged" },
  {   1, "conversion-with-loss-allowed" },
  {   2, "conversion-with-loss-prohibited" },
  { 0, NULL }
};


static int
dissect_acp133_T_conversion_with_loss_prohibited(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_conversion_with_loss_prohibited(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_T_conversion_with_loss_prohibited(FALSE, tvb, offset, pinfo, tree, hf_acp133_conversion_with_loss_prohibited);
}


static const value_string acp133_T_proof_of_delivery_vals[] = {
  {   0, "dl-expansion-point" },
  {   1, "dl-members" },
  {   2, "both" },
  {   3, "neither" },
  { 0, NULL }
};


static int
dissect_acp133_T_proof_of_delivery(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_proof_of_delivery(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_T_proof_of_delivery(FALSE, tvb, offset, pinfo, tree, hf_acp133_proof_of_delivery);
}


static const value_string acp133_T_requested_delivery_method_vals[] = {
  {   0, "unchanged" },
  {   1, "removed" },
  {   2, "replaced" },
  { 0, NULL }
};

static const ber_choice_t T_requested_delivery_method_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_unchanged },
  {   1, BER_CLASS_CON, 1, 0, dissect_removed },
  {   2, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_replaced },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_acp133_T_requested_delivery_method(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_requested_delivery_method_choice, hf_index, ett_acp133_T_requested_delivery_method,
                                 NULL);

  return offset;
}
static int dissect_requested_delivery_method(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_T_requested_delivery_method(FALSE, tvb, offset, pinfo, tree, hf_acp133_requested_delivery_method);
}


static const ber_sequence_t AlgorithmInformation_sequence[] = {
  { BER_CLASS_CON, 0, 0, dissect_algorithm_identifier },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_originator_certificate_selector },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_recipient_certificate_selector },
  { 0, 0, 0, NULL }
};

static int
dissect_acp133_AlgorithmInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AlgorithmInformation_sequence, hf_index, ett_acp133_AlgorithmInformation);

  return offset;
}
static int dissect_token_encryption_algorithm_preference_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_AlgorithmInformation(FALSE, tvb, offset, pinfo, tree, hf_acp133_token_encryption_algorithm_preference_item);
}
static int dissect_token_signature_algorithm_preference_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_AlgorithmInformation(FALSE, tvb, offset, pinfo, tree, hf_acp133_token_signature_algorithm_preference_item);
}


static const ber_sequence_t SEQUENCE_OF_AlgorithmInformation_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_token_encryption_algorithm_preference_item },
};

static int
dissect_acp133_SEQUENCE_OF_AlgorithmInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_AlgorithmInformation_sequence_of, hf_index, ett_acp133_SEQUENCE_OF_AlgorithmInformation);

  return offset;
}
static int dissect_token_encryption_algorithm_preference(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_SEQUENCE_OF_AlgorithmInformation(FALSE, tvb, offset, pinfo, tree, hf_acp133_token_encryption_algorithm_preference);
}
static int dissect_token_signature_algorithm_preference(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_SEQUENCE_OF_AlgorithmInformation(FALSE, tvb, offset, pinfo, tree, hf_acp133_token_signature_algorithm_preference);
}


static const ber_sequence_t DLPolicy_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_report_propagation },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_report_from_dl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_originating_MTA_report },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_originator_report },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_return_of_content },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_priority },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_disclosure_of_other_recipients },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL, dissect_implicit_conversion_prohibited },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_conversion_with_loss_prohibited },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL, dissect_further_dl_expansion_allowed },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL, dissect_originator_requested_alternate_recipient_removed },
  { BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL, dissect_proof_of_delivery },
  { BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL, dissect_requested_delivery_method },
  { BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL, dissect_token_encryption_algorithm_preference },
  { BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL, dissect_token_signature_algorithm_preference },
  { 0, 0, 0, NULL }
};

static int
dissect_acp133_DLPolicy(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              DLPolicy_set, hf_index, ett_acp133_DLPolicy);

  return offset;
}



static int
dissect_acp133_GeneralString(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GeneralString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_description(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_GeneralString(FALSE, tvb, offset, pinfo, tree, hf_acp133_description);
}


static const ber_sequence_t SET_OF_ExtendedContentType_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_content_types_item },
};

static int
dissect_acp133_SET_OF_ExtendedContentType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_ExtendedContentType_set_of, hf_index, ett_acp133_SET_OF_ExtendedContentType);

  return offset;
}
static int dissect_content_types(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_SET_OF_ExtendedContentType(FALSE, tvb, offset, pinfo, tree, hf_acp133_content_types);
}


static const ber_sequence_t Capability_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_content_types },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_maximum_content_length },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_encoded_information_types_constraints },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_security_labels },
  { 0, 0, 0, NULL }
};

static int
dissect_acp133_Capability(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              Capability_set, hf_index, ett_acp133_Capability);

  return offset;
}
static int dissect_capabilities_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_Capability(FALSE, tvb, offset, pinfo, tree, hf_acp133_capabilities_item);
}


static const ber_sequence_t SET_OF_Capability_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_capabilities_item },
};

static int
dissect_acp133_SET_OF_Capability(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_Capability_set_of, hf_index, ett_acp133_SET_OF_Capability);

  return offset;
}
static int dissect_capabilities(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_acp133_SET_OF_Capability(FALSE, tvb, offset, pinfo, tree, hf_acp133_capabilities);
}


static const ber_sequence_t AddressCapabilities_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_GeneralString, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_description },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_address },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_capabilities },
  { 0, 0, 0, NULL }
};

static int
dissect_acp133_AddressCapabilities(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AddressCapabilities_sequence, hf_index, ett_acp133_AddressCapabilities);

  return offset;
}

/*--- PDUs ---*/

static void dissect_ACPPreferredDelivery_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_acp133_ACPPreferredDelivery(FALSE, tvb, 0, pinfo, tree, hf_acp133_ACPPreferredDelivery_PDU);
}
static void dissect_ALType_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_acp133_ALType(FALSE, tvb, 0, pinfo, tree, hf_acp133_ALType_PDU);
}
static void dissect_Community_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_acp133_Community(FALSE, tvb, 0, pinfo, tree, hf_acp133_Community_PDU);
}
static void dissect_OnSupported_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_acp133_OnSupported(FALSE, tvb, 0, pinfo, tree, hf_acp133_OnSupported_PDU);
}
static void dissect_ACPLegacyFormat_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_acp133_ACPLegacyFormat(FALSE, tvb, 0, pinfo, tree, hf_acp133_ACPLegacyFormat_PDU);
}
static void dissect_Addressees_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_acp133_Addressees(FALSE, tvb, 0, pinfo, tree, hf_acp133_Addressees_PDU);
}
static void dissect_Classification_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_acp133_Classification(FALSE, tvb, 0, pinfo, tree, hf_acp133_Classification_PDU);
}
static void dissect_DistributionCode_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_acp133_DistributionCode(FALSE, tvb, 0, pinfo, tree, hf_acp133_DistributionCode_PDU);
}
static void dissect_JPEG_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_acp133_JPEG(FALSE, tvb, 0, pinfo, tree, hf_acp133_JPEG_PDU);
}
static void dissect_MonthlyUKMs_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_acp133_MonthlyUKMs(FALSE, tvb, 0, pinfo, tree, hf_acp133_MonthlyUKMs_PDU);
}
static void dissect_Remarks_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_acp133_Remarks(FALSE, tvb, 0, pinfo, tree, hf_acp133_Remarks_PDU);
}
static void dissect_RIParameters_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_acp133_RIParameters(FALSE, tvb, 0, pinfo, tree, hf_acp133_RIParameters_PDU);
}
static void dissect_Kmid_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_acp133_Kmid(FALSE, tvb, 0, pinfo, tree, hf_acp133_Kmid_PDU);
}
static void dissect_MLReceiptPolicy_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_acp133_MLReceiptPolicy(FALSE, tvb, 0, pinfo, tree, hf_acp133_MLReceiptPolicy_PDU);
}
static void dissect_DLSubmitPermission_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_acp133_DLSubmitPermission(FALSE, tvb, 0, pinfo, tree, hf_acp133_DLSubmitPermission_PDU);
}
static void dissect_DLPolicy_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_acp133_DLPolicy(FALSE, tvb, 0, pinfo, tree, hf_acp133_DLPolicy_PDU);
}
static void dissect_AddressCapabilities_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_acp133_AddressCapabilities(FALSE, tvb, 0, pinfo, tree, hf_acp133_AddressCapabilities_PDU);
}
static void dissect_Capability_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_acp133_Capability(FALSE, tvb, 0, pinfo, tree, hf_acp133_Capability_PDU);
}


/*--- End of included file: packet-acp133-fn.c ---*/
#line 61 "packet-acp133-template.c"


/*--- proto_register_acp133 -------------------------------------------*/
void proto_register_acp133(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {

/*--- Included file: packet-acp133-hfarr.c ---*/
#line 1 "packet-acp133-hfarr.c"
    { &hf_acp133_ACPPreferredDelivery_PDU,
      { "ACPPreferredDelivery", "acp133.ACPPreferredDelivery",
        FT_UINT32, BASE_DEC, VALS(acp133_ACPPreferredDelivery_vals), 0,
        "ACPPreferredDelivery", HFILL }},
    { &hf_acp133_ALType_PDU,
      { "ALType", "acp133.ALType",
        FT_INT32, BASE_DEC, VALS(acp133_ALType_vals), 0,
        "ALType", HFILL }},
    { &hf_acp133_Community_PDU,
      { "Community", "acp133.Community",
        FT_UINT32, BASE_DEC, VALS(acp133_Community_vals), 0,
        "Community", HFILL }},
    { &hf_acp133_OnSupported_PDU,
      { "OnSupported", "acp133.OnSupported",
        FT_BYTES, BASE_HEX, NULL, 0,
        "OnSupported", HFILL }},
    { &hf_acp133_ACPLegacyFormat_PDU,
      { "ACPLegacyFormat", "acp133.ACPLegacyFormat",
        FT_INT32, BASE_DEC, VALS(acp133_ACPLegacyFormat_vals), 0,
        "ACPLegacyFormat", HFILL }},
    { &hf_acp133_Addressees_PDU,
      { "Addressees", "acp133.Addressees",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Addressees", HFILL }},
    { &hf_acp133_Classification_PDU,
      { "Classification", "acp133.Classification",
        FT_UINT32, BASE_DEC, VALS(acp133_Classification_vals), 0,
        "Classification", HFILL }},
    { &hf_acp133_DistributionCode_PDU,
      { "DistributionCode", "acp133.DistributionCode",
        FT_STRING, BASE_NONE, NULL, 0,
        "DistributionCode", HFILL }},
    { &hf_acp133_JPEG_PDU,
      { "JPEG", "acp133.JPEG",
        FT_BYTES, BASE_HEX, NULL, 0,
        "JPEG", HFILL }},
    { &hf_acp133_MonthlyUKMs_PDU,
      { "MonthlyUKMs", "acp133.MonthlyUKMs",
        FT_NONE, BASE_NONE, NULL, 0,
        "MonthlyUKMs", HFILL }},
    { &hf_acp133_Remarks_PDU,
      { "Remarks", "acp133.Remarks",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Remarks", HFILL }},
    { &hf_acp133_RIParameters_PDU,
      { "RIParameters", "acp133.RIParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "RIParameters", HFILL }},
    { &hf_acp133_Kmid_PDU,
      { "Kmid", "acp133.Kmid",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Kmid", HFILL }},
    { &hf_acp133_MLReceiptPolicy_PDU,
      { "MLReceiptPolicy", "acp133.MLReceiptPolicy",
        FT_UINT32, BASE_DEC, VALS(acp133_MLReceiptPolicy_vals), 0,
        "MLReceiptPolicy", HFILL }},
    { &hf_acp133_DLSubmitPermission_PDU,
      { "DLSubmitPermission", "acp133.DLSubmitPermission",
        FT_UINT32, BASE_DEC, VALS(acp133_DLSubmitPermission_vals), 0,
        "DLSubmitPermission", HFILL }},
    { &hf_acp133_DLPolicy_PDU,
      { "DLPolicy", "acp133.DLPolicy",
        FT_NONE, BASE_NONE, NULL, 0,
        "DLPolicy", HFILL }},
    { &hf_acp133_AddressCapabilities_PDU,
      { "AddressCapabilities", "acp133.AddressCapabilities",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddressCapabilities", HFILL }},
    { &hf_acp133_Capability_PDU,
      { "Capability", "acp133.Capability",
        FT_NONE, BASE_NONE, NULL, 0,
        "Capability", HFILL }},
    { &hf_acp133_Addressees_item,
      { "Item", "acp133.Addressees_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "Addressees/_item", HFILL }},
    { &hf_acp133_ukm_entries,
      { "ukm-entries", "acp133.ukm_entries",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MonthlyUKMs/ukm-entries", HFILL }},
    { &hf_acp133_ukm_entries_item,
      { "Item", "acp133.ukm_entries_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "MonthlyUKMs/ukm-entries/_item", HFILL }},
    { &hf_acp133_algorithm_identifier,
      { "algorithm-identifier", "acp133.algorithm_identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_acp133_encrypted,
      { "encrypted", "acp133.encrypted",
        FT_BYTES, BASE_HEX, NULL, 0,
        "MonthlyUKMs/encrypted", HFILL }},
    { &hf_acp133_Remarks_item,
      { "Item", "acp133.Remarks_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "Remarks/_item", HFILL }},
    { &hf_acp133_rI,
      { "rI", "acp133.rI",
        FT_STRING, BASE_NONE, NULL, 0,
        "RIParameters/rI", HFILL }},
    { &hf_acp133_rIType,
      { "rIType", "acp133.rIType",
        FT_UINT32, BASE_DEC, VALS(acp133_T_rIType_vals), 0,
        "RIParameters/rIType", HFILL }},
    { &hf_acp133_minimize,
      { "minimize", "acp133.minimize",
        FT_BOOLEAN, 8, NULL, 0,
        "RIParameters/minimize", HFILL }},
    { &hf_acp133_sHD,
      { "sHD", "acp133.sHD",
        FT_STRING, BASE_NONE, NULL, 0,
        "RIParameters/sHD", HFILL }},
    { &hf_acp133_classification,
      { "classification", "acp133.classification",
        FT_UINT32, BASE_DEC, VALS(acp133_Classification_vals), 0,
        "RIParameters/classification", HFILL }},
    { &hf_acp133_tag,
      { "tag", "acp133.tag",
        FT_NONE, BASE_NONE, NULL, 0,
        "UKMEntry/tag", HFILL }},
    { &hf_acp133_ukm,
      { "ukm", "acp133.ukm",
        FT_BYTES, BASE_HEX, NULL, 0,
        "UKMEntry/ukm", HFILL }},
    { &hf_acp133_kmid,
      { "kmid", "acp133.kmid",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PairwiseTag/kmid", HFILL }},
    { &hf_acp133_edition,
      { "edition", "acp133.edition",
        FT_INT32, BASE_DEC, NULL, 0,
        "PairwiseTag/edition", HFILL }},
    { &hf_acp133_date,
      { "date", "acp133.date",
        FT_STRING, BASE_NONE, NULL, 0,
        "PairwiseTag/date", HFILL }},
    { &hf_acp133_none,
      { "none", "acp133.none",
        FT_NONE, BASE_NONE, NULL, 0,
        "MLReceiptPolicy/none", HFILL }},
    { &hf_acp133_insteadOf,
      { "insteadOf", "acp133.insteadOf",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MLReceiptPolicy/insteadOf", HFILL }},
    { &hf_acp133_insteadOf_item,
      { "Item", "acp133.insteadOf_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MLReceiptPolicy/insteadOf/_item", HFILL }},
    { &hf_acp133_inAdditionTo,
      { "inAdditionTo", "acp133.inAdditionTo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MLReceiptPolicy/inAdditionTo", HFILL }},
    { &hf_acp133_inAdditionTo_item,
      { "Item", "acp133.inAdditionTo_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MLReceiptPolicy/inAdditionTo/_item", HFILL }},
    { &hf_acp133_individual,
      { "individual", "acp133.individual",
        FT_NONE, BASE_NONE, NULL, 0,
        "DLSubmitPermission/individual", HFILL }},
    { &hf_acp133_member_of_dl,
      { "member-of-dl", "acp133.member_of_dl",
        FT_NONE, BASE_NONE, NULL, 0,
        "DLSubmitPermission/member-of-dl", HFILL }},
    { &hf_acp133_pattern_match,
      { "pattern-match", "acp133.pattern_match",
        FT_NONE, BASE_NONE, NULL, 0,
        "DLSubmitPermission/pattern-match", HFILL }},
    { &hf_acp133_member_of_group,
      { "member-of-group", "acp133.member_of_group",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "DLSubmitPermission/member-of-group", HFILL }},
    { &hf_acp133_report_propagation,
      { "report-propagation", "acp133.report_propagation",
        FT_INT32, BASE_DEC, VALS(acp133_T_report_propagation_vals), 0,
        "DLPolicy/report-propagation", HFILL }},
    { &hf_acp133_report_from_dl,
      { "report-from-dl", "acp133.report_from_dl",
        FT_INT32, BASE_DEC, VALS(acp133_T_report_from_dl_vals), 0,
        "DLPolicy/report-from-dl", HFILL }},
    { &hf_acp133_originating_MTA_report,
      { "originating-MTA-report", "acp133.originating_MTA_report",
        FT_INT32, BASE_DEC, VALS(acp133_T_originating_MTA_report_vals), 0,
        "DLPolicy/originating-MTA-report", HFILL }},
    { &hf_acp133_originator_report,
      { "originator-report", "acp133.originator_report",
        FT_INT32, BASE_DEC, VALS(acp133_T_originator_report_vals), 0,
        "DLPolicy/originator-report", HFILL }},
    { &hf_acp133_return_of_content,
      { "return-of-content", "acp133.return_of_content",
        FT_UINT32, BASE_DEC, VALS(acp133_T_return_of_content_vals), 0,
        "DLPolicy/return-of-content", HFILL }},
    { &hf_acp133_priority,
      { "priority", "acp133.priority",
        FT_INT32, BASE_DEC, VALS(acp133_T_priority_vals), 0,
        "DLPolicy/priority", HFILL }},
    { &hf_acp133_disclosure_of_other_recipients,
      { "disclosure-of-other-recipients", "acp133.disclosure_of_other_recipients",
        FT_UINT32, BASE_DEC, VALS(acp133_T_disclosure_of_other_recipients_vals), 0,
        "DLPolicy/disclosure-of-other-recipients", HFILL }},
    { &hf_acp133_implicit_conversion_prohibited,
      { "implicit-conversion-prohibited", "acp133.implicit_conversion_prohibited",
        FT_UINT32, BASE_DEC, VALS(acp133_T_implicit_conversion_prohibited_vals), 0,
        "DLPolicy/implicit-conversion-prohibited", HFILL }},
    { &hf_acp133_conversion_with_loss_prohibited,
      { "conversion-with-loss-prohibited", "acp133.conversion_with_loss_prohibited",
        FT_UINT32, BASE_DEC, VALS(acp133_T_conversion_with_loss_prohibited_vals), 0,
        "DLPolicy/conversion-with-loss-prohibited", HFILL }},
    { &hf_acp133_further_dl_expansion_allowed,
      { "further-dl-expansion-allowed", "acp133.further_dl_expansion_allowed",
        FT_BOOLEAN, 8, NULL, 0,
        "DLPolicy/further-dl-expansion-allowed", HFILL }},
    { &hf_acp133_originator_requested_alternate_recipient_removed,
      { "originator-requested-alternate-recipient-removed", "acp133.originator_requested_alternate_recipient_removed",
        FT_BOOLEAN, 8, NULL, 0,
        "DLPolicy/originator-requested-alternate-recipient-removed", HFILL }},
    { &hf_acp133_proof_of_delivery,
      { "proof-of-delivery", "acp133.proof_of_delivery",
        FT_INT32, BASE_DEC, VALS(acp133_T_proof_of_delivery_vals), 0,
        "DLPolicy/proof-of-delivery", HFILL }},
    { &hf_acp133_requested_delivery_method,
      { "requested-delivery-method", "acp133.requested_delivery_method",
        FT_UINT32, BASE_DEC, VALS(acp133_T_requested_delivery_method_vals), 0,
        "DLPolicy/requested-delivery-method", HFILL }},
    { &hf_acp133_unchanged,
      { "unchanged", "acp133.unchanged",
        FT_NONE, BASE_NONE, NULL, 0,
        "DLPolicy/requested-delivery-method/unchanged", HFILL }},
    { &hf_acp133_removed,
      { "removed", "acp133.removed",
        FT_NONE, BASE_NONE, NULL, 0,
        "DLPolicy/requested-delivery-method/removed", HFILL }},
    { &hf_acp133_replaced,
      { "replaced", "acp133.replaced",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DLPolicy/requested-delivery-method/replaced", HFILL }},
    { &hf_acp133_token_encryption_algorithm_preference,
      { "token-encryption-algorithm-preference", "acp133.token_encryption_algorithm_preference",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DLPolicy/token-encryption-algorithm-preference", HFILL }},
    { &hf_acp133_token_encryption_algorithm_preference_item,
      { "Item", "acp133.token_encryption_algorithm_preference_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "DLPolicy/token-encryption-algorithm-preference/_item", HFILL }},
    { &hf_acp133_token_signature_algorithm_preference,
      { "token-signature-algorithm-preference", "acp133.token_signature_algorithm_preference",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DLPolicy/token-signature-algorithm-preference", HFILL }},
    { &hf_acp133_token_signature_algorithm_preference_item,
      { "Item", "acp133.token_signature_algorithm_preference_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "DLPolicy/token-signature-algorithm-preference/_item", HFILL }},
    { &hf_acp133_originator_certificate_selector,
      { "originator-certificate-selector", "acp133.originator_certificate_selector",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmInformation/originator-certificate-selector", HFILL }},
    { &hf_acp133_recipient_certificate_selector,
      { "recipient-certificate-selector", "acp133.recipient_certificate_selector",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmInformation/recipient-certificate-selector", HFILL }},
    { &hf_acp133_description,
      { "description", "acp133.description",
        FT_STRING, BASE_NONE, NULL, 0,
        "AddressCapabilities/description", HFILL }},
    { &hf_acp133_address,
      { "address", "acp133.address",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddressCapabilities/address", HFILL }},
    { &hf_acp133_capabilities,
      { "capabilities", "acp133.capabilities",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AddressCapabilities/capabilities", HFILL }},
    { &hf_acp133_capabilities_item,
      { "Item", "acp133.capabilities_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddressCapabilities/capabilities/_item", HFILL }},
    { &hf_acp133_content_types,
      { "content-types", "acp133.content_types",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Capability/content-types", HFILL }},
    { &hf_acp133_content_types_item,
      { "Item", "acp133.content_types_item",
        FT_OID, BASE_NONE, NULL, 0,
        "Capability/content-types/_item", HFILL }},
    { &hf_acp133_maximum_content_length,
      { "maximum-content-length", "acp133.maximum_content_length",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Capability/maximum-content-length", HFILL }},
    { &hf_acp133_encoded_information_types_constraints,
      { "encoded-information-types-constraints", "acp133.encoded_information_types_constraints",
        FT_NONE, BASE_NONE, NULL, 0,
        "Capability/encoded-information-types-constraints", HFILL }},
    { &hf_acp133_security_labels,
      { "security-labels", "acp133.security_labels",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Capability/security-labels", HFILL }},
    { &hf_acp133_OnSupported_acp127_nn,
      { "acp127-nn", "acp133.acp127-nn",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_acp133_OnSupported_acp127_pn,
      { "acp127-pn", "acp133.acp127-pn",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_acp133_OnSupported_acp127_tn,
      { "acp127-tn", "acp133.acp127-tn",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},

/*--- End of included file: packet-acp133-hfarr.c ---*/
#line 70 "packet-acp133-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_acp133,

/*--- Included file: packet-acp133-ettarr.c ---*/
#line 1 "packet-acp133-ettarr.c"
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
#line 76 "packet-acp133-template.c"
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
#line 1 "packet-acp133-dis-tab.c"
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
#line 92 "packet-acp133-template.c"

  /* X.402 Object Classes */
  register_ber_oid_name("2.6.5.1.0","id-oc-mhs-distribution-list");
  register_ber_oid_name("2.6.5.1.1","id-oc-mhs-message-store");
  register_ber_oid_name("2.6.5.1.2","id-oc-mhs-message-transfer-agent");
  register_ber_oid_name("2.6.5.1.3","id-oc-mhs-user");

  /* SDN.701 Object Classes */
  register_ber_oid_name("2.16.840.1.101.2.1.4.13", "id-oc-secure-user");
  register_ber_oid_name("2.16.840.1.101.2.1.4.16", "id-oc-ukms");

  /* ACP133 Object Classes */
  register_ber_oid_name("2.16.840.1.101.2.2.3.26", "id-oc-plaData");
  register_ber_oid_name("2.16.840.1.101.2.2.3.28", "id-oc-cadACP127");
  register_ber_oid_name("2.16.840.1.101.2.2.3.31", "id-oc-mLA");
  register_ber_oid_name("2.16.840.1.101.2.2.3.34", "id-oc-orgACP127");
  register_ber_oid_name("2.16.840.1.101.2.2.3.35", "id-oc-plaCollectiveACP127");
  register_ber_oid_name("2.16.840.1.101.2.2.3.37", "id-oc-routingIndicator");
  register_ber_oid_name("2.16.840.1.101.2.2.3.38", "id-oc-sigintPLA");
  register_ber_oid_name("2.16.840.1.101.2.2.3.39", "id-oc-sIPLA");
  register_ber_oid_name("2.16.840.1.101.2.2.3.40", "id-oc-spotPLA");
  register_ber_oid_name("2.16.840.1.101.2.2.3.41", "id-oc-taskForceACP127");
  register_ber_oid_name("2.16.840.1.101.2.2.3.42", "id-oc-tenantACP127");
  register_ber_oid_name("2.16.840.1.101.2.2.3.47", "id-oc-plaACP127");
  register_ber_oid_name("2.16.840.1.101.2.2.3.52", "id-oc-aliasCommonName");
  register_ber_oid_name("2.16.840.1.101.2.2.3.53", "id-oc-aliasOrganizationalUnit");
  register_ber_oid_name("2.16.840.1.101.2.2.3.54", "id-oc-distributionCodesHandled");
  register_ber_oid_name("2.16.840.1.101.2.2.3.55", "id-oc-distributionCodeDescription");
  register_ber_oid_name("2.16.840.1.101.2.2.3.56", "id-oc-plaUser");
  register_ber_oid_name("2.16.840.1.101.2.2.3.57", "id-oc-addressList");
  register_ber_oid_name("2.16.840.1.101.2.2.3.58", "id-oc-altSpellingACP127");
  register_ber_oid_name("2.16.840.1.101.2.2.3.59", "id-oc-messagingGateway");
  register_ber_oid_name("2.16.840.1.101.2.2.3.60", "id-oc-network");
  register_ber_oid_name("2.16.840.1.101.2.2.3.61", "id-oc-networkInstructions");
  register_ber_oid_name("2.16.840.1.101.2.2.3.62", "id-oc-otherContactInformation");
  register_ber_oid_name("2.16.840.1.101.2.2.3.63", "id-oc-releaseAuthorityPerson");
  register_ber_oid_name("2.16.840.1.101.2.2.3.64", "id-oc-mLAgent");
  register_ber_oid_name("2.16.840.1.101.2.2.3.65", "id-oc-releaseAuthorityPersonA");
  register_ber_oid_name("2.16.840.1.101.2.2.3.66", "id-oc-securePkiUser");
  register_ber_oid_name("2.16.840.1.101.2.2.3.67", "id-oc-dSSCSPLA");
  register_ber_oid_name("2.16.840.1.101.2.2.3.68", "id-oc-aCPNetworkEdB");
  register_ber_oid_name("2.16.840.1.101.2.2.3.69", "id-oc-aCPNetworkInstructionsEdB");

  /* gateway types */
  register_ber_oid_name("2.16.840.1.101.2.2.5.0", "acp120-acp127");
  register_ber_oid_name("2.16.840.1.101.2.2.5.1", "acp120-janap128");
  register_ber_oid_name("2.16.840.1.101.2.2.5.2", "acp120-mhs");
  register_ber_oid_name("2.16.840.1.101.2.2.5.3", "acp120-mmhs");
  register_ber_oid_name("2.16.840.1.101.2.2.5.4", "acp120-rfc822");
  register_ber_oid_name("2.16.840.1.101.2.2.5.5", "boundaryMTA");
  register_ber_oid_name("2.16.840.1.101.2.2.5.6", "mmhs-mhs");
  register_ber_oid_name("2.16.840.1.101.2.2.5.7", "mmhs-rfc822");
  register_ber_oid_name("2.16.840.1.101.2.2.5.8", "mta-acp127");

}
