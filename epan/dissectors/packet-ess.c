/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* .\packet-ess.c                                                             */
/* ../../tools/asn2eth.py -X -b -k -e -p ess -c ess.cnf -s packet-ess-template ExtendedSecurityServices.asn */

/* Input file: packet-ess-template.c */

/* packet-ess.c
 * Routines for RFC2634 Extended Security Services packet dissection
 *   Ronnie Sahlberg 2004
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

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-ess.h"
#include "packet-cms.h"
#include "packet-x509ce.h"
#include "packet-x509af.h"

#define PNAME  "Extended Security Services"
#define PSNAME "ESS"
#define PFNAME "ess"

/* Initialize the protocol and registered fields */
static int proto_ess = -1;
static int hf_ess_SecurityCategory_type_OID = -1;

/*--- Included file: packet-ess-hf.c ---*/

static int hf_ess_ReceiptRequest_PDU = -1;        /* ReceiptRequest */
static int hf_ess_ContentIdentifier_PDU = -1;     /* ContentIdentifier */
static int hf_ess_Receipt_PDU = -1;               /* Receipt */
static int hf_ess_ContentHints_PDU = -1;          /* ContentHints */
static int hf_ess_MsgSigDigest_PDU = -1;          /* MsgSigDigest */
static int hf_ess_ContentReference_PDU = -1;      /* ContentReference */
static int hf_ess_ESSSecurityLabel_PDU = -1;      /* ESSSecurityLabel */
static int hf_ess_EquivalentLabels_PDU = -1;      /* EquivalentLabels */
static int hf_ess_MLExpansionHistory_PDU = -1;    /* MLExpansionHistory */
static int hf_ess_SigningCertificate_PDU = -1;    /* SigningCertificate */
static int hf_ess_signedContentIdentifier = -1;   /* ContentIdentifier */
static int hf_ess_receiptsFrom = -1;              /* ReceiptsFrom */
static int hf_ess_receiptsTo = -1;                /* SEQUENCE_OF_GeneralNames */
static int hf_ess_receiptsTo_item = -1;           /* GeneralNames */
static int hf_ess_allOrFirstTier = -1;            /* AllOrFirstTier */
static int hf_ess_receiptList = -1;               /* SEQUENCE_OF_GeneralNames */
static int hf_ess_receiptList_item = -1;          /* GeneralNames */
static int hf_ess_version = -1;                   /* ESSVersion */
static int hf_ess_contentType = -1;               /* ContentType */
static int hf_ess_originatorSignatureValue = -1;  /* OCTET_STRING */
static int hf_ess_contentDescription = -1;        /* UTF8String */
static int hf_ess_security_policy_identifier = -1;  /* SecurityPolicyIdentifier */
static int hf_ess_security_classification = -1;   /* SecurityClassification */
static int hf_ess_privacy_mark = -1;              /* ESSPrivacyMark */
static int hf_ess_security_categories = -1;       /* SecurityCategories */
static int hf_ess_pString = -1;                   /* PrintableString */
static int hf_ess_utf8String = -1;                /* UTF8String */
static int hf_ess_SecurityCategories_item = -1;   /* SecurityCategory */
static int hf_ess_type = -1;                      /* T_type */
static int hf_ess_value = -1;                     /* T_value */
static int hf_ess_EquivalentLabels_item = -1;     /* ESSSecurityLabel */
static int hf_ess_MLExpansionHistory_item = -1;   /* MLData */
static int hf_ess_mailListIdentifier = -1;        /* EntityIdentifier */
static int hf_ess_expansionTime = -1;             /* GeneralizedTime */
static int hf_ess_mlReceiptPolicy = -1;           /* MLReceiptPolicy */
static int hf_ess_issuerAndSerialNumber = -1;     /* IssuerAndSerialNumber */
static int hf_ess_subjectKeyIdentifier = -1;      /* SubjectKeyIdentifier */
static int hf_ess_none = -1;                      /* NULL */
static int hf_ess_insteadOf = -1;                 /* SEQUENCE_OF_GeneralNames */
static int hf_ess_insteadOf_item = -1;            /* GeneralNames */
static int hf_ess_inAdditionTo = -1;              /* SEQUENCE_OF_GeneralNames */
static int hf_ess_inAdditionTo_item = -1;         /* GeneralNames */
static int hf_ess_certs = -1;                     /* SEQUENCE_OF_ESSCertID */
static int hf_ess_certs_item = -1;                /* ESSCertID */
static int hf_ess_policies = -1;                  /* SEQUENCE_OF_PolicyInformation */
static int hf_ess_policies_item = -1;             /* PolicyInformation */
static int hf_ess_certHash = -1;                  /* Hash */
static int hf_ess_issuerSerial = -1;              /* IssuerSerial */
static int hf_ess_issuer = -1;                    /* GeneralNames */
static int hf_ess_serialNumber = -1;              /* CertificateSerialNumber */

/*--- End of included file: packet-ess-hf.c ---*/


/* Initialize the subtree pointers */

/*--- Included file: packet-ess-ett.c ---*/

static gint ett_ess_ReceiptRequest = -1;
static gint ett_ess_SEQUENCE_OF_GeneralNames = -1;
static gint ett_ess_ReceiptsFrom = -1;
static gint ett_ess_Receipt = -1;
static gint ett_ess_ContentHints = -1;
static gint ett_ess_ContentReference = -1;
static gint ett_ess_ESSSecurityLabel = -1;
static gint ett_ess_ESSPrivacyMark = -1;
static gint ett_ess_SecurityCategories = -1;
static gint ett_ess_SecurityCategory = -1;
static gint ett_ess_EquivalentLabels = -1;
static gint ett_ess_MLExpansionHistory = -1;
static gint ett_ess_MLData = -1;
static gint ett_ess_EntityIdentifier = -1;
static gint ett_ess_MLReceiptPolicy = -1;
static gint ett_ess_SigningCertificate = -1;
static gint ett_ess_SEQUENCE_OF_ESSCertID = -1;
static gint ett_ess_SEQUENCE_OF_PolicyInformation = -1;
static gint ett_ess_ESSCertID = -1;
static gint ett_ess_IssuerSerial = -1;

/*--- End of included file: packet-ess-ett.c ---*/


static const char *object_identifier_id;


/*--- Included file: packet-ess-fn.c ---*/

/*--- Fields for imported types ---*/

static int dissect_receiptsTo_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_GeneralNames(FALSE, tvb, offset, pinfo, tree, hf_ess_receiptsTo_item);
}
static int dissect_receiptList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_GeneralNames(FALSE, tvb, offset, pinfo, tree, hf_ess_receiptList_item);
}
static int dissect_contentType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_ContentType(FALSE, tvb, offset, pinfo, tree, hf_ess_contentType);
}
static int dissect_issuerAndSerialNumber(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_IssuerAndSerialNumber(FALSE, tvb, offset, pinfo, tree, hf_ess_issuerAndSerialNumber);
}
static int dissect_subjectKeyIdentifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_SubjectKeyIdentifier(FALSE, tvb, offset, pinfo, tree, hf_ess_subjectKeyIdentifier);
}
static int dissect_insteadOf_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_GeneralNames(FALSE, tvb, offset, pinfo, tree, hf_ess_insteadOf_item);
}
static int dissect_inAdditionTo_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_GeneralNames(FALSE, tvb, offset, pinfo, tree, hf_ess_inAdditionTo_item);
}
static int dissect_policies_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_PolicyInformation(FALSE, tvb, offset, pinfo, tree, hf_ess_policies_item);
}
static int dissect_issuer(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_GeneralNames(FALSE, tvb, offset, pinfo, tree, hf_ess_issuer);
}
static int dissect_serialNumber(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_CertificateSerialNumber(FALSE, tvb, offset, pinfo, tree, hf_ess_serialNumber);
}



static int
dissect_ess_ContentIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_signedContentIdentifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ess_ContentIdentifier(FALSE, tvb, offset, pinfo, tree, hf_ess_signedContentIdentifier);
}


static const value_string ess_AllOrFirstTier_vals[] = {
  {   0, "allReceipts" },
  {   1, "firstTierRecipients" },
  { 0, NULL }
};


static int
dissect_ess_AllOrFirstTier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_allOrFirstTier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ess_AllOrFirstTier(TRUE, tvb, offset, pinfo, tree, hf_ess_allOrFirstTier);
}


static const ber_sequence_t SEQUENCE_OF_GeneralNames_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_receiptsTo_item },
};

static int
dissect_ess_SEQUENCE_OF_GeneralNames(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_GeneralNames_sequence_of, hf_index, ett_ess_SEQUENCE_OF_GeneralNames);

  return offset;
}
static int dissect_receiptsTo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ess_SEQUENCE_OF_GeneralNames(FALSE, tvb, offset, pinfo, tree, hf_ess_receiptsTo);
}
static int dissect_receiptList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ess_SEQUENCE_OF_GeneralNames(TRUE, tvb, offset, pinfo, tree, hf_ess_receiptList);
}
static int dissect_insteadOf_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ess_SEQUENCE_OF_GeneralNames(TRUE, tvb, offset, pinfo, tree, hf_ess_insteadOf);
}
static int dissect_inAdditionTo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ess_SEQUENCE_OF_GeneralNames(TRUE, tvb, offset, pinfo, tree, hf_ess_inAdditionTo);
}


static const value_string ess_ReceiptsFrom_vals[] = {
  {   0, "allOrFirstTier" },
  {   1, "receiptList" },
  { 0, NULL }
};

static const ber_choice_t ReceiptsFrom_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_allOrFirstTier_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_receiptList_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_ess_ReceiptsFrom(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ReceiptsFrom_choice, hf_index, ett_ess_ReceiptsFrom,
                                 NULL);

  return offset;
}
static int dissect_receiptsFrom(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ess_ReceiptsFrom(FALSE, tvb, offset, pinfo, tree, hf_ess_receiptsFrom);
}


static const ber_sequence_t ReceiptRequest_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_signedContentIdentifier },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_receiptsFrom },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_receiptsTo },
  { 0, 0, 0, NULL }
};

static int
dissect_ess_ReceiptRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ReceiptRequest_sequence, hf_index, ett_ess_ReceiptRequest);

  return offset;
}


static const value_string ess_ESSVersion_vals[] = {
  {   1, "v1" },
  { 0, NULL }
};


static int
dissect_ess_ESSVersion(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_version(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ess_ESSVersion(FALSE, tvb, offset, pinfo, tree, hf_ess_version);
}



static int
dissect_ess_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_originatorSignatureValue(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ess_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_ess_originatorSignatureValue);
}


static const ber_sequence_t Receipt_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_version },
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_contentType },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_signedContentIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_originatorSignatureValue },
  { 0, 0, 0, NULL }
};

static int
dissect_ess_Receipt(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Receipt_sequence, hf_index, ett_ess_Receipt);

  return offset;
}



static int
dissect_ess_UTF8String(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_contentDescription(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ess_UTF8String(FALSE, tvb, offset, pinfo, tree, hf_ess_contentDescription);
}
static int dissect_utf8String(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ess_UTF8String(FALSE, tvb, offset, pinfo, tree, hf_ess_utf8String);
}


static const ber_sequence_t ContentHints_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_UTF8String, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_contentDescription },
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_contentType },
  { 0, 0, 0, NULL }
};

static int
dissect_ess_ContentHints(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ContentHints_sequence, hf_index, ett_ess_ContentHints);

  return offset;
}



static int
dissect_ess_MsgSigDigest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t ContentReference_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_contentType },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_signedContentIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_originatorSignatureValue },
  { 0, 0, 0, NULL }
};

static int
dissect_ess_ContentReference(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ContentReference_sequence, hf_index, ett_ess_ContentReference);

  return offset;
}



static int
dissect_ess_SecurityPolicyIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_security_policy_identifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ess_SecurityPolicyIdentifier(FALSE, tvb, offset, pinfo, tree, hf_ess_security_policy_identifier);
}


static const value_string ess_SecurityClassification_vals[] = {
  {   0, "unmarked" },
  {   1, "unclassified" },
  {   2, "restricted" },
  {   3, "confidential" },
  {   4, "secret" },
  {   5, "top-secret" },
  { 0, NULL }
};


static int
dissect_ess_SecurityClassification(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_security_classification(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ess_SecurityClassification(FALSE, tvb, offset, pinfo, tree, hf_ess_security_classification);
}



static int
dissect_ess_PrintableString(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_pString(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ess_PrintableString(FALSE, tvb, offset, pinfo, tree, hf_ess_pString);
}


static const value_string ess_ESSPrivacyMark_vals[] = {
  {   0, "pString" },
  {   1, "utf8String" },
  { 0, NULL }
};

static const ber_choice_t ESSPrivacyMark_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_pString },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_UTF8String, BER_FLAGS_NOOWNTAG, dissect_utf8String },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_ess_ESSPrivacyMark(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ESSPrivacyMark_choice, hf_index, ett_ess_ESSPrivacyMark,
                                 NULL);

  return offset;
}
static int dissect_privacy_mark(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ess_ESSPrivacyMark(FALSE, tvb, offset, pinfo, tree, hf_ess_privacy_mark);
}



static int
dissect_ess_T_type(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, pinfo, tree, tvb, offset, hf_ess_SecurityCategory_type_OID, &object_identifier_id);

  return offset;
}
static int dissect_type_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ess_T_type(TRUE, tvb, offset, pinfo, tree, hf_ess_type);
}



static int
dissect_ess_T_value(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, pinfo, tree);


  return offset;
}
static int dissect_value(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ess_T_value(FALSE, tvb, offset, pinfo, tree, hf_ess_value);
}


static const ber_sequence_t SecurityCategory_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_type_impl },
  { BER_CLASS_CON, 1, 0, dissect_value },
  { 0, 0, 0, NULL }
};

static int
dissect_ess_SecurityCategory(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SecurityCategory_sequence, hf_index, ett_ess_SecurityCategory);

  return offset;
}
static int dissect_SecurityCategories_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ess_SecurityCategory(FALSE, tvb, offset, pinfo, tree, hf_ess_SecurityCategories_item);
}


static const ber_sequence_t SecurityCategories_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_SecurityCategories_item },
};

static int
dissect_ess_SecurityCategories(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SecurityCategories_set_of, hf_index, ett_ess_SecurityCategories);

  return offset;
}
static int dissect_security_categories(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ess_SecurityCategories(FALSE, tvb, offset, pinfo, tree, hf_ess_security_categories);
}


static const ber_sequence_t ESSSecurityLabel_set[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_security_policy_identifier },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_security_classification },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_privacy_mark },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_security_categories },
  { 0, 0, 0, NULL }
};

static int
dissect_ess_ESSSecurityLabel(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              ESSSecurityLabel_set, hf_index, ett_ess_ESSSecurityLabel);

  return offset;
}
static int dissect_EquivalentLabels_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ess_ESSSecurityLabel(FALSE, tvb, offset, pinfo, tree, hf_ess_EquivalentLabels_item);
}


static const ber_sequence_t EquivalentLabels_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_EquivalentLabels_item },
};

static int
dissect_ess_EquivalentLabels(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      EquivalentLabels_sequence_of, hf_index, ett_ess_EquivalentLabels);

  return offset;
}


static const value_string ess_EntityIdentifier_vals[] = {
  {   0, "issuerAndSerialNumber" },
  {   1, "subjectKeyIdentifier" },
  { 0, NULL }
};

static const ber_choice_t EntityIdentifier_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_issuerAndSerialNumber },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_subjectKeyIdentifier },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_ess_EntityIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 EntityIdentifier_choice, hf_index, ett_ess_EntityIdentifier,
                                 NULL);

  return offset;
}
static int dissect_mailListIdentifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ess_EntityIdentifier(FALSE, tvb, offset, pinfo, tree, hf_ess_mailListIdentifier);
}



static int
dissect_ess_GeneralizedTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_expansionTime(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ess_GeneralizedTime(FALSE, tvb, offset, pinfo, tree, hf_ess_expansionTime);
}



static int
dissect_ess_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_none_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ess_NULL(TRUE, tvb, offset, pinfo, tree, hf_ess_none);
}


static const value_string ess_MLReceiptPolicy_vals[] = {
  {   0, "none" },
  {   1, "insteadOf" },
  {   2, "inAdditionTo" },
  { 0, NULL }
};

static const ber_choice_t MLReceiptPolicy_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_none_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_insteadOf_impl },
  {   2, BER_CLASS_CON, 2, 0, dissect_inAdditionTo_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_ess_MLReceiptPolicy(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 MLReceiptPolicy_choice, hf_index, ett_ess_MLReceiptPolicy,
                                 NULL);

  return offset;
}
static int dissect_mlReceiptPolicy(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ess_MLReceiptPolicy(FALSE, tvb, offset, pinfo, tree, hf_ess_mlReceiptPolicy);
}


static const ber_sequence_t MLData_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mailListIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_expansionTime },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_mlReceiptPolicy },
  { 0, 0, 0, NULL }
};

static int
dissect_ess_MLData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   MLData_sequence, hf_index, ett_ess_MLData);

  return offset;
}
static int dissect_MLExpansionHistory_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ess_MLData(FALSE, tvb, offset, pinfo, tree, hf_ess_MLExpansionHistory_item);
}


static const ber_sequence_t MLExpansionHistory_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_MLExpansionHistory_item },
};

static int
dissect_ess_MLExpansionHistory(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      MLExpansionHistory_sequence_of, hf_index, ett_ess_MLExpansionHistory);

  return offset;
}



static int
dissect_ess_Hash(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_certHash(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ess_Hash(FALSE, tvb, offset, pinfo, tree, hf_ess_certHash);
}


static const ber_sequence_t IssuerSerial_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_issuer },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_serialNumber },
  { 0, 0, 0, NULL }
};

static int
dissect_ess_IssuerSerial(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   IssuerSerial_sequence, hf_index, ett_ess_IssuerSerial);

  return offset;
}
static int dissect_issuerSerial(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ess_IssuerSerial(FALSE, tvb, offset, pinfo, tree, hf_ess_issuerSerial);
}


static const ber_sequence_t ESSCertID_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_certHash },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_issuerSerial },
  { 0, 0, 0, NULL }
};

static int
dissect_ess_ESSCertID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ESSCertID_sequence, hf_index, ett_ess_ESSCertID);

  return offset;
}
static int dissect_certs_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ess_ESSCertID(FALSE, tvb, offset, pinfo, tree, hf_ess_certs_item);
}


static const ber_sequence_t SEQUENCE_OF_ESSCertID_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_certs_item },
};

static int
dissect_ess_SEQUENCE_OF_ESSCertID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_ESSCertID_sequence_of, hf_index, ett_ess_SEQUENCE_OF_ESSCertID);

  return offset;
}
static int dissect_certs(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ess_SEQUENCE_OF_ESSCertID(FALSE, tvb, offset, pinfo, tree, hf_ess_certs);
}


static const ber_sequence_t SEQUENCE_OF_PolicyInformation_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_policies_item },
};

static int
dissect_ess_SEQUENCE_OF_PolicyInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_PolicyInformation_sequence_of, hf_index, ett_ess_SEQUENCE_OF_PolicyInformation);

  return offset;
}
static int dissect_policies(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ess_SEQUENCE_OF_PolicyInformation(FALSE, tvb, offset, pinfo, tree, hf_ess_policies);
}


static const ber_sequence_t SigningCertificate_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_certs },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_policies },
  { 0, 0, 0, NULL }
};

static int
dissect_ess_SigningCertificate(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SigningCertificate_sequence, hf_index, ett_ess_SigningCertificate);

  return offset;
}

/*--- PDUs ---*/

static void dissect_ReceiptRequest_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_ess_ReceiptRequest(FALSE, tvb, 0, pinfo, tree, hf_ess_ReceiptRequest_PDU);
}
static void dissect_ContentIdentifier_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_ess_ContentIdentifier(FALSE, tvb, 0, pinfo, tree, hf_ess_ContentIdentifier_PDU);
}
static void dissect_Receipt_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_ess_Receipt(FALSE, tvb, 0, pinfo, tree, hf_ess_Receipt_PDU);
}
static void dissect_ContentHints_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_ess_ContentHints(FALSE, tvb, 0, pinfo, tree, hf_ess_ContentHints_PDU);
}
static void dissect_MsgSigDigest_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_ess_MsgSigDigest(FALSE, tvb, 0, pinfo, tree, hf_ess_MsgSigDigest_PDU);
}
static void dissect_ContentReference_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_ess_ContentReference(FALSE, tvb, 0, pinfo, tree, hf_ess_ContentReference_PDU);
}
static void dissect_ESSSecurityLabel_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_ess_ESSSecurityLabel(FALSE, tvb, 0, pinfo, tree, hf_ess_ESSSecurityLabel_PDU);
}
static void dissect_EquivalentLabels_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_ess_EquivalentLabels(FALSE, tvb, 0, pinfo, tree, hf_ess_EquivalentLabels_PDU);
}
static void dissect_MLExpansionHistory_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_ess_MLExpansionHistory(FALSE, tvb, 0, pinfo, tree, hf_ess_MLExpansionHistory_PDU);
}
static void dissect_SigningCertificate_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_ess_SigningCertificate(FALSE, tvb, 0, pinfo, tree, hf_ess_SigningCertificate_PDU);
}


/*--- End of included file: packet-ess-fn.c ---*/



/*--- proto_register_ess ----------------------------------------------*/
void proto_register_ess(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_ess_SecurityCategory_type_OID, 
      { "type", "ess.type_OID", FT_STRING, BASE_NONE, NULL, 0,
	"Type of Security Category", HFILL }},

/*--- Included file: packet-ess-hfarr.c ---*/

    { &hf_ess_ReceiptRequest_PDU,
      { "ReceiptRequest", "ess.ReceiptRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReceiptRequest", HFILL }},
    { &hf_ess_ContentIdentifier_PDU,
      { "ContentIdentifier", "ess.ContentIdentifier",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ContentIdentifier", HFILL }},
    { &hf_ess_Receipt_PDU,
      { "Receipt", "ess.Receipt",
        FT_NONE, BASE_NONE, NULL, 0,
        "Receipt", HFILL }},
    { &hf_ess_ContentHints_PDU,
      { "ContentHints", "ess.ContentHints",
        FT_NONE, BASE_NONE, NULL, 0,
        "ContentHints", HFILL }},
    { &hf_ess_MsgSigDigest_PDU,
      { "MsgSigDigest", "ess.MsgSigDigest",
        FT_BYTES, BASE_HEX, NULL, 0,
        "MsgSigDigest", HFILL }},
    { &hf_ess_ContentReference_PDU,
      { "ContentReference", "ess.ContentReference",
        FT_NONE, BASE_NONE, NULL, 0,
        "ContentReference", HFILL }},
    { &hf_ess_ESSSecurityLabel_PDU,
      { "ESSSecurityLabel", "ess.ESSSecurityLabel",
        FT_NONE, BASE_NONE, NULL, 0,
        "ESSSecurityLabel", HFILL }},
    { &hf_ess_EquivalentLabels_PDU,
      { "EquivalentLabels", "ess.EquivalentLabels",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EquivalentLabels", HFILL }},
    { &hf_ess_MLExpansionHistory_PDU,
      { "MLExpansionHistory", "ess.MLExpansionHistory",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MLExpansionHistory", HFILL }},
    { &hf_ess_SigningCertificate_PDU,
      { "SigningCertificate", "ess.SigningCertificate",
        FT_NONE, BASE_NONE, NULL, 0,
        "SigningCertificate", HFILL }},
    { &hf_ess_signedContentIdentifier,
      { "signedContentIdentifier", "ess.signedContentIdentifier",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_ess_receiptsFrom,
      { "receiptsFrom", "ess.receiptsFrom",
        FT_UINT32, BASE_DEC, VALS(ess_ReceiptsFrom_vals), 0,
        "ReceiptRequest/receiptsFrom", HFILL }},
    { &hf_ess_receiptsTo,
      { "receiptsTo", "ess.receiptsTo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ReceiptRequest/receiptsTo", HFILL }},
    { &hf_ess_receiptsTo_item,
      { "Item", "ess.receiptsTo_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ReceiptRequest/receiptsTo/_item", HFILL }},
    { &hf_ess_allOrFirstTier,
      { "allOrFirstTier", "ess.allOrFirstTier",
        FT_INT32, BASE_DEC, VALS(ess_AllOrFirstTier_vals), 0,
        "ReceiptsFrom/allOrFirstTier", HFILL }},
    { &hf_ess_receiptList,
      { "receiptList", "ess.receiptList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ReceiptsFrom/receiptList", HFILL }},
    { &hf_ess_receiptList_item,
      { "Item", "ess.receiptList_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ReceiptsFrom/receiptList/_item", HFILL }},
    { &hf_ess_version,
      { "version", "ess.version",
        FT_INT32, BASE_DEC, VALS(ess_ESSVersion_vals), 0,
        "Receipt/version", HFILL }},
    { &hf_ess_contentType,
      { "contentType", "ess.contentType",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_ess_originatorSignatureValue,
      { "originatorSignatureValue", "ess.originatorSignatureValue",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_ess_contentDescription,
      { "contentDescription", "ess.contentDescription",
        FT_STRING, BASE_NONE, NULL, 0,
        "ContentHints/contentDescription", HFILL }},
    { &hf_ess_security_policy_identifier,
      { "security-policy-identifier", "ess.security_policy_identifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "ESSSecurityLabel/security-policy-identifier", HFILL }},
    { &hf_ess_security_classification,
      { "security-classification", "ess.security_classification",
        FT_INT32, BASE_DEC, VALS(ess_SecurityClassification_vals), 0,
        "ESSSecurityLabel/security-classification", HFILL }},
    { &hf_ess_privacy_mark,
      { "privacy-mark", "ess.privacy_mark",
        FT_UINT32, BASE_DEC, VALS(ess_ESSPrivacyMark_vals), 0,
        "ESSSecurityLabel/privacy-mark", HFILL }},
    { &hf_ess_security_categories,
      { "security-categories", "ess.security_categories",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ESSSecurityLabel/security-categories", HFILL }},
    { &hf_ess_pString,
      { "pString", "ess.pString",
        FT_STRING, BASE_NONE, NULL, 0,
        "ESSPrivacyMark/pString", HFILL }},
    { &hf_ess_utf8String,
      { "utf8String", "ess.utf8String",
        FT_STRING, BASE_NONE, NULL, 0,
        "ESSPrivacyMark/utf8String", HFILL }},
    { &hf_ess_SecurityCategories_item,
      { "Item", "ess.SecurityCategories_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SecurityCategories/_item", HFILL }},
    { &hf_ess_type,
      { "type", "ess.type",
        FT_STRING, BASE_NONE, NULL, 0,
        "SecurityCategory/type", HFILL }},
    { &hf_ess_value,
      { "value", "ess.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "SecurityCategory/value", HFILL }},
    { &hf_ess_EquivalentLabels_item,
      { "Item", "ess.EquivalentLabels_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "EquivalentLabels/_item", HFILL }},
    { &hf_ess_MLExpansionHistory_item,
      { "Item", "ess.MLExpansionHistory_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "MLExpansionHistory/_item", HFILL }},
    { &hf_ess_mailListIdentifier,
      { "mailListIdentifier", "ess.mailListIdentifier",
        FT_UINT32, BASE_DEC, VALS(ess_EntityIdentifier_vals), 0,
        "MLData/mailListIdentifier", HFILL }},
    { &hf_ess_expansionTime,
      { "expansionTime", "ess.expansionTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "MLData/expansionTime", HFILL }},
    { &hf_ess_mlReceiptPolicy,
      { "mlReceiptPolicy", "ess.mlReceiptPolicy",
        FT_UINT32, BASE_DEC, VALS(ess_MLReceiptPolicy_vals), 0,
        "MLData/mlReceiptPolicy", HFILL }},
    { &hf_ess_issuerAndSerialNumber,
      { "issuerAndSerialNumber", "ess.issuerAndSerialNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        "EntityIdentifier/issuerAndSerialNumber", HFILL }},
    { &hf_ess_subjectKeyIdentifier,
      { "subjectKeyIdentifier", "ess.subjectKeyIdentifier",
        FT_BYTES, BASE_HEX, NULL, 0,
        "EntityIdentifier/subjectKeyIdentifier", HFILL }},
    { &hf_ess_none,
      { "none", "ess.none",
        FT_NONE, BASE_NONE, NULL, 0,
        "MLReceiptPolicy/none", HFILL }},
    { &hf_ess_insteadOf,
      { "insteadOf", "ess.insteadOf",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MLReceiptPolicy/insteadOf", HFILL }},
    { &hf_ess_insteadOf_item,
      { "Item", "ess.insteadOf_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MLReceiptPolicy/insteadOf/_item", HFILL }},
    { &hf_ess_inAdditionTo,
      { "inAdditionTo", "ess.inAdditionTo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MLReceiptPolicy/inAdditionTo", HFILL }},
    { &hf_ess_inAdditionTo_item,
      { "Item", "ess.inAdditionTo_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MLReceiptPolicy/inAdditionTo/_item", HFILL }},
    { &hf_ess_certs,
      { "certs", "ess.certs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SigningCertificate/certs", HFILL }},
    { &hf_ess_certs_item,
      { "Item", "ess.certs_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SigningCertificate/certs/_item", HFILL }},
    { &hf_ess_policies,
      { "policies", "ess.policies",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SigningCertificate/policies", HFILL }},
    { &hf_ess_policies_item,
      { "Item", "ess.policies_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SigningCertificate/policies/_item", HFILL }},
    { &hf_ess_certHash,
      { "certHash", "ess.certHash",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ESSCertID/certHash", HFILL }},
    { &hf_ess_issuerSerial,
      { "issuerSerial", "ess.issuerSerial",
        FT_NONE, BASE_NONE, NULL, 0,
        "ESSCertID/issuerSerial", HFILL }},
    { &hf_ess_issuer,
      { "issuer", "ess.issuer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "IssuerSerial/issuer", HFILL }},
    { &hf_ess_serialNumber,
      { "serialNumber", "ess.serialNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        "IssuerSerial/serialNumber", HFILL }},

/*--- End of included file: packet-ess-hfarr.c ---*/

  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-ess-ettarr.c ---*/

    &ett_ess_ReceiptRequest,
    &ett_ess_SEQUENCE_OF_GeneralNames,
    &ett_ess_ReceiptsFrom,
    &ett_ess_Receipt,
    &ett_ess_ContentHints,
    &ett_ess_ContentReference,
    &ett_ess_ESSSecurityLabel,
    &ett_ess_ESSPrivacyMark,
    &ett_ess_SecurityCategories,
    &ett_ess_SecurityCategory,
    &ett_ess_EquivalentLabels,
    &ett_ess_MLExpansionHistory,
    &ett_ess_MLData,
    &ett_ess_EntityIdentifier,
    &ett_ess_MLReceiptPolicy,
    &ett_ess_SigningCertificate,
    &ett_ess_SEQUENCE_OF_ESSCertID,
    &ett_ess_SEQUENCE_OF_PolicyInformation,
    &ett_ess_ESSCertID,
    &ett_ess_IssuerSerial,

/*--- End of included file: packet-ess-ettarr.c ---*/

  };

  /* Register protocol */
  proto_ess = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_ess, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_ess -------------------------------------------*/
void proto_reg_handoff_ess(void) {

/*--- Included file: packet-ess-dis-tab.c ---*/

  register_ber_oid_dissector("1.2.840.113549.1.9.16.2.1", dissect_ReceiptRequest_PDU, proto_ess, "id-aa-receiptRequest");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.2.7", dissect_ContentIdentifier_PDU, proto_ess, "id-aa-contentIdentifier");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.1.1", dissect_Receipt_PDU, proto_ess, "id-ct-receipt");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.2.4", dissect_ContentHints_PDU, proto_ess, "id-aa-contentHint");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.2.5", dissect_MsgSigDigest_PDU, proto_ess, "id-aa-msgSigDigest");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.2.10", dissect_ContentReference_PDU, proto_ess, "id-aa-contentReference");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.2.2", dissect_ESSSecurityLabel_PDU, proto_ess, "id-aa-securityLabel");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.2.9", dissect_EquivalentLabels_PDU, proto_ess, "id-aa-equivalentLabels");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.2.3", dissect_MLExpansionHistory_PDU, proto_ess, "id-aa-mlExpandHistory");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.2.12", dissect_SigningCertificate_PDU, proto_ess, "id-aa-signingCertificate");


/*--- End of included file: packet-ess-dis-tab.c ---*/

}

