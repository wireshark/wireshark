/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-ess.c                                                               */
/* ../../tools/asn2wrs.py -b -k -C -p ess -c ./ess.cnf -s ./packet-ess-template -D . -O ../../epan/dissectors ExtendedSecurityServices.asn */

/* Input file: packet-ess-template.c */

#line 1 "../../asn1/ess/packet-ess-template.c"
/* packet-ess.c
 * Routines for RFC5035 Extended Security Services packet dissection
 *   Ronnie Sahlberg 2004
 *   Stig Bjorlykke 2010
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <string.h>

#include <epan/packet.h>
#include <epan/asn1.h>
#include <epan/prefs.h>
#include <epan/uat.h>

#include "packet-ber.h"
#include "packet-ess.h"
#include "packet-cms.h"
#include "packet-x509ce.h"
#include "packet-x509af.h"

#define PNAME  "Extended Security Services"
#define PSNAME "ESS"
#define PFNAME "ess"

typedef struct _ess_category_attributes_t {
   char *oid;
   guint lacv;
   char *name;
} ess_category_attributes_t;

static ess_category_attributes_t *ess_category_attributes;
static guint num_ess_category_attributes;

/* Initialize the protocol and registered fields */
static int proto_ess = -1;
static int hf_ess_SecurityCategory_type_OID = -1;
static int hf_ess_Category_attribute = -1;

static gint ett_Category_attributes = -1;


/*--- Included file: packet-ess-hf.c ---*/
#line 1 "../../asn1/ess/packet-ess-hf.c"
static int hf_ess_ReceiptRequest_PDU = -1;        /* ReceiptRequest */
static int hf_ess_ContentIdentifier_PDU = -1;     /* ContentIdentifier */
static int hf_ess_Receipt_PDU = -1;               /* Receipt */
static int hf_ess_ContentHints_PDU = -1;          /* ContentHints */
static int hf_ess_MsgSigDigest_PDU = -1;          /* MsgSigDigest */
static int hf_ess_ContentReference_PDU = -1;      /* ContentReference */
static int hf_ess_ess_ESSSecurityLabel_PDU = -1;  /* ESSSecurityLabel */
static int hf_ess_RestrictiveTag_PDU = -1;        /* RestrictiveTag */
static int hf_ess_EnumeratedTag_PDU = -1;         /* EnumeratedTag */
static int hf_ess_PermissiveTag_PDU = -1;         /* PermissiveTag */
static int hf_ess_InformativeTag_PDU = -1;        /* InformativeTag */
static int hf_ess_EquivalentLabels_PDU = -1;      /* EquivalentLabels */
static int hf_ess_MLExpansionHistory_PDU = -1;    /* MLExpansionHistory */
static int hf_ess_SigningCertificate_PDU = -1;    /* SigningCertificate */
static int hf_ess_SigningCertificateV2_PDU = -1;  /* SigningCertificateV2 */
static int hf_ess_signedContentIdentifier = -1;   /* ContentIdentifier */
static int hf_ess_receiptsFrom = -1;              /* ReceiptsFrom */
static int hf_ess_receiptsTo = -1;                /* SEQUENCE_SIZE_1_ub_receiptsTo_OF_GeneralNames */
static int hf_ess_receiptsTo_item = -1;           /* GeneralNames */
static int hf_ess_allOrFirstTier = -1;            /* AllOrFirstTier */
static int hf_ess_receiptList = -1;               /* SEQUENCE_OF_GeneralNames */
static int hf_ess_receiptList_item = -1;          /* GeneralNames */
static int hf_ess_version = -1;                   /* ESSVersion */
static int hf_ess_contentType = -1;               /* ContentType */
static int hf_ess_originatorSignatureValue = -1;  /* OCTET_STRING */
static int hf_ess_contentDescription = -1;        /* UTF8String_SIZE_1_MAX */
static int hf_ess_security_policy_identifier = -1;  /* SecurityPolicyIdentifier */
static int hf_ess_security_classification = -1;   /* SecurityClassification */
static int hf_ess_privacy_mark = -1;              /* ESSPrivacyMark */
static int hf_ess_security_categories = -1;       /* SecurityCategories */
static int hf_ess_pString = -1;                   /* PrintableString_SIZE_1_ub_privacy_mark_length */
static int hf_ess_utf8String = -1;                /* UTF8String_SIZE_1_MAX */
static int hf_ess_SecurityCategories_item = -1;   /* SecurityCategory */
static int hf_ess_type = -1;                      /* T_type */
static int hf_ess_value = -1;                     /* T_value */
static int hf_ess_restrictiveTagName = -1;        /* T_restrictiveTagName */
static int hf_ess_restrictiveAttributeFlags = -1;  /* T_restrictiveAttributeFlags */
static int hf_ess_tagName = -1;                   /* T_tagName */
static int hf_ess_attributeList = -1;             /* SET_OF_SecurityAttribute */
static int hf_ess_attributeList_item = -1;        /* SecurityAttribute */
static int hf_ess_permissiveTagName = -1;         /* T_permissiveTagName */
static int hf_ess_permissiveAttributeFlags = -1;  /* T_permissiveAttributeFlags */
static int hf_ess_informativeTagName = -1;        /* T_informativeTagName */
static int hf_ess_attributes = -1;                /* FreeFormField */
static int hf_ess_informativeAttributeFlags = -1;  /* T_informativeAttributeFlags */
static int hf_ess_securityAttributes = -1;        /* SET_OF_SecurityAttribute */
static int hf_ess_securityAttributes_item = -1;   /* SecurityAttribute */
static int hf_ess_EquivalentLabels_item = -1;     /* ESSSecurityLabel */
static int hf_ess_MLExpansionHistory_item = -1;   /* MLData */
static int hf_ess_mailListIdentifier = -1;        /* EntityIdentifier */
static int hf_ess_expansionTime = -1;             /* GeneralizedTime */
static int hf_ess_mlReceiptPolicy = -1;           /* MLReceiptPolicy */
static int hf_ess_issuerAndSerialNumber = -1;     /* IssuerAndSerialNumber */
static int hf_ess_subjectKeyIdentifier = -1;      /* SubjectKeyIdentifier */
static int hf_ess_none = -1;                      /* NULL */
static int hf_ess_insteadOf = -1;                 /* SEQUENCE_SIZE_1_MAX_OF_GeneralNames */
static int hf_ess_insteadOf_item = -1;            /* GeneralNames */
static int hf_ess_inAdditionTo = -1;              /* SEQUENCE_SIZE_1_MAX_OF_GeneralNames */
static int hf_ess_inAdditionTo_item = -1;         /* GeneralNames */
static int hf_ess_certs = -1;                     /* SEQUENCE_OF_ESSCertID */
static int hf_ess_certs_item = -1;                /* ESSCertID */
static int hf_ess_policies = -1;                  /* SEQUENCE_OF_PolicyInformation */
static int hf_ess_policies_item = -1;             /* PolicyInformation */
static int hf_ess_certsV2 = -1;                   /* SEQUENCE_OF_ESSCertIDv2 */
static int hf_ess_certsV2_item = -1;              /* ESSCertIDv2 */
static int hf_ess_hashAlgorithm = -1;             /* AlgorithmIdentifier */
static int hf_ess_certHash = -1;                  /* Hash */
static int hf_ess_issuerSerial = -1;              /* IssuerSerial */
static int hf_ess_issuer = -1;                    /* GeneralNames */
static int hf_ess_serialNumber = -1;              /* CertificateSerialNumber */

/*--- End of included file: packet-ess-hf.c ---*/
#line 64 "../../asn1/ess/packet-ess-template.c"


/*--- Included file: packet-ess-val.h ---*/
#line 1 "../../asn1/ess/packet-ess-val.h"
#define ub_receiptsTo                  16
#define id_aa_receiptRequest           "1.2.840.113549.1.9.16.2.1"
#define id_aa_contentIdentifier        "1.2.840.113549.1.9.16.2.7"
#define id_ct_receipt                  "1.2.840.113549.1.9.16.1.1"
#define id_aa_contentHint              "1.2.840.113549.1.9.16.2.4"
#define id_aa_msgSigDigest             "1.2.840.113549.1.9.16.2.5"
#define id_aa_contentReference         "1.2.840.113549.1.9.16.2.10"
#define id_aa_securityLabel            "1.2.840.113549.1.9.16.2.2"
#define ub_integer_options             256
#define ub_privacy_mark_length         128
#define ub_security_categories         64
#define id_aa_equivalentLabels         "1.2.840.113549.1.9.16.2.9"
#define id_aa_mlExpandHistory          "1.2.840.113549.1.9.16.2.3"
#define ub_ml_expansion_history        64
#define id_aa_signingCertificate       "1.2.840.113549.1.9.16.2.12"
#define id_aa_signingCertificateV2     "1.2.840.113549.1.9.16.2.47"
#define id_sha256                      "2.16.840.1.101.3.4.2.1"

/*--- End of included file: packet-ess-val.h ---*/
#line 66 "../../asn1/ess/packet-ess-template.c"

/* Initialize the subtree pointers */

/*--- Included file: packet-ess-ett.c ---*/
#line 1 "../../asn1/ess/packet-ess-ett.c"
static gint ett_ess_ReceiptRequest = -1;
static gint ett_ess_SEQUENCE_SIZE_1_ub_receiptsTo_OF_GeneralNames = -1;
static gint ett_ess_ReceiptsFrom = -1;
static gint ett_ess_SEQUENCE_OF_GeneralNames = -1;
static gint ett_ess_Receipt = -1;
static gint ett_ess_ContentHints = -1;
static gint ett_ess_ContentReference = -1;
static gint ett_ess_ESSSecurityLabel = -1;
static gint ett_ess_ESSPrivacyMark = -1;
static gint ett_ess_SecurityCategories = -1;
static gint ett_ess_SecurityCategory = -1;
static gint ett_ess_RestrictiveTag = -1;
static gint ett_ess_EnumeratedTag = -1;
static gint ett_ess_SET_OF_SecurityAttribute = -1;
static gint ett_ess_PermissiveTag = -1;
static gint ett_ess_InformativeTag = -1;
static gint ett_ess_FreeFormField = -1;
static gint ett_ess_EquivalentLabels = -1;
static gint ett_ess_MLExpansionHistory = -1;
static gint ett_ess_MLData = -1;
static gint ett_ess_EntityIdentifier = -1;
static gint ett_ess_MLReceiptPolicy = -1;
static gint ett_ess_SEQUENCE_SIZE_1_MAX_OF_GeneralNames = -1;
static gint ett_ess_SigningCertificate = -1;
static gint ett_ess_SEQUENCE_OF_ESSCertID = -1;
static gint ett_ess_SEQUENCE_OF_PolicyInformation = -1;
static gint ett_ess_SigningCertificateV2 = -1;
static gint ett_ess_SEQUENCE_OF_ESSCertIDv2 = -1;
static gint ett_ess_ESSCertIDv2 = -1;
static gint ett_ess_ESSCertID = -1;
static gint ett_ess_IssuerSerial = -1;

/*--- End of included file: packet-ess-ett.c ---*/
#line 69 "../../asn1/ess/packet-ess-template.c"

static const char *object_identifier_id;

UAT_CSTRING_CB_DEF(ess_category_attributes, oid, ess_category_attributes_t);
UAT_DEC_CB_DEF(ess_category_attributes, lacv, ess_category_attributes_t);
UAT_CSTRING_CB_DEF(ess_category_attributes, name, ess_category_attributes_t);

static void *
ess_copy_cb(void *dest, const void *orig, size_t len _U_)
{
  ess_category_attributes_t *u = dest;
  const ess_category_attributes_t *o = orig;

  u->oid  = g_strdup(o->oid);
  u->lacv = o->lacv;
  u->name = g_strdup(o->name);

  return dest;
}

static void
ess_free_cb(void *r)
{
  ess_category_attributes_t *u = r;

  g_free(u->oid);
  g_free(u->name);
}

static void
ess_dissect_attribute (guint32 value, asn1_ctx_t *actx)
{
  guint i;
   
  for (i = 0; i < num_ess_category_attributes; i++) {
    ess_category_attributes_t *u = &(ess_category_attributes[i]);

    if ((strcmp (u->oid, object_identifier_id) == 0) &&
        (u->lacv == value))
    {
       proto_item_append_text (actx->created_item, " (%s)", u->name);
       break;
    }
  }
}

static void
ess_dissect_attribute_flags (tvbuff_t *tvb, asn1_ctx_t *actx)
{
  proto_tree *tree;
  guint8 *value;
  guint i;
   
  tree = proto_item_add_subtree (actx->created_item, ett_Category_attributes);
  value = tvb_get_ephemeral_string (tvb, 0, tvb_length (tvb));
  
  for (i = 0; i < num_ess_category_attributes; i++) {
    ess_category_attributes_t *u = &(ess_category_attributes[i]);

    if ((strcmp (u->oid, object_identifier_id) == 0) &&
        ((u->lacv / 8) < tvb_length (tvb)) &&
        (value[u->lacv / 8] & (1 << (7 - (u->lacv % 8)))))
    {
       proto_tree_add_string_format (tree, hf_ess_Category_attribute, tvb,
                                     u->lacv / 8, 1, u->name,
                                     "%s (%d)", u->name, u->lacv);
    }
  }
}


/*--- Included file: packet-ess-fn.c ---*/
#line 1 "../../asn1/ess/packet-ess-fn.c"


static int
dissect_ess_ContentIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string ess_AllOrFirstTier_vals[] = {
  {   0, "allReceipts" },
  {   1, "firstTierRecipients" },
  { 0, NULL }
};


static int
dissect_ess_AllOrFirstTier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_GeneralNames_sequence_of[1] = {
  { &hf_ess_receiptList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509ce_GeneralNames },
};

static int
dissect_ess_SEQUENCE_OF_GeneralNames(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_GeneralNames_sequence_of, hf_index, ett_ess_SEQUENCE_OF_GeneralNames);

  return offset;
}


static const value_string ess_ReceiptsFrom_vals[] = {
  {   0, "allOrFirstTier" },
  {   1, "receiptList" },
  { 0, NULL }
};

static const ber_choice_t ReceiptsFrom_choice[] = {
  {   0, &hf_ess_allOrFirstTier  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ess_AllOrFirstTier },
  {   1, &hf_ess_receiptList     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ess_SEQUENCE_OF_GeneralNames },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ess_ReceiptsFrom(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ReceiptsFrom_choice, hf_index, ett_ess_ReceiptsFrom,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_ub_receiptsTo_OF_GeneralNames_sequence_of[1] = {
  { &hf_ess_receiptsTo_item , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509ce_GeneralNames },
};

static int
dissect_ess_SEQUENCE_SIZE_1_ub_receiptsTo_OF_GeneralNames(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                                  1, ub_receiptsTo, SEQUENCE_SIZE_1_ub_receiptsTo_OF_GeneralNames_sequence_of, hf_index, ett_ess_SEQUENCE_SIZE_1_ub_receiptsTo_OF_GeneralNames);

  return offset;
}


static const ber_sequence_t ReceiptRequest_sequence[] = {
  { &hf_ess_signedContentIdentifier, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ess_ContentIdentifier },
  { &hf_ess_receiptsFrom    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ess_ReceiptsFrom },
  { &hf_ess_receiptsTo      , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ess_SEQUENCE_SIZE_1_ub_receiptsTo_OF_GeneralNames },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ess_ReceiptRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReceiptRequest_sequence, hf_index, ett_ess_ReceiptRequest);

  return offset;
}


static const value_string ess_ESSVersion_vals[] = {
  {   1, "v1" },
  { 0, NULL }
};


static int
dissect_ess_ESSVersion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ess_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t Receipt_sequence[] = {
  { &hf_ess_version         , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_ess_ESSVersion },
  { &hf_ess_contentType     , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cms_ContentType },
  { &hf_ess_signedContentIdentifier, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ess_ContentIdentifier },
  { &hf_ess_originatorSignatureValue, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ess_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ess_Receipt(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 102 "../../asn1/ess/ess.cnf"
  col_set_str(actx->pinfo->cinfo, COL_PROTOCOL, "ESS");
  col_set_str(actx->pinfo->cinfo, COL_INFO, "Signed Receipt");
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Receipt_sequence, hf_index, ett_ess_Receipt);




  return offset;
}



static int
dissect_ess_UTF8String_SIZE_1_MAX(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                                        actx, tree, tvb, offset,
                                                        1, NO_BOUND, hf_index, NULL);

  return offset;
}


static const ber_sequence_t ContentHints_sequence[] = {
  { &hf_ess_contentDescription, BER_CLASS_UNI, BER_UNI_TAG_UTF8String, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ess_UTF8String_SIZE_1_MAX },
  { &hf_ess_contentType     , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cms_ContentType },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ess_ContentHints(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ContentHints_sequence, hf_index, ett_ess_ContentHints);

  return offset;
}



static int
dissect_ess_MsgSigDigest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t ContentReference_sequence[] = {
  { &hf_ess_contentType     , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cms_ContentType },
  { &hf_ess_signedContentIdentifier, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ess_ContentIdentifier },
  { &hf_ess_originatorSignatureValue, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ess_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ess_ContentReference(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ContentReference_sequence, hf_index, ett_ess_ContentReference);

  return offset;
}



static int
dissect_ess_SecurityPolicyIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
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
dissect_ess_SecurityClassification(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_integer(implicit_tag, actx, tree, tvb, offset,
                                                            0U, ub_integer_options, hf_index, NULL);

  return offset;
}



static int
dissect_ess_PrintableString_SIZE_1_ub_privacy_mark_length(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                                        actx, tree, tvb, offset,
                                                        1, ub_privacy_mark_length, hf_index, NULL);

  return offset;
}


static const value_string ess_ESSPrivacyMark_vals[] = {
  {   0, "pString" },
  {   1, "utf8String" },
  { 0, NULL }
};

static const ber_choice_t ESSPrivacyMark_choice[] = {
  {   0, &hf_ess_pString         , BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_ess_PrintableString_SIZE_1_ub_privacy_mark_length },
  {   1, &hf_ess_utf8String      , BER_CLASS_UNI, BER_UNI_TAG_UTF8String, BER_FLAGS_NOOWNTAG, dissect_ess_UTF8String_SIZE_1_MAX },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ess_ESSPrivacyMark(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ESSPrivacyMark_choice, hf_index, ett_ess_ESSPrivacyMark,
                                 NULL);

  return offset;
}



static int
dissect_ess_T_type(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_ess_SecurityCategory_type_OID, &object_identifier_id);

  return offset;
}



static int
dissect_ess_T_value(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 51 "../../asn1/ess/ess.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);



  return offset;
}


static const ber_sequence_t SecurityCategory_sequence[] = {
  { &hf_ess_type            , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ess_T_type },
  { &hf_ess_value           , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ess_T_value },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ess_SecurityCategory(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SecurityCategory_sequence, hf_index, ett_ess_SecurityCategory);

  return offset;
}


static const ber_sequence_t SecurityCategories_set_of[1] = {
  { &hf_ess_SecurityCategories_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ess_SecurityCategory },
};

static int
dissect_ess_SecurityCategories(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_set_of(implicit_tag, actx, tree, tvb, offset,
                                             1, ub_security_categories, SecurityCategories_set_of, hf_index, ett_ess_SecurityCategories);

  return offset;
}


static const ber_sequence_t ESSSecurityLabel_set[] = {
  { &hf_ess_security_policy_identifier, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_ess_SecurityPolicyIdentifier },
  { &hf_ess_security_classification, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ess_SecurityClassification },
  { &hf_ess_privacy_mark    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ess_ESSPrivacyMark },
  { &hf_ess_security_categories, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ess_SecurityCategories },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ess_ESSSecurityLabel(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              ESSSecurityLabel_set, hf_index, ett_ess_ESSSecurityLabel);

  return offset;
}



static int
dissect_ess_T_restrictiveTagName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &object_identifier_id);

  return offset;
}



static int
dissect_ess_T_restrictiveAttributeFlags(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 78 "../../asn1/ess/ess.cnf"
  tvbuff_t *attributes;
  
    offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    &attributes);

  ess_dissect_attribute_flags (attributes, actx);
  


  return offset;
}


static const ber_sequence_t RestrictiveTag_sequence[] = {
  { &hf_ess_restrictiveTagName, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_ess_T_restrictiveTagName },
  { &hf_ess_restrictiveAttributeFlags, BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_ess_T_restrictiveAttributeFlags },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ess_RestrictiveTag(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RestrictiveTag_sequence, hf_index, ett_ess_RestrictiveTag);

  return offset;
}



static int
dissect_ess_T_tagName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &object_identifier_id);

  return offset;
}



static int
dissect_ess_SecurityAttribute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 69 "../../asn1/ess/ess.cnf"
  guint32 attribute;
  
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &attribute);

  ess_dissect_attribute (attribute, actx);
  


  return offset;
}


static const ber_sequence_t SET_OF_SecurityAttribute_set_of[1] = {
  { &hf_ess_attributeList_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_ess_SecurityAttribute },
};

static int
dissect_ess_SET_OF_SecurityAttribute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_SecurityAttribute_set_of, hf_index, ett_ess_SET_OF_SecurityAttribute);

  return offset;
}


static const ber_sequence_t EnumeratedTag_sequence[] = {
  { &hf_ess_tagName         , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_ess_T_tagName },
  { &hf_ess_attributeList   , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_ess_SET_OF_SecurityAttribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ess_EnumeratedTag(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EnumeratedTag_sequence, hf_index, ett_ess_EnumeratedTag);

  return offset;
}



static int
dissect_ess_T_permissiveTagName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &object_identifier_id);

  return offset;
}



static int
dissect_ess_T_permissiveAttributeFlags(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 87 "../../asn1/ess/ess.cnf"
  tvbuff_t *attributes;
  
    offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    &attributes);

  ess_dissect_attribute_flags (attributes, actx);
  


  return offset;
}


static const ber_sequence_t PermissiveTag_sequence[] = {
  { &hf_ess_permissiveTagName, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_ess_T_permissiveTagName },
  { &hf_ess_permissiveAttributeFlags, BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_ess_T_permissiveAttributeFlags },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ess_PermissiveTag(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PermissiveTag_sequence, hf_index, ett_ess_PermissiveTag);

  return offset;
}



static int
dissect_ess_T_informativeTagName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &object_identifier_id);

  return offset;
}



static int
dissect_ess_T_informativeAttributeFlags(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 96 "../../asn1/ess/ess.cnf"
  tvbuff_t *attributes;
  
    offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    &attributes);

  ess_dissect_attribute_flags (attributes, actx);
  


  return offset;
}


static const value_string ess_FreeFormField_vals[] = {
  {   0, "bitSetAttributes" },
  {   1, "securityAttributes" },
  { 0, NULL }
};

static const ber_choice_t FreeFormField_choice[] = {
  {   0, &hf_ess_informativeAttributeFlags, BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_ess_T_informativeAttributeFlags },
  {   1, &hf_ess_securityAttributes, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_ess_SET_OF_SecurityAttribute },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ess_FreeFormField(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 FreeFormField_choice, hf_index, ett_ess_FreeFormField,
                                 NULL);

  return offset;
}


static const ber_sequence_t InformativeTag_sequence[] = {
  { &hf_ess_informativeTagName, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_ess_T_informativeTagName },
  { &hf_ess_attributes      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ess_FreeFormField },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ess_InformativeTag(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InformativeTag_sequence, hf_index, ett_ess_InformativeTag);

  return offset;
}


static const ber_sequence_t EquivalentLabels_sequence_of[1] = {
  { &hf_ess_EquivalentLabels_item, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_ess_ESSSecurityLabel },
};

static int
dissect_ess_EquivalentLabels(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      EquivalentLabels_sequence_of, hf_index, ett_ess_EquivalentLabels);

  return offset;
}


static const value_string ess_EntityIdentifier_vals[] = {
  {   0, "issuerAndSerialNumber" },
  {   1, "subjectKeyIdentifier" },
  { 0, NULL }
};

static const ber_choice_t EntityIdentifier_choice[] = {
  {   0, &hf_ess_issuerAndSerialNumber, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_IssuerAndSerialNumber },
  {   1, &hf_ess_subjectKeyIdentifier, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_x509ce_SubjectKeyIdentifier },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ess_EntityIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 EntityIdentifier_choice, hf_index, ett_ess_EntityIdentifier,
                                 NULL);

  return offset;
}



static int
dissect_ess_GeneralizedTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_ess_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_GeneralNames_sequence_of[1] = {
  { &hf_ess_insteadOf_item  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509ce_GeneralNames },
};

static int
dissect_ess_SEQUENCE_SIZE_1_MAX_OF_GeneralNames(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                                  1, NO_BOUND, SEQUENCE_SIZE_1_MAX_OF_GeneralNames_sequence_of, hf_index, ett_ess_SEQUENCE_SIZE_1_MAX_OF_GeneralNames);

  return offset;
}


static const value_string ess_MLReceiptPolicy_vals[] = {
  {   0, "none" },
  {   1, "insteadOf" },
  {   2, "inAdditionTo" },
  { 0, NULL }
};

static const ber_choice_t MLReceiptPolicy_choice[] = {
  {   0, &hf_ess_none            , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ess_NULL },
  {   1, &hf_ess_insteadOf       , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ess_SEQUENCE_SIZE_1_MAX_OF_GeneralNames },
  {   2, &hf_ess_inAdditionTo    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ess_SEQUENCE_SIZE_1_MAX_OF_GeneralNames },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ess_MLReceiptPolicy(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 MLReceiptPolicy_choice, hf_index, ett_ess_MLReceiptPolicy,
                                 NULL);

  return offset;
}


static const ber_sequence_t MLData_sequence[] = {
  { &hf_ess_mailListIdentifier, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ess_EntityIdentifier },
  { &hf_ess_expansionTime   , BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_ess_GeneralizedTime },
  { &hf_ess_mlReceiptPolicy , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ess_MLReceiptPolicy },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ess_MLData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MLData_sequence, hf_index, ett_ess_MLData);

  return offset;
}


static const ber_sequence_t MLExpansionHistory_sequence_of[1] = {
  { &hf_ess_MLExpansionHistory_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ess_MLData },
};

static int
dissect_ess_MLExpansionHistory(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                                  1, ub_ml_expansion_history, MLExpansionHistory_sequence_of, hf_index, ett_ess_MLExpansionHistory);

  return offset;
}



static int
dissect_ess_Hash(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t IssuerSerial_sequence[] = {
  { &hf_ess_issuer          , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509ce_GeneralNames },
  { &hf_ess_serialNumber    , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_x509af_CertificateSerialNumber },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ess_IssuerSerial(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IssuerSerial_sequence, hf_index, ett_ess_IssuerSerial);

  return offset;
}


static const ber_sequence_t ESSCertID_sequence[] = {
  { &hf_ess_certHash        , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ess_Hash },
  { &hf_ess_issuerSerial    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ess_IssuerSerial },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ess_ESSCertID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ESSCertID_sequence, hf_index, ett_ess_ESSCertID);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ESSCertID_sequence_of[1] = {
  { &hf_ess_certs_item      , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ess_ESSCertID },
};

static int
dissect_ess_SEQUENCE_OF_ESSCertID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ESSCertID_sequence_of, hf_index, ett_ess_SEQUENCE_OF_ESSCertID);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_PolicyInformation_sequence_of[1] = {
  { &hf_ess_policies_item   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509ce_PolicyInformation },
};

static int
dissect_ess_SEQUENCE_OF_PolicyInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_PolicyInformation_sequence_of, hf_index, ett_ess_SEQUENCE_OF_PolicyInformation);

  return offset;
}


static const ber_sequence_t SigningCertificate_sequence[] = {
  { &hf_ess_certs           , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ess_SEQUENCE_OF_ESSCertID },
  { &hf_ess_policies        , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ess_SEQUENCE_OF_PolicyInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ess_SigningCertificate(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SigningCertificate_sequence, hf_index, ett_ess_SigningCertificate);

  return offset;
}


static const ber_sequence_t ESSCertIDv2_sequence[] = {
  { &hf_ess_hashAlgorithm   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_ess_certHash        , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ess_Hash },
  { &hf_ess_issuerSerial    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ess_IssuerSerial },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ess_ESSCertIDv2(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ESSCertIDv2_sequence, hf_index, ett_ess_ESSCertIDv2);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ESSCertIDv2_sequence_of[1] = {
  { &hf_ess_certsV2_item    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ess_ESSCertIDv2 },
};

static int
dissect_ess_SEQUENCE_OF_ESSCertIDv2(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ESSCertIDv2_sequence_of, hf_index, ett_ess_SEQUENCE_OF_ESSCertIDv2);

  return offset;
}


static const ber_sequence_t SigningCertificateV2_sequence[] = {
  { &hf_ess_certsV2         , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ess_SEQUENCE_OF_ESSCertIDv2 },
  { &hf_ess_policies        , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ess_SEQUENCE_OF_PolicyInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ess_SigningCertificateV2(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SigningCertificateV2_sequence, hf_index, ett_ess_SigningCertificateV2);

  return offset;
}

/*--- PDUs ---*/

static void dissect_ReceiptRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_ess_ReceiptRequest(FALSE, tvb, 0, &asn1_ctx, tree, hf_ess_ReceiptRequest_PDU);
}
static void dissect_ContentIdentifier_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_ess_ContentIdentifier(FALSE, tvb, 0, &asn1_ctx, tree, hf_ess_ContentIdentifier_PDU);
}
static void dissect_Receipt_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_ess_Receipt(FALSE, tvb, 0, &asn1_ctx, tree, hf_ess_Receipt_PDU);
}
static void dissect_ContentHints_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_ess_ContentHints(FALSE, tvb, 0, &asn1_ctx, tree, hf_ess_ContentHints_PDU);
}
static void dissect_MsgSigDigest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_ess_MsgSigDigest(FALSE, tvb, 0, &asn1_ctx, tree, hf_ess_MsgSigDigest_PDU);
}
static void dissect_ContentReference_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_ess_ContentReference(FALSE, tvb, 0, &asn1_ctx, tree, hf_ess_ContentReference_PDU);
}
void dissect_ess_ESSSecurityLabel_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_ess_ESSSecurityLabel(FALSE, tvb, 0, &asn1_ctx, tree, hf_ess_ess_ESSSecurityLabel_PDU);
}
static void dissect_RestrictiveTag_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_ess_RestrictiveTag(FALSE, tvb, 0, &asn1_ctx, tree, hf_ess_RestrictiveTag_PDU);
}
static void dissect_EnumeratedTag_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_ess_EnumeratedTag(FALSE, tvb, 0, &asn1_ctx, tree, hf_ess_EnumeratedTag_PDU);
}
static void dissect_PermissiveTag_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_ess_PermissiveTag(FALSE, tvb, 0, &asn1_ctx, tree, hf_ess_PermissiveTag_PDU);
}
static void dissect_InformativeTag_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_ess_InformativeTag(FALSE, tvb, 0, &asn1_ctx, tree, hf_ess_InformativeTag_PDU);
}
static void dissect_EquivalentLabels_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_ess_EquivalentLabels(FALSE, tvb, 0, &asn1_ctx, tree, hf_ess_EquivalentLabels_PDU);
}
static void dissect_MLExpansionHistory_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_ess_MLExpansionHistory(FALSE, tvb, 0, &asn1_ctx, tree, hf_ess_MLExpansionHistory_PDU);
}
static void dissect_SigningCertificate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_ess_SigningCertificate(FALSE, tvb, 0, &asn1_ctx, tree, hf_ess_SigningCertificate_PDU);
}
static void dissect_SigningCertificateV2_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_ess_SigningCertificateV2(FALSE, tvb, 0, &asn1_ctx, tree, hf_ess_SigningCertificateV2_PDU);
}


/*--- End of included file: packet-ess-fn.c ---*/
#line 140 "../../asn1/ess/packet-ess-template.c"

/*--- proto_register_ess ----------------------------------------------*/
void proto_register_ess(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_ess_SecurityCategory_type_OID, 
      { "type", "ess.type_OID", FT_STRING, BASE_NONE, NULL, 0,
	"Type of Security Category", HFILL }},
    { &hf_ess_Category_attribute, 
      { "Attribute", "ess.attribute", FT_STRING, BASE_NONE, NULL, 0,
	NULL, HFILL }},

/*--- Included file: packet-ess-hfarr.c ---*/
#line 1 "../../asn1/ess/packet-ess-hfarr.c"
    { &hf_ess_ReceiptRequest_PDU,
      { "ReceiptRequest", "ess.ReceiptRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ess_ContentIdentifier_PDU,
      { "ContentIdentifier", "ess.ContentIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ess_Receipt_PDU,
      { "Receipt", "ess.Receipt",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ess_ContentHints_PDU,
      { "ContentHints", "ess.ContentHints",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ess_MsgSigDigest_PDU,
      { "MsgSigDigest", "ess.MsgSigDigest",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ess_ContentReference_PDU,
      { "ContentReference", "ess.ContentReference",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ess_ess_ESSSecurityLabel_PDU,
      { "ESSSecurityLabel", "ess.ESSSecurityLabel",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ess_RestrictiveTag_PDU,
      { "RestrictiveTag", "ess.RestrictiveTag",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ess_EnumeratedTag_PDU,
      { "EnumeratedTag", "ess.EnumeratedTag",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ess_PermissiveTag_PDU,
      { "PermissiveTag", "ess.PermissiveTag",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ess_InformativeTag_PDU,
      { "InformativeTag", "ess.InformativeTag",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ess_EquivalentLabels_PDU,
      { "EquivalentLabels", "ess.EquivalentLabels",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ess_MLExpansionHistory_PDU,
      { "MLExpansionHistory", "ess.MLExpansionHistory",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ess_SigningCertificate_PDU,
      { "SigningCertificate", "ess.SigningCertificate",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ess_SigningCertificateV2_PDU,
      { "SigningCertificateV2", "ess.SigningCertificateV2",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ess_signedContentIdentifier,
      { "signedContentIdentifier", "ess.signedContentIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "ContentIdentifier", HFILL }},
    { &hf_ess_receiptsFrom,
      { "receiptsFrom", "ess.receiptsFrom",
        FT_UINT32, BASE_DEC, VALS(ess_ReceiptsFrom_vals), 0,
        NULL, HFILL }},
    { &hf_ess_receiptsTo,
      { "receiptsTo", "ess.receiptsTo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_ub_receiptsTo_OF_GeneralNames", HFILL }},
    { &hf_ess_receiptsTo_item,
      { "GeneralNames", "ess.GeneralNames",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ess_allOrFirstTier,
      { "allOrFirstTier", "ess.allOrFirstTier",
        FT_INT32, BASE_DEC, VALS(ess_AllOrFirstTier_vals), 0,
        NULL, HFILL }},
    { &hf_ess_receiptList,
      { "receiptList", "ess.receiptList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_GeneralNames", HFILL }},
    { &hf_ess_receiptList_item,
      { "GeneralNames", "ess.GeneralNames",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ess_version,
      { "version", "ess.version",
        FT_INT32, BASE_DEC, VALS(ess_ESSVersion_vals), 0,
        "ESSVersion", HFILL }},
    { &hf_ess_contentType,
      { "contentType", "ess.contentType",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ess_originatorSignatureValue,
      { "originatorSignatureValue", "ess.originatorSignatureValue",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_ess_contentDescription,
      { "contentDescription", "ess.contentDescription",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String_SIZE_1_MAX", HFILL }},
    { &hf_ess_security_policy_identifier,
      { "security-policy-identifier", "ess.security_policy_identifier",
        FT_OID, BASE_NONE, NULL, 0,
        "SecurityPolicyIdentifier", HFILL }},
    { &hf_ess_security_classification,
      { "security-classification", "ess.security_classification",
        FT_UINT32, BASE_DEC, VALS(ess_SecurityClassification_vals), 0,
        "SecurityClassification", HFILL }},
    { &hf_ess_privacy_mark,
      { "privacy-mark", "ess.privacy_mark",
        FT_UINT32, BASE_DEC, VALS(ess_ESSPrivacyMark_vals), 0,
        "ESSPrivacyMark", HFILL }},
    { &hf_ess_security_categories,
      { "security-categories", "ess.security_categories",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SecurityCategories", HFILL }},
    { &hf_ess_pString,
      { "pString", "ess.pString",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString_SIZE_1_ub_privacy_mark_length", HFILL }},
    { &hf_ess_utf8String,
      { "utf8String", "ess.utf8String",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String_SIZE_1_MAX", HFILL }},
    { &hf_ess_SecurityCategories_item,
      { "SecurityCategory", "ess.SecurityCategory",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ess_type,
      { "type", "ess.type",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ess_value,
      { "value", "ess.value",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ess_restrictiveTagName,
      { "tagName", "ess.tagName",
        FT_OID, BASE_NONE, NULL, 0,
        "T_restrictiveTagName", HFILL }},
    { &hf_ess_restrictiveAttributeFlags,
      { "attributeFlags", "ess.attributeFlags",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_restrictiveAttributeFlags", HFILL }},
    { &hf_ess_tagName,
      { "tagName", "ess.tagName",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ess_attributeList,
      { "attributeList", "ess.attributeList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_SecurityAttribute", HFILL }},
    { &hf_ess_attributeList_item,
      { "SecurityAttribute", "ess.SecurityAttribute",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ess_permissiveTagName,
      { "tagName", "ess.tagName",
        FT_OID, BASE_NONE, NULL, 0,
        "T_permissiveTagName", HFILL }},
    { &hf_ess_permissiveAttributeFlags,
      { "attributeFlags", "ess.attributeFlags",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_permissiveAttributeFlags", HFILL }},
    { &hf_ess_informativeTagName,
      { "tagName", "ess.tagName",
        FT_OID, BASE_NONE, NULL, 0,
        "T_informativeTagName", HFILL }},
    { &hf_ess_attributes,
      { "attributes", "ess.attributes",
        FT_UINT32, BASE_DEC, VALS(ess_FreeFormField_vals), 0,
        "FreeFormField", HFILL }},
    { &hf_ess_informativeAttributeFlags,
      { "bitSetAttributes", "ess.bitSetAttributes",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_informativeAttributeFlags", HFILL }},
    { &hf_ess_securityAttributes,
      { "securityAttributes", "ess.securityAttributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_SecurityAttribute", HFILL }},
    { &hf_ess_securityAttributes_item,
      { "SecurityAttribute", "ess.SecurityAttribute",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ess_EquivalentLabels_item,
      { "ESSSecurityLabel", "ess.ESSSecurityLabel",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ess_MLExpansionHistory_item,
      { "MLData", "ess.MLData",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ess_mailListIdentifier,
      { "mailListIdentifier", "ess.mailListIdentifier",
        FT_UINT32, BASE_DEC, VALS(ess_EntityIdentifier_vals), 0,
        "EntityIdentifier", HFILL }},
    { &hf_ess_expansionTime,
      { "expansionTime", "ess.expansionTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_ess_mlReceiptPolicy,
      { "mlReceiptPolicy", "ess.mlReceiptPolicy",
        FT_UINT32, BASE_DEC, VALS(ess_MLReceiptPolicy_vals), 0,
        NULL, HFILL }},
    { &hf_ess_issuerAndSerialNumber,
      { "issuerAndSerialNumber", "ess.issuerAndSerialNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ess_subjectKeyIdentifier,
      { "subjectKeyIdentifier", "ess.subjectKeyIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ess_none,
      { "none", "ess.none",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ess_insteadOf,
      { "insteadOf", "ess.insteadOf",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_GeneralNames", HFILL }},
    { &hf_ess_insteadOf_item,
      { "GeneralNames", "ess.GeneralNames",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ess_inAdditionTo,
      { "inAdditionTo", "ess.inAdditionTo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_GeneralNames", HFILL }},
    { &hf_ess_inAdditionTo_item,
      { "GeneralNames", "ess.GeneralNames",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ess_certs,
      { "certs", "ess.certs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ESSCertID", HFILL }},
    { &hf_ess_certs_item,
      { "ESSCertID", "ess.ESSCertID",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ess_policies,
      { "policies", "ess.policies",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_PolicyInformation", HFILL }},
    { &hf_ess_policies_item,
      { "PolicyInformation", "ess.PolicyInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ess_certsV2,
      { "certs", "ess.certs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ESSCertIDv2", HFILL }},
    { &hf_ess_certsV2_item,
      { "ESSCertIDv2", "ess.ESSCertIDv2",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ess_hashAlgorithm,
      { "hashAlgorithm", "ess.hashAlgorithm",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_ess_certHash,
      { "certHash", "ess.certHash",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Hash", HFILL }},
    { &hf_ess_issuerSerial,
      { "issuerSerial", "ess.issuerSerial",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ess_issuer,
      { "issuer", "ess.issuer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GeneralNames", HFILL }},
    { &hf_ess_serialNumber,
      { "serialNumber", "ess.serialNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        "CertificateSerialNumber", HFILL }},

/*--- End of included file: packet-ess-hfarr.c ---*/
#line 153 "../../asn1/ess/packet-ess-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
     &ett_Category_attributes,

/*--- Included file: packet-ess-ettarr.c ---*/
#line 1 "../../asn1/ess/packet-ess-ettarr.c"
    &ett_ess_ReceiptRequest,
    &ett_ess_SEQUENCE_SIZE_1_ub_receiptsTo_OF_GeneralNames,
    &ett_ess_ReceiptsFrom,
    &ett_ess_SEQUENCE_OF_GeneralNames,
    &ett_ess_Receipt,
    &ett_ess_ContentHints,
    &ett_ess_ContentReference,
    &ett_ess_ESSSecurityLabel,
    &ett_ess_ESSPrivacyMark,
    &ett_ess_SecurityCategories,
    &ett_ess_SecurityCategory,
    &ett_ess_RestrictiveTag,
    &ett_ess_EnumeratedTag,
    &ett_ess_SET_OF_SecurityAttribute,
    &ett_ess_PermissiveTag,
    &ett_ess_InformativeTag,
    &ett_ess_FreeFormField,
    &ett_ess_EquivalentLabels,
    &ett_ess_MLExpansionHistory,
    &ett_ess_MLData,
    &ett_ess_EntityIdentifier,
    &ett_ess_MLReceiptPolicy,
    &ett_ess_SEQUENCE_SIZE_1_MAX_OF_GeneralNames,
    &ett_ess_SigningCertificate,
    &ett_ess_SEQUENCE_OF_ESSCertID,
    &ett_ess_SEQUENCE_OF_PolicyInformation,
    &ett_ess_SigningCertificateV2,
    &ett_ess_SEQUENCE_OF_ESSCertIDv2,
    &ett_ess_ESSCertIDv2,
    &ett_ess_ESSCertID,
    &ett_ess_IssuerSerial,

/*--- End of included file: packet-ess-ettarr.c ---*/
#line 159 "../../asn1/ess/packet-ess-template.c"
  };
  
  static uat_field_t attributes_flds[] = {
    UAT_FLD_CSTRING(ess_category_attributes,oid, "Tag Set", "Category Tag Set (Object Identifier)"),
    UAT_FLD_DEC(ess_category_attributes,lacv, "Value", "Label And Cert Value"),
    UAT_FLD_CSTRING(ess_category_attributes,name, "Name", "Category Name"),
    UAT_END_FIELDS
  };

  uat_t *attributes_uat = uat_new("ESS Category Attributes",
                                  sizeof(ess_category_attributes_t),
                                  "ess_category_attributes",
                                  TRUE,
                                  (void*) &ess_category_attributes,
                                  &num_ess_category_attributes,
                                  UAT_AFFECTS_DISSECTION, /* affects dissection of packets, but not set of named fields */
                                  "ChEssCategoryAttributes",
                                  ess_copy_cb,
                                  NULL,
                                  ess_free_cb,
                                  NULL,
                                  attributes_flds);

  static module_t *ess_module;

  /* Register protocol */
  proto_ess = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_ess, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  
  ess_module = prefs_register_protocol(proto_ess, NULL);

  prefs_register_uat_preference(ess_module, "attributes_table",
                                "ESS Category Attributes",
                                "ESS category attributes translation table",
                                attributes_uat);

}


/*--- proto_reg_handoff_ess -------------------------------------------*/
void proto_reg_handoff_ess(void) {

/*--- Included file: packet-ess-dis-tab.c ---*/
#line 1 "../../asn1/ess/packet-ess-dis-tab.c"
  register_ber_oid_dissector("1.2.840.113549.1.9.16.2.1", dissect_ReceiptRequest_PDU, proto_ess, "id-aa-receiptRequest");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.2.7", dissect_ContentIdentifier_PDU, proto_ess, "id-aa-contentIdentifier");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.1.1", dissect_Receipt_PDU, proto_ess, "id-ct-receipt");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.2.4", dissect_ContentHints_PDU, proto_ess, "id-aa-contentHint");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.2.5", dissect_MsgSigDigest_PDU, proto_ess, "id-aa-msgSigDigest");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.2.10", dissect_ContentReference_PDU, proto_ess, "id-aa-contentReference");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.2.2", dissect_ess_ESSSecurityLabel_PDU, proto_ess, "id-aa-securityLabel");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.2.9", dissect_EquivalentLabels_PDU, proto_ess, "id-aa-equivalentLabels");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.2.3", dissect_MLExpansionHistory_PDU, proto_ess, "id-aa-mlExpandHistory");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.2.12", dissect_SigningCertificate_PDU, proto_ess, "id-aa-signingCertificate");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.2.47", dissect_SigningCertificateV2_PDU, proto_ess, "id-aa-signingCertificateV2");
  register_ber_oid_dissector("2.16.840.1.101.2.1.8.3.0", dissect_RestrictiveTag_PDU, proto_ess, "id-restrictiveAttributes");
  register_ber_oid_dissector("2.16.840.1.101.2.1.8.3.1", dissect_EnumeratedTag_PDU, proto_ess, "id-enumeratedPermissiveAttributes");
  register_ber_oid_dissector("2.16.840.1.101.2.1.8.3.2", dissect_PermissiveTag_PDU, proto_ess, "id-permissiveAttributes");
  register_ber_oid_dissector("2.16.840.1.101.2.1.8.3.3", dissect_InformativeTag_PDU, proto_ess, "id-informativeAttributes");
  register_ber_oid_dissector("2.16.840.1.101.2.1.8.3.4", dissect_EnumeratedTag_PDU, proto_ess, "id-enumeratedRestrictiveAttributes");


/*--- End of included file: packet-ess-dis-tab.c ---*/
#line 204 "../../asn1/ess/packet-ess-template.c"
}

