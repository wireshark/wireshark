/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* packet-cms.c                                                               */
/* ../../tools/asn2eth.py -X -b -p cms -c cms.cnf -s packet-cms-template CryptographicMessageSyntax.asn */

/* Input file: packet-cms-template.c */
/* Include files: packet-cms-hf.c, packet-cms-ett.c, packet-cms-fn.c, packet-cms-hfarr.c, packet-cms-ettarr.c, packet-cms-val.h */

/* packet-cms.c
 * Routines for RFC2630 Cryptographic Message Syntax packet dissection
 *
 * $Id: packet-cms-template.c,v 1.2 2004/05/25 21:07:43 guy Exp $
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
#include "packet-cms.h"
#include "packet-x509af.h"

#define PNAME  "Cryptographic Message Syntax"
#define PSNAME "CMS"
#define PFNAME "cms"

/* Initialize the protocol and registered fields */
int proto_cms = -1;

/*--- Included file: packet-cms-hf.c ---*/

/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* packet-cms-hf.c                                                            */
/* ../../tools/asn2eth.py -X -b -p cms -c cms.cnf -s packet-cms-template CryptographicMessageSyntax.asn */

static int hf_cms_version = -1;                   /* CMSVersion */
static int hf_cms_digestAlgorithms = -1;          /* DigestAlgorithmIdentifiers */
static int hf_cms_encapContentInfo = -1;          /* EncapsulatedContentInfo */
static int hf_cms_certificates = -1;              /* CertificateSet */
static int hf_cms_crls = -1;                      /* CertificateRevocationLists */
static int hf_cms_signerInfos = -1;               /* SignerInfos */
static int hf_cms_DigestAlgorithmIdentifiers_item = -1;  /* DigestAlgorithmIdentifier */
static int hf_cms_SignerInfos_item = -1;          /* SignerInfo */
static int hf_cms_eContentType = -1;              /* ContentType */
static int hf_cms_eContent = -1;                  /* OCTET_STRING */
static int hf_cms_sid = -1;                       /* SignerIdentifier */
static int hf_cms_digestAlgorithm = -1;           /* DigestAlgorithmIdentifier */
static int hf_cms_signedAttrs = -1;               /* SignedAttributes */
static int hf_cms_signatureAlgorithm = -1;        /* SignatureAlgorithmIdentifier */
static int hf_cms_signature = -1;                 /* SignatureValue */
static int hf_cms_unsignedAttrs = -1;             /* UnsignedAttributes */
static int hf_cms_issuerAndSerialNumber = -1;     /* IssuerAndSerialNumber */
static int hf_cms_subjectKeyIdentifier = -1;      /* SubjectKeyIdentifier */
static int hf_cms_SignedAttributes_item = -1;     /* Attribute */
static int hf_cms_UnsignedAttributes_item = -1;   /* Attribute */
static int hf_cms_attrType = -1;                  /* OBJECT_IDENTIFIER */
static int hf_cms_AuthAttributes_item = -1;       /* Attribute */
static int hf_cms_UnauthAttributes_item = -1;     /* Attribute */
static int hf_cms_CertificateRevocationLists_item = -1;  /* CertificateList */
static int hf_cms_certificate = -1;               /* Certificate */
static int hf_cms_extendedCertificate = -1;       /* ExtendedCertificate */
static int hf_cms_attrCert = -1;                  /* AttributeCertificate */
static int hf_cms_CertificateSet_item = -1;       /* CertificateChoices */
static int hf_cms_serialNumber = -1;              /* CertificateSerialNumber */
static int hf_cms_extendedCertificateInfo = -1;   /* ExtendedCertificateInfo */
static int hf_cms_signature1 = -1;                /* Signature */
static int hf_cms_attributes = -1;                /* UnauthAttributes */

/*--- End of included file: packet-cms-hf.c ---*/


/* Initialize the subtree pointers */

/*--- Included file: packet-cms-ett.c ---*/

/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* packet-cms-ett.c                                                           */
/* ../../tools/asn2eth.py -X -b -p cms -c cms.cnf -s packet-cms-template CryptographicMessageSyntax.asn */

static gint ett_cms_SignedData = -1;
static gint ett_cms_DigestAlgorithmIdentifiers = -1;
static gint ett_cms_SignerInfos = -1;
static gint ett_cms_EncapsulatedContentInfo = -1;
static gint ett_cms_SignerInfo = -1;
static gint ett_cms_SignerIdentifier = -1;
static gint ett_cms_SignedAttributes = -1;
static gint ett_cms_UnsignedAttributes = -1;
static gint ett_cms_Attribute = -1;
static gint ett_cms_RecipientIdentifier = -1;
static gint ett_cms_AuthAttributes = -1;
static gint ett_cms_UnauthAttributes = -1;
static gint ett_cms_CertificateRevocationLists = -1;
static gint ett_cms_CertificateChoices = -1;
static gint ett_cms_CertificateSet = -1;
static gint ett_cms_IssuerAndSerialNumber = -1;
static gint ett_cms_ExtendedCertificate = -1;
static gint ett_cms_ExtendedCertificateInfo = -1;

/*--- End of included file: packet-cms-ett.c ---*/



/*--- Included file: packet-cms-fn.c ---*/

/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* packet-cms-fn.c                                                            */
/* ../../tools/asn2eth.py -X -b -p cms -c cms.cnf -s packet-cms-template CryptographicMessageSyntax.asn */

static int dissect_CertificateRevocationLists_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_CertificateList(FALSE, tvb, offset, pinfo, tree, hf_cms_CertificateRevocationLists_item);
}
static int dissect_certificate(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_Certificate(FALSE, tvb, offset, pinfo, tree, hf_cms_certificate);
}
static int dissect_attrCert_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_AttributeCertificate(TRUE, tvb, offset, pinfo, tree, hf_cms_attrCert);
}
static int dissect_serialNumber(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_CertificateSerialNumber(FALSE, tvb, offset, pinfo, tree, hf_cms_serialNumber);
}

static int
dissect_cms_ContentType(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset,
                                         hf_index, NULL);

  return offset;
}
static int dissect_eContentType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_ContentType(FALSE, tvb, offset, pinfo, tree, hf_cms_eContentType);
}


static const value_string CMSVersion_vals[] = {
  {   0, "v0" },
  {   1, "v1" },
  {   2, "v2" },
  {   3, "v3" },
  {   4, "v4" },
  { 0, NULL }
};


static int
dissect_cms_CMSVersion(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_integer(pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_version(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_CMSVersion(FALSE, tvb, offset, pinfo, tree, hf_cms_version);
}


static int
dissect_cms_DigestAlgorithmIdentifier(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_DigestAlgorithmIdentifiers_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_DigestAlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_cms_DigestAlgorithmIdentifiers_item);
}
static int dissect_digestAlgorithm(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_DigestAlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_cms_digestAlgorithm);
}

static ber_sequence DigestAlgorithmIdentifiers_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_DigestAlgorithmIdentifiers_item },
};

static int
dissect_cms_DigestAlgorithmIdentifiers(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                              DigestAlgorithmIdentifiers_set_of, hf_index, ett_cms_DigestAlgorithmIdentifiers);

  return offset;
}
static int dissect_digestAlgorithms(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_DigestAlgorithmIdentifiers(FALSE, tvb, offset, pinfo, tree, hf_cms_digestAlgorithms);
}


static int
dissect_cms_OCTET_STRING(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_eContent(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_cms_eContent);
}

static ber_sequence EncapsulatedContentInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_eContentType },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_eContent },
  { 0, 0, 0, NULL }
};

static int
dissect_cms_EncapsulatedContentInfo(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                EncapsulatedContentInfo_sequence, hf_index, ett_cms_EncapsulatedContentInfo);

  return offset;
}
static int dissect_encapContentInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_EncapsulatedContentInfo(FALSE, tvb, offset, pinfo, tree, hf_cms_encapContentInfo);
}


static int
dissect_cms_OBJECT_IDENTIFIER(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset,
                                         hf_index, NULL);

  return offset;
}
static int dissect_attrType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_cms_attrType);
}

static ber_sequence Attribute_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_attrType },
  { 0, 0, 0, NULL }
};

static int
dissect_cms_Attribute(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                Attribute_sequence, hf_index, ett_cms_Attribute);

  return offset;
}
static int dissect_SignedAttributes_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_Attribute(FALSE, tvb, offset, pinfo, tree, hf_cms_SignedAttributes_item);
}
static int dissect_UnsignedAttributes_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_Attribute(FALSE, tvb, offset, pinfo, tree, hf_cms_UnsignedAttributes_item);
}
static int dissect_AuthAttributes_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_Attribute(FALSE, tvb, offset, pinfo, tree, hf_cms_AuthAttributes_item);
}
static int dissect_UnauthAttributes_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_Attribute(FALSE, tvb, offset, pinfo, tree, hf_cms_UnauthAttributes_item);
}

static ber_sequence UnauthAttributes_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_UnauthAttributes_item },
};

static int
dissect_cms_UnauthAttributes(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                              UnauthAttributes_set_of, hf_index, ett_cms_UnauthAttributes);

  return offset;
}
static int dissect_attributes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_UnauthAttributes(FALSE, tvb, offset, pinfo, tree, hf_cms_attributes);
}

static ber_sequence ExtendedCertificateInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_version },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_certificate },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_attributes },
  { 0, 0, 0, NULL }
};

static int
dissect_cms_ExtendedCertificateInfo(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                ExtendedCertificateInfo_sequence, hf_index, ett_cms_ExtendedCertificateInfo);

  return offset;
}
static int dissect_extendedCertificateInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_ExtendedCertificateInfo(FALSE, tvb, offset, pinfo, tree, hf_cms_extendedCertificateInfo);
}


static int
dissect_cms_SignatureAlgorithmIdentifier(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_signatureAlgorithm(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_SignatureAlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_cms_signatureAlgorithm);
}


static int
dissect_cms_Signature(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                 NULL, hf_index, -1,
                                 NULL);

  return offset;
}
static int dissect_signature1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_Signature(FALSE, tvb, offset, pinfo, tree, hf_cms_signature1);
}

static ber_sequence ExtendedCertificate_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_extendedCertificateInfo },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signatureAlgorithm },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_signature1 },
  { 0, 0, 0, NULL }
};

static int
dissect_cms_ExtendedCertificate(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                ExtendedCertificate_sequence, hf_index, ett_cms_ExtendedCertificate);

  return offset;
}
static int dissect_extendedCertificate_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_ExtendedCertificate(TRUE, tvb, offset, pinfo, tree, hf_cms_extendedCertificate);
}


static const value_string CertificateChoices_vals[] = {
  {   0, "certificate" },
  {   1, "extendedCertificate" },
  {   2, "attrCert" },
  { 0, NULL }
};

static ber_choice CertificateChoices_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_certificate },
  {   1, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_extendedCertificate_impl },
  {   2, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_attrCert_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_cms_CertificateChoices(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              CertificateChoices_choice, hf_index, ett_cms_CertificateChoices);

  return offset;
}
static int dissect_CertificateSet_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_CertificateChoices(FALSE, tvb, offset, pinfo, tree, hf_cms_CertificateSet_item);
}

static ber_sequence CertificateSet_set_of[1] = {
  { -1/*choice*/ , -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_CertificateSet_item },
};

static int
dissect_cms_CertificateSet(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                              CertificateSet_set_of, hf_index, ett_cms_CertificateSet);

  return offset;
}
static int dissect_certificates_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_CertificateSet(TRUE, tvb, offset, pinfo, tree, hf_cms_certificates);
}

static ber_sequence CertificateRevocationLists_set_of[1] = {
  { -1 /*imported*/, -1 /*imported*/, BER_FLAGS_NOOWNTAG, dissect_CertificateRevocationLists_item },
};

static int
dissect_cms_CertificateRevocationLists(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                              CertificateRevocationLists_set_of, hf_index, ett_cms_CertificateRevocationLists);

  return offset;
}
static int dissect_crls_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_CertificateRevocationLists(TRUE, tvb, offset, pinfo, tree, hf_cms_crls);
}

static ber_sequence IssuerAndSerialNumber_sequence[] = {
  { -1 /*imported*/, -1 /*imported*/, BER_FLAGS_NOOWNTAG, dissect_serialNumber },
  { 0, 0, 0, NULL }
};

static int
dissect_cms_IssuerAndSerialNumber(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                IssuerAndSerialNumber_sequence, hf_index, ett_cms_IssuerAndSerialNumber);

  return offset;
}
static int dissect_issuerAndSerialNumber(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_IssuerAndSerialNumber(FALSE, tvb, offset, pinfo, tree, hf_cms_issuerAndSerialNumber);
}


static int
dissect_cms_SubjectKeyIdentifier(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_subjectKeyIdentifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_SubjectKeyIdentifier(FALSE, tvb, offset, pinfo, tree, hf_cms_subjectKeyIdentifier);
}


static const value_string SignerIdentifier_vals[] = {
  {   0, "issuerAndSerialNumber" },
  {   1, "subjectKeyIdentifier" },
  { 0, NULL }
};

static ber_choice SignerIdentifier_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_issuerAndSerialNumber },
  {   1, BER_CLASS_CON, 0, 0, dissect_subjectKeyIdentifier },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_cms_SignerIdentifier(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              SignerIdentifier_choice, hf_index, ett_cms_SignerIdentifier);

  return offset;
}
static int dissect_sid(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_SignerIdentifier(FALSE, tvb, offset, pinfo, tree, hf_cms_sid);
}

static ber_sequence SignedAttributes_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_SignedAttributes_item },
};

static int
dissect_cms_SignedAttributes(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                              SignedAttributes_set_of, hf_index, ett_cms_SignedAttributes);

  return offset;
}
static int dissect_signedAttrs_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_SignedAttributes(TRUE, tvb, offset, pinfo, tree, hf_cms_signedAttrs);
}


static int
dissect_cms_SignatureValue(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_signature(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_SignatureValue(FALSE, tvb, offset, pinfo, tree, hf_cms_signature);
}

static ber_sequence UnsignedAttributes_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_UnsignedAttributes_item },
};

static int
dissect_cms_UnsignedAttributes(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                              UnsignedAttributes_set_of, hf_index, ett_cms_UnsignedAttributes);

  return offset;
}
static int dissect_unsignedAttrs_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_UnsignedAttributes(TRUE, tvb, offset, pinfo, tree, hf_cms_unsignedAttrs);
}

static ber_sequence SignerInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_version },
  { -1/*choice*/ , -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_sid },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_digestAlgorithm },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_signedAttrs_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signatureAlgorithm },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_signature },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_unsignedAttrs_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_cms_SignerInfo(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                SignerInfo_sequence, hf_index, ett_cms_SignerInfo);

  return offset;
}
static int dissect_SignerInfos_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_SignerInfo(FALSE, tvb, offset, pinfo, tree, hf_cms_SignerInfos_item);
}

static ber_sequence SignerInfos_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_SignerInfos_item },
};

static int
dissect_cms_SignerInfos(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                              SignerInfos_set_of, hf_index, ett_cms_SignerInfos);

  return offset;
}
static int dissect_signerInfos(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_SignerInfos(FALSE, tvb, offset, pinfo, tree, hf_cms_signerInfos);
}

static ber_sequence SignedData_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_version },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_digestAlgorithms },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_encapContentInfo },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_certificates_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_crls_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_signerInfos },
  { 0, 0, 0, NULL }
};

int
dissect_cms_SignedData(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                SignedData_sequence, hf_index, ett_cms_SignedData);

  return offset;
}


static const value_string RecipientIdentifier_vals[] = {
  {   0, "issuerAndSerialNumber" },
  {   1, "subjectKeyIdentifier" },
  { 0, NULL }
};

static ber_choice RecipientIdentifier_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_issuerAndSerialNumber },
  {   1, BER_CLASS_CON, 0, 0, dissect_subjectKeyIdentifier },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_cms_RecipientIdentifier(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              RecipientIdentifier_choice, hf_index, ett_cms_RecipientIdentifier);

  return offset;
}


static int
dissect_cms_Digest(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}

static ber_sequence AuthAttributes_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_AuthAttributes_item },
};

static int
dissect_cms_AuthAttributes(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                              AuthAttributes_set_of, hf_index, ett_cms_AuthAttributes);

  return offset;
}


static int
dissect_cms_MessageAuthenticationCode(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}


static int
dissect_cms_KeyEncryptionAlgorithmIdentifier(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static int
dissect_cms_ContentEncryptionAlgorithmIdentifier(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static int
dissect_cms_MessageAuthenticationCodeAlgorithm(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static int
dissect_cms_Countersignature(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_cms_SignerInfo(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}


/*--- End of included file: packet-cms-fn.c ---*/



static void
dissect_cms_SignedData_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_cms_SignedData(FALSE, tvb, 0, pinfo, tree, -1);
}

/*--- proto_register_cms ----------------------------------------------*/
void proto_register_cms(void) {

  /* List of fields */
  static hf_register_info hf[] = {

/*--- Included file: packet-cms-hfarr.c ---*/

/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* packet-cms-hfarr.c                                                         */
/* ../../tools/asn2eth.py -X -b -p cms -c cms.cnf -s packet-cms-template CryptographicMessageSyntax.asn */

    { &hf_cms_version,
      { "version", "cms.version",
        FT_INT32, BASE_DEC, VALS(CMSVersion_vals), 0,
        "", HFILL }},
    { &hf_cms_digestAlgorithms,
      { "digestAlgorithms", "cms.digestAlgorithms",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SignedData/digestAlgorithms", HFILL }},
    { &hf_cms_encapContentInfo,
      { "encapContentInfo", "cms.encapContentInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "SignedData/encapContentInfo", HFILL }},
    { &hf_cms_certificates,
      { "certificates", "cms.certificates",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SignedData/certificates", HFILL }},
    { &hf_cms_crls,
      { "crls", "cms.crls",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SignedData/crls", HFILL }},
    { &hf_cms_signerInfos,
      { "signerInfos", "cms.signerInfos",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SignedData/signerInfos", HFILL }},
    { &hf_cms_DigestAlgorithmIdentifiers_item,
      { "Item(##)", "cms.DigestAlgorithmIdentifiers_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "DigestAlgorithmIdentifiers/_item", HFILL }},
    { &hf_cms_SignerInfos_item,
      { "Item(##)", "cms.SignerInfos_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SignerInfos/_item", HFILL }},
    { &hf_cms_eContentType,
      { "eContentType", "cms.eContentType",
        FT_STRING, BASE_NONE, NULL, 0,
        "EncapsulatedContentInfo/eContentType", HFILL }},
    { &hf_cms_eContent,
      { "eContent", "cms.eContent",
        FT_BYTES, BASE_HEX, NULL, 0,
        "EncapsulatedContentInfo/eContent", HFILL }},
    { &hf_cms_sid,
      { "sid", "cms.sid",
        FT_UINT32, BASE_DEC, VALS(SignerIdentifier_vals), 0,
        "SignerInfo/sid", HFILL }},
    { &hf_cms_digestAlgorithm,
      { "digestAlgorithm", "cms.digestAlgorithm",
        FT_NONE, BASE_NONE, NULL, 0,
        "SignerInfo/digestAlgorithm", HFILL }},
    { &hf_cms_signedAttrs,
      { "signedAttrs", "cms.signedAttrs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SignerInfo/signedAttrs", HFILL }},
    { &hf_cms_signatureAlgorithm,
      { "signatureAlgorithm", "cms.signatureAlgorithm",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_cms_signature,
      { "signature", "cms.signature",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SignerInfo/signature", HFILL }},
    { &hf_cms_unsignedAttrs,
      { "unsignedAttrs", "cms.unsignedAttrs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SignerInfo/unsignedAttrs", HFILL }},
    { &hf_cms_issuerAndSerialNumber,
      { "issuerAndSerialNumber", "cms.issuerAndSerialNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_cms_subjectKeyIdentifier,
      { "subjectKeyIdentifier", "cms.subjectKeyIdentifier",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_cms_SignedAttributes_item,
      { "Item(##)", "cms.SignedAttributes_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SignedAttributes/_item", HFILL }},
    { &hf_cms_UnsignedAttributes_item,
      { "Item(##)", "cms.UnsignedAttributes_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnsignedAttributes/_item", HFILL }},
    { &hf_cms_attrType,
      { "attrType", "cms.attrType",
        FT_STRING, BASE_NONE, NULL, 0,
        "Attribute/attrType", HFILL }},
    { &hf_cms_AuthAttributes_item,
      { "Item(##)", "cms.AuthAttributes_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "AuthAttributes/_item", HFILL }},
    { &hf_cms_UnauthAttributes_item,
      { "Item(##)", "cms.UnauthAttributes_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnauthAttributes/_item", HFILL }},
    { &hf_cms_CertificateRevocationLists_item,
      { "Item(##)", "cms.CertificateRevocationLists_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertificateRevocationLists/_item", HFILL }},
    { &hf_cms_certificate,
      { "certificate", "cms.certificate",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_cms_extendedCertificate,
      { "extendedCertificate", "cms.extendedCertificate",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertificateChoices/extendedCertificate", HFILL }},
    { &hf_cms_attrCert,
      { "attrCert", "cms.attrCert",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertificateChoices/attrCert", HFILL }},
    { &hf_cms_CertificateSet_item,
      { "Item(##)", "cms.CertificateSet_item",
        FT_UINT32, BASE_DEC, VALS(CertificateChoices_vals), 0,
        "CertificateSet/_item", HFILL }},
    { &hf_cms_serialNumber,
      { "serialNumber", "cms.serialNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        "IssuerAndSerialNumber/serialNumber", HFILL }},
    { &hf_cms_extendedCertificateInfo,
      { "extendedCertificateInfo", "cms.extendedCertificateInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "ExtendedCertificate/extendedCertificateInfo", HFILL }},
    { &hf_cms_signature1,
      { "signature", "cms.signature",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ExtendedCertificate/signature", HFILL }},
    { &hf_cms_attributes,
      { "attributes", "cms.attributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ExtendedCertificateInfo/attributes", HFILL }},

/*--- End of included file: packet-cms-hfarr.c ---*/

  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-cms-ettarr.c ---*/

/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* packet-cms-ettarr.c                                                        */
/* ../../tools/asn2eth.py -X -b -p cms -c cms.cnf -s packet-cms-template CryptographicMessageSyntax.asn */

    &ett_cms_SignedData,
    &ett_cms_DigestAlgorithmIdentifiers,
    &ett_cms_SignerInfos,
    &ett_cms_EncapsulatedContentInfo,
    &ett_cms_SignerInfo,
    &ett_cms_SignerIdentifier,
    &ett_cms_SignedAttributes,
    &ett_cms_UnsignedAttributes,
    &ett_cms_Attribute,
    &ett_cms_RecipientIdentifier,
    &ett_cms_AuthAttributes,
    &ett_cms_UnauthAttributes,
    &ett_cms_CertificateRevocationLists,
    &ett_cms_CertificateChoices,
    &ett_cms_CertificateSet,
    &ett_cms_IssuerAndSerialNumber,
    &ett_cms_ExtendedCertificate,
    &ett_cms_ExtendedCertificateInfo,

/*--- End of included file: packet-cms-ettarr.c ---*/

  };

  /* Register protocol */
  proto_cms = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_cms, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_cms -------------------------------------------*/
void proto_reg_handoff_cms(void) {
	register_ber_oid_dissector("1.2.840.113549.1.7.2", dissect_cms_SignedData_callback, proto_cms, "id-signedData");
}

