/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* packet-x509ce.c                                                            */
/* ../../tools/asn2eth.py -X -b -p x509ce -c x509ce.cnf -s packet-x509ce-template CertificateExtensions.asn */

/* Input file: packet-x509ce-template.c */
/* Include files: packet-x509ce-hf.c, packet-x509ce-ett.c, packet-x509ce-fn.c, packet-x509ce-hfarr.c, packet-x509ce-ettarr.c, packet-x509ce-val.h */

/* packet-x509ce.c
 * Routines for X.509 Certificate Extensions packet dissection
 *
 * $Id: packet-x509ce-template.c,v 1.2 2004/05/25 21:07:43 guy Exp $
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
#include "packet-x509ce.h"
#include "packet-x509af.h"
#include "packet-x509if.h"

#define PNAME  "X.509 Certificate Extensions"
#define PSNAME "X509CE"
#define PFNAME "x509ce"

/* Initialize the protocol and registered fields */
int proto_x509ce = -1;
static int hf_x509ce_id_ce_subjectDirectoryAttributes = -1;
static int hf_x509ce_id_ce_subjectKeyIdentifier = -1;
static int hf_x509ce_id_ce_keyUsage = -1;
static int hf_x509ce_id_ce_privateKeyUsagePeriod = -1;
static int hf_x509ce_id_ce_subjectAltName = -1;
static int hf_x509ce_id_ce_issuerAltName = -1;
static int hf_x509ce_id_ce_basicConstraints = -1;
static int hf_x509ce_id_ce_cRLNumber = -1;
static int hf_x509ce_id_ce_reasonCode = -1;
static int hf_x509ce_id_ce_instructionCode = -1;
static int hf_x509ce_id_ce_invalidityDate = -1;
static int hf_x509ce_id_ce_deltaCRLIndicator = -1;
static int hf_x509ce_id_ce_issuingDistributionPoint = -1;
static int hf_x509ce_id_ce_certificateIssuer = -1;
static int hf_x509ce_id_ce_nameConstraints = -1;
static int hf_x509ce_id_ce_cRLDistributionPoints = -1;
static int hf_x509ce_id_ce_certificatePolicies = -1;
static int hf_x509ce_id_ce_policyMappings = -1;
static int hf_x509ce_id_ce_authorityKeyIdentifier = -1;
static int hf_x509ce_id_ce_policyConstraints = -1;
static int hf_x509ce_id_ce_extKeyUsage = -1;
static int hf_x509ce_id_ce_cRLStreamIdentifier = -1;
static int hf_x509ce_id_ce_cRLScope = -1;
static int hf_x509ce_id_ce_statusReferrals = -1;
static int hf_x509ce_id_ce_freshestCRL = -1;
static int hf_x509ce_id_ce_orderedList = -1;
static int hf_x509ce_id_ce_baseUpdateTime = -1;
static int hf_x509ce_id_ce_deltaInfo = -1;
static int hf_x509ce_id_ce_inhibitAnyPolicy = -1;

/*--- Included file: packet-x509ce-hf.c ---*/

/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* packet-x509ce-hf.c                                                         */
/* ../../tools/asn2eth.py -X -b -p x509ce -c x509ce.cnf -s packet-x509ce-template CertificateExtensions.asn */

static int hf_x509ce_keyIdentifier = -1;          /* KeyIdentifier */
static int hf_x509ce_authorityCertIssuer = -1;    /* GeneralNames */
static int hf_x509ce_authorityCertSerialNumber = -1;  /* CertificateSerialNumber */
static int hf_x509ce_KeyPurposeIDs_item = -1;     /* KeyPurposeId */
static int hf_x509ce_notBefore = -1;              /* GeneralizedTime */
static int hf_x509ce_notAfter = -1;               /* GeneralizedTime */
static int hf_x509ce_CertificatePoliciesSyntax_item = -1;  /* PolicyInformation */
static int hf_x509ce_policyIdentifier = -1;       /* CertPolicyId */
static int hf_x509ce_policyQualifiers = -1;       /* SEQUNCE_OF_PolicyQualifierInfo */
static int hf_x509ce_policyQualifiers_item = -1;  /* PolicyQualifierInfo */
static int hf_x509ce_PolicyMappingsSyntax_item = -1;  /* PolicyMappingsSyntax_item */
static int hf_x509ce_issuerDomainPolicy = -1;     /* CertPolicyId */
static int hf_x509ce_subjectDomainPolicy = -1;    /* CertPolicyId */
static int hf_x509ce_GeneralNames_item = -1;      /* GeneralName */
static int hf_x509ce_rfc822Name = -1;             /* IA5String */
static int hf_x509ce_dNSName = -1;                /* IA5String */
static int hf_x509ce_directoryName = -1;          /* Name */
static int hf_x509ce_uniformResourceIdentifier = -1;  /* IA5String */
static int hf_x509ce_iPAddress = -1;              /* OCTET_STRING */
static int hf_x509ce_registeredID = -1;           /* OBJECT_IDENTIFIER */
static int hf_x509ce_AttributesSyntax_item = -1;  /* Attribute */
static int hf_x509ce_cA = -1;                     /* BOOLEAN */
static int hf_x509ce_pathLenConstraint = -1;      /* INTEGER */
static int hf_x509ce_permittedSubtrees = -1;      /* GeneralSubtrees */
static int hf_x509ce_excludedSubtrees = -1;       /* GeneralSubtrees */
static int hf_x509ce_GeneralSubtrees_item = -1;   /* GeneralSubtree */
static int hf_x509ce_base = -1;                   /* GeneralName */
static int hf_x509ce_minimum = -1;                /* BaseDistance */
static int hf_x509ce_maximum = -1;                /* BaseDistance */
static int hf_x509ce_requireExplicitPolicy = -1;  /* SkipCerts */
static int hf_x509ce_inhibitPolicyMapping = -1;   /* SkipCerts */
static int hf_x509ce_CRLScopeSyntax_item = -1;    /* PerAuthorityScope */
static int hf_x509ce_authorityName = -1;          /* GeneralName */
static int hf_x509ce_distributionPoint = -1;      /* DistributionPointName */
static int hf_x509ce_onlyContains = -1;           /* OnlyCertificateTypes */
static int hf_x509ce_onlySomeReasons = -1;        /* ReasonFlags */
static int hf_x509ce_serialNumberRange = -1;      /* NumberRange */
static int hf_x509ce_subjectKeyIdRange = -1;      /* NumberRange */
static int hf_x509ce_nameSubtrees = -1;           /* GeneralNames */
static int hf_x509ce_baseRevocationInfo = -1;     /* BaseRevocationInfo */
static int hf_x509ce_startingNumber = -1;         /* INTEGER */
static int hf_x509ce_endingNumber = -1;           /* INTEGER */
static int hf_x509ce_modulus = -1;                /* INTEGER */
static int hf_x509ce_cRLStreamIdentifier = -1;    /* CRLStreamIdentifier */
static int hf_x509ce_cRLNumber = -1;              /* CRLNumber */
static int hf_x509ce_baseThisUpdate = -1;         /* GeneralizedTime */
static int hf_x509ce_StatusReferrals_item = -1;   /* StatusReferral */
static int hf_x509ce_cRLReferral = -1;            /* CRLReferral */
static int hf_x509ce_issuer = -1;                 /* GeneralName */
static int hf_x509ce_location = -1;               /* GeneralName */
static int hf_x509ce_deltaRefInfo = -1;           /* DeltaRefInfo */
static int hf_x509ce_cRLScope = -1;               /* CRLScopeSyntax */
static int hf_x509ce_lastUpdate = -1;             /* GeneralizedTime */
static int hf_x509ce_lastChangedCRL = -1;         /* GeneralizedTime */
static int hf_x509ce_deltaLocation = -1;          /* GeneralName */
static int hf_x509ce_lastDelta = -1;              /* GeneralizedTime */
static int hf_x509ce_nextDelta = -1;              /* GeneralizedTime */
static int hf_x509ce_CRLDistPointsSyntax_item = -1;  /* DistributionPoint */
static int hf_x509ce_reasons = -1;                /* ReasonFlags */
static int hf_x509ce_cRLIssuer = -1;              /* GeneralNames */
static int hf_x509ce_fullName = -1;               /* GeneralNames */
static int hf_x509ce_nameRelativeToCRLIssuer = -1;  /* RelativeDistinguishedName */
static int hf_x509ce_containsUserPublicKeyCerts = -1;  /* BOOLEAN */
static int hf_x509ce_containsCACerts = -1;        /* BOOLEAN */
static int hf_x509ce_indirectCRL = -1;            /* BOOLEAN */
static int hf_x509ce_containsUserAttributeCerts = -1;  /* BOOLEAN */
static int hf_x509ce_containsAACerts = -1;        /* BOOLEAN */
static int hf_x509ce_containsSOAPublicKeyCerts = -1;  /* BOOLEAN */
/* named bits */
static int hf_x509ce_KeyUsage_digitalSignature = -1;
static int hf_x509ce_KeyUsage_nonRepudiation = -1;
static int hf_x509ce_KeyUsage_keyEncipherment = -1;
static int hf_x509ce_KeyUsage_dataEncipherment = -1;
static int hf_x509ce_KeyUsage_keyAgreement = -1;
static int hf_x509ce_KeyUsage_keyCertSign = -1;
static int hf_x509ce_KeyUsage_cRLSign = -1;
static int hf_x509ce_KeyUsage_encipherOnly = -1;
static int hf_x509ce_KeyUsage_decipherOnly = -1;
static int hf_x509ce_OnlyCertificateTypes_userPublicKey = -1;
static int hf_x509ce_OnlyCertificateTypes_cA = -1;
static int hf_x509ce_OnlyCertificateTypes_userAttribute = -1;
static int hf_x509ce_OnlyCertificateTypes_aA = -1;
static int hf_x509ce_OnlyCertificateTypes_sOAPublicKey = -1;
static int hf_x509ce_ReasonFlags_unused = -1;
static int hf_x509ce_ReasonFlags_keyCompromise = -1;
static int hf_x509ce_ReasonFlags_cACompromise = -1;
static int hf_x509ce_ReasonFlags_affiliationChanged = -1;
static int hf_x509ce_ReasonFlags_superseded = -1;
static int hf_x509ce_ReasonFlags_cessationOfOperation = -1;
static int hf_x509ce_ReasonFlags_certificateHold = -1;
static int hf_x509ce_ReasonFlags_privilegeWithdrawn = -1;
static int hf_x509ce_ReasonFlags_aACompromise = -1;

/*--- End of included file: packet-x509ce-hf.c ---*/


/* Initialize the subtree pointers */

/*--- Included file: packet-x509ce-ett.c ---*/

/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* packet-x509ce-ett.c                                                        */
/* ../../tools/asn2eth.py -X -b -p x509ce -c x509ce.cnf -s packet-x509ce-template CertificateExtensions.asn */

static gint ett_x509ce_AuthorityKeyIdentifier = -1;
static gint ett_x509ce_KeyUsage = -1;
static gint ett_x509ce_KeyPurposeIDs = -1;
static gint ett_x509ce_PrivateKeyUsagePeriod = -1;
static gint ett_x509ce_CertificatePoliciesSyntax = -1;
static gint ett_x509ce_PolicyInformation = -1;
static gint ett_x509ce_SEQUNCE_OF_PolicyQualifierInfo = -1;
static gint ett_x509ce_PolicyQualifierInfo = -1;
static gint ett_x509ce_PolicyMappingsSyntax = -1;
static gint ett_x509ce_PolicyMappingsSyntax_item = -1;
static gint ett_x509ce_GeneralNames = -1;
static gint ett_x509ce_GeneralName = -1;
static gint ett_x509ce_AttributesSyntax = -1;
static gint ett_x509ce_BasicConstraintsSyntax = -1;
static gint ett_x509ce_NameConstraintsSyntax = -1;
static gint ett_x509ce_GeneralSubtrees = -1;
static gint ett_x509ce_GeneralSubtree = -1;
static gint ett_x509ce_PolicyConstraintsSyntax = -1;
static gint ett_x509ce_CRLScopeSyntax = -1;
static gint ett_x509ce_PerAuthorityScope = -1;
static gint ett_x509ce_OnlyCertificateTypes = -1;
static gint ett_x509ce_NumberRange = -1;
static gint ett_x509ce_BaseRevocationInfo = -1;
static gint ett_x509ce_StatusReferrals = -1;
static gint ett_x509ce_StatusReferral = -1;
static gint ett_x509ce_CRLReferral = -1;
static gint ett_x509ce_DeltaRefInfo = -1;
static gint ett_x509ce_DeltaInformation = -1;
static gint ett_x509ce_CRLDistPointsSyntax = -1;
static gint ett_x509ce_DistributionPoint = -1;
static gint ett_x509ce_DistributionPointName = -1;
static gint ett_x509ce_ReasonFlags = -1;
static gint ett_x509ce_IssuingDistPointSyntax = -1;

/*--- End of included file: packet-x509ce-ett.c ---*/



/*--- Included file: packet-x509ce-fn.c ---*/

/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* packet-x509ce-fn.c                                                         */
/* ../../tools/asn2eth.py -X -b -p x509ce -c x509ce.cnf -s packet-x509ce-template CertificateExtensions.asn */

/*--- Fields for imported types ---*/

static int dissect_authorityCertSerialNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_CertificateSerialNumber(TRUE, tvb, offset, pinfo, tree, hf_x509ce_authorityCertSerialNumber);
}
static int dissect_directoryName_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Name(TRUE, tvb, offset, pinfo, tree, hf_x509ce_directoryName);
}
static int dissect_AttributesSyntax_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Attribute(FALSE, tvb, offset, pinfo, tree, hf_x509ce_AttributesSyntax_item);
}
static int dissect_nameRelativeToCRLIssuer_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_RelativeDistinguishedName(TRUE, tvb, offset, pinfo, tree, hf_x509ce_nameRelativeToCRLIssuer);
}


static int
dissect_x509ce_KeyIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_keyIdentifier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_KeyIdentifier(TRUE, tvb, offset, pinfo, tree, hf_x509ce_keyIdentifier);
}


static int
dissect_x509ce_IA5String(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_restricted_string(implicit_tag, 1,
                                         pinfo, tree, tvb, offset, hf_index,
                                         NULL);

  return offset;
}
static int dissect_rfc822Name_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_IA5String(TRUE, tvb, offset, pinfo, tree, hf_x509ce_rfc822Name);
}
static int dissect_dNSName_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_IA5String(TRUE, tvb, offset, pinfo, tree, hf_x509ce_dNSName);
}
static int dissect_uniformResourceIdentifier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_IA5String(TRUE, tvb, offset, pinfo, tree, hf_x509ce_uniformResourceIdentifier);
}


static int
dissect_x509ce_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_iPAddress_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_x509ce_iPAddress);
}


static int
dissect_x509ce_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset,
                                         hf_index, NULL);

  return offset;
}
static int dissect_registeredID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_OBJECT_IDENTIFIER(TRUE, tvb, offset, pinfo, tree, hf_x509ce_registeredID);
}


static const value_string GeneralName_vals[] = {
  {   1, "rfc822Name" },
  {   2, "dNSName" },
  {   4, "directoryName" },
  {   6, "uniformResourceIdentifier" },
  {   7, "iPAddress" },
  {   8, "registeredID" },
  { 0, NULL }
};

static ber_choice GeneralName_choice[] = {
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_rfc822Name_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_dNSName_impl },
  {   4, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_directoryName_impl },
  {   6, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_uniformResourceIdentifier_impl },
  {   7, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_iPAddress_impl },
  {   8, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_registeredID_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x509ce_GeneralName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              GeneralName_choice, hf_index, ett_x509ce_GeneralName);

  return offset;
}
static int dissect_GeneralNames_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_GeneralName(FALSE, tvb, offset, pinfo, tree, hf_x509ce_GeneralNames_item);
}
static int dissect_base(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_GeneralName(FALSE, tvb, offset, pinfo, tree, hf_x509ce_base);
}
static int dissect_authorityName_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_GeneralName(TRUE, tvb, offset, pinfo, tree, hf_x509ce_authorityName);
}
static int dissect_issuer_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_GeneralName(TRUE, tvb, offset, pinfo, tree, hf_x509ce_issuer);
}
static int dissect_location_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_GeneralName(TRUE, tvb, offset, pinfo, tree, hf_x509ce_location);
}
static int dissect_deltaLocation(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_GeneralName(FALSE, tvb, offset, pinfo, tree, hf_x509ce_deltaLocation);
}

static ber_sequence GeneralNames_sequence_of[1] = {
  { BER_CLASS_CON, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_GeneralNames_item },
};

int
dissect_x509ce_GeneralNames(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   GeneralNames_sequence_of, hf_index, ett_x509ce_GeneralNames);

  return offset;
}
static int dissect_authorityCertIssuer_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_GeneralNames(TRUE, tvb, offset, pinfo, tree, hf_x509ce_authorityCertIssuer);
}
static int dissect_nameSubtrees_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_GeneralNames(TRUE, tvb, offset, pinfo, tree, hf_x509ce_nameSubtrees);
}
static int dissect_cRLIssuer_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_GeneralNames(TRUE, tvb, offset, pinfo, tree, hf_x509ce_cRLIssuer);
}
static int dissect_fullName_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_GeneralNames(TRUE, tvb, offset, pinfo, tree, hf_x509ce_fullName);
}

static ber_sequence AuthorityKeyIdentifier_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_keyIdentifier_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_authorityCertIssuer_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_authorityCertSerialNumber_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x509ce_AuthorityKeyIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                AuthorityKeyIdentifier_sequence, hf_index, ett_x509ce_AuthorityKeyIdentifier);

  return offset;
}


static int
dissect_x509ce_SubjectKeyIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_x509ce_KeyIdentifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}

static asn_namedbit KeyUsage_bits[] = {
  {  0, &hf_x509ce_KeyUsage_digitalSignature, -1, -1, NULL, NULL },
  {  1, &hf_x509ce_KeyUsage_nonRepudiation, -1, -1, NULL, NULL },
  {  2, &hf_x509ce_KeyUsage_keyEncipherment, -1, -1, NULL, NULL },
  {  3, &hf_x509ce_KeyUsage_dataEncipherment, -1, -1, NULL, NULL },
  {  4, &hf_x509ce_KeyUsage_keyAgreement, -1, -1, NULL, NULL },
  {  5, &hf_x509ce_KeyUsage_keyCertSign, -1, -1, NULL, NULL },
  {  6, &hf_x509ce_KeyUsage_cRLSign, -1, -1, NULL, NULL },
  {  7, &hf_x509ce_KeyUsage_encipherOnly, -1, -1, NULL, NULL },
  {  8, &hf_x509ce_KeyUsage_decipherOnly, -1, -1, NULL, NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_x509ce_KeyUsage(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                 KeyUsage_bits, hf_index, ett_x509ce_KeyUsage,
                                 NULL);

  return offset;
}


static int
dissect_x509ce_KeyPurposeId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset,
                                         hf_index, NULL);

  return offset;
}
static int dissect_KeyPurposeIDs_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_KeyPurposeId(FALSE, tvb, offset, pinfo, tree, hf_x509ce_KeyPurposeIDs_item);
}

static ber_sequence KeyPurposeIDs_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_KeyPurposeIDs_item },
};

static int
dissect_x509ce_KeyPurposeIDs(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   KeyPurposeIDs_sequence_of, hf_index, ett_x509ce_KeyPurposeIDs);

  return offset;
}


static int
dissect_x509ce_GeneralizedTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_generalized_time(pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_notBefore_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_GeneralizedTime(TRUE, tvb, offset, pinfo, tree, hf_x509ce_notBefore);
}
static int dissect_notAfter_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_GeneralizedTime(TRUE, tvb, offset, pinfo, tree, hf_x509ce_notAfter);
}
static int dissect_baseThisUpdate_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_GeneralizedTime(TRUE, tvb, offset, pinfo, tree, hf_x509ce_baseThisUpdate);
}
static int dissect_lastUpdate_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_GeneralizedTime(TRUE, tvb, offset, pinfo, tree, hf_x509ce_lastUpdate);
}
static int dissect_lastChangedCRL_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_GeneralizedTime(TRUE, tvb, offset, pinfo, tree, hf_x509ce_lastChangedCRL);
}
static int dissect_lastDelta(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_GeneralizedTime(FALSE, tvb, offset, pinfo, tree, hf_x509ce_lastDelta);
}
static int dissect_nextDelta(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_GeneralizedTime(FALSE, tvb, offset, pinfo, tree, hf_x509ce_nextDelta);
}

static ber_sequence PrivateKeyUsagePeriod_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_notBefore_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_notAfter_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x509ce_PrivateKeyUsagePeriod(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                PrivateKeyUsagePeriod_sequence, hf_index, ett_x509ce_PrivateKeyUsagePeriod);

  return offset;
}


static int
dissect_x509ce_CertPolicyId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset,
                                         hf_index, NULL);

  return offset;
}
static int dissect_policyIdentifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_CertPolicyId(FALSE, tvb, offset, pinfo, tree, hf_x509ce_policyIdentifier);
}
static int dissect_issuerDomainPolicy(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_CertPolicyId(FALSE, tvb, offset, pinfo, tree, hf_x509ce_issuerDomainPolicy);
}
static int dissect_subjectDomainPolicy(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_CertPolicyId(FALSE, tvb, offset, pinfo, tree, hf_x509ce_subjectDomainPolicy);
}

static ber_sequence PolicyQualifierInfo_sequence[] = {
  { 0, 0, 0, NULL }
};

static int
dissect_x509ce_PolicyQualifierInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                PolicyQualifierInfo_sequence, hf_index, ett_x509ce_PolicyQualifierInfo);

  return offset;
}
static int dissect_policyQualifiers_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_PolicyQualifierInfo(FALSE, tvb, offset, pinfo, tree, hf_x509ce_policyQualifiers_item);
}

static ber_sequence SEQUNCE_OF_PolicyQualifierInfo_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_policyQualifiers_item },
};

static int
dissect_x509ce_SEQUNCE_OF_PolicyQualifierInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   SEQUNCE_OF_PolicyQualifierInfo_sequence_of, hf_index, ett_x509ce_SEQUNCE_OF_PolicyQualifierInfo);

  return offset;
}
static int dissect_policyQualifiers(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_SEQUNCE_OF_PolicyQualifierInfo(FALSE, tvb, offset, pinfo, tree, hf_x509ce_policyQualifiers);
}

static ber_sequence PolicyInformation_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_policyIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_policyQualifiers },
  { 0, 0, 0, NULL }
};

static int
dissect_x509ce_PolicyInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                PolicyInformation_sequence, hf_index, ett_x509ce_PolicyInformation);

  return offset;
}
static int dissect_CertificatePoliciesSyntax_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_PolicyInformation(FALSE, tvb, offset, pinfo, tree, hf_x509ce_CertificatePoliciesSyntax_item);
}

static ber_sequence CertificatePoliciesSyntax_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_CertificatePoliciesSyntax_item },
};

static int
dissect_x509ce_CertificatePoliciesSyntax(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   CertificatePoliciesSyntax_sequence_of, hf_index, ett_x509ce_CertificatePoliciesSyntax);

  return offset;
}

static ber_sequence PolicyMappingsSyntax_item_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_issuerDomainPolicy },
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_subjectDomainPolicy },
  { 0, 0, 0, NULL }
};

static int
dissect_x509ce_PolicyMappingsSyntax_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                PolicyMappingsSyntax_item_sequence, hf_index, ett_x509ce_PolicyMappingsSyntax_item);

  return offset;
}
static int dissect_PolicyMappingsSyntax_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_PolicyMappingsSyntax_item(FALSE, tvb, offset, pinfo, tree, hf_x509ce_PolicyMappingsSyntax_item);
}

static ber_sequence PolicyMappingsSyntax_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_PolicyMappingsSyntax_item },
};

static int
dissect_x509ce_PolicyMappingsSyntax(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   PolicyMappingsSyntax_sequence_of, hf_index, ett_x509ce_PolicyMappingsSyntax);

  return offset;
}

static ber_sequence AttributesSyntax_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_AttributesSyntax_item },
};

static int
dissect_x509ce_AttributesSyntax(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   AttributesSyntax_sequence_of, hf_index, ett_x509ce_AttributesSyntax);

  return offset;
}


static int
dissect_x509ce_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_boolean(pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_cA(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_x509ce_cA);
}
static int dissect_containsUserPublicKeyCerts_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_BOOLEAN(TRUE, tvb, offset, pinfo, tree, hf_x509ce_containsUserPublicKeyCerts);
}
static int dissect_containsCACerts_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_BOOLEAN(TRUE, tvb, offset, pinfo, tree, hf_x509ce_containsCACerts);
}
static int dissect_indirectCRL_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_BOOLEAN(TRUE, tvb, offset, pinfo, tree, hf_x509ce_indirectCRL);
}
static int dissect_containsUserAttributeCerts_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_BOOLEAN(TRUE, tvb, offset, pinfo, tree, hf_x509ce_containsUserAttributeCerts);
}
static int dissect_containsAACerts_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_BOOLEAN(TRUE, tvb, offset, pinfo, tree, hf_x509ce_containsAACerts);
}
static int dissect_containsSOAPublicKeyCerts_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_BOOLEAN(TRUE, tvb, offset, pinfo, tree, hf_x509ce_containsSOAPublicKeyCerts);
}



static int
dissect_x509ce_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_integer(pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_pathLenConstraint(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_x509ce_pathLenConstraint);
}
static int dissect_startingNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_INTEGER(TRUE, tvb, offset, pinfo, tree, hf_x509ce_startingNumber);
}
static int dissect_endingNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_INTEGER(TRUE, tvb, offset, pinfo, tree, hf_x509ce_endingNumber);
}
static int dissect_modulus(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_x509ce_modulus);
}

static ber_sequence BasicConstraintsSyntax_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cA },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_pathLenConstraint },
  { 0, 0, 0, NULL }
};

static int
dissect_x509ce_BasicConstraintsSyntax(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                BasicConstraintsSyntax_sequence, hf_index, ett_x509ce_BasicConstraintsSyntax);

  return offset;
}



static int
dissect_x509ce_BaseDistance(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_integer(pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_minimum_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_BaseDistance(TRUE, tvb, offset, pinfo, tree, hf_x509ce_minimum);
}
static int dissect_maximum_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_BaseDistance(TRUE, tvb, offset, pinfo, tree, hf_x509ce_maximum);
}

static ber_sequence GeneralSubtree_sequence[] = {
  { BER_CLASS_CON, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_base },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_minimum_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_maximum_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x509ce_GeneralSubtree(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                GeneralSubtree_sequence, hf_index, ett_x509ce_GeneralSubtree);

  return offset;
}
static int dissect_GeneralSubtrees_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_GeneralSubtree(FALSE, tvb, offset, pinfo, tree, hf_x509ce_GeneralSubtrees_item);
}

static ber_sequence GeneralSubtrees_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_GeneralSubtrees_item },
};

static int
dissect_x509ce_GeneralSubtrees(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   GeneralSubtrees_sequence_of, hf_index, ett_x509ce_GeneralSubtrees);

  return offset;
}
static int dissect_permittedSubtrees_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_GeneralSubtrees(TRUE, tvb, offset, pinfo, tree, hf_x509ce_permittedSubtrees);
}
static int dissect_excludedSubtrees_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_GeneralSubtrees(TRUE, tvb, offset, pinfo, tree, hf_x509ce_excludedSubtrees);
}

static ber_sequence NameConstraintsSyntax_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_permittedSubtrees_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_excludedSubtrees_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x509ce_NameConstraintsSyntax(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                NameConstraintsSyntax_sequence, hf_index, ett_x509ce_NameConstraintsSyntax);

  return offset;
}



static int
dissect_x509ce_SkipCerts(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_integer(pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_requireExplicitPolicy_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_SkipCerts(TRUE, tvb, offset, pinfo, tree, hf_x509ce_requireExplicitPolicy);
}
static int dissect_inhibitPolicyMapping_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_SkipCerts(TRUE, tvb, offset, pinfo, tree, hf_x509ce_inhibitPolicyMapping);
}

static ber_sequence PolicyConstraintsSyntax_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_requireExplicitPolicy_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inhibitPolicyMapping_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x509ce_PolicyConstraintsSyntax(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                PolicyConstraintsSyntax_sequence, hf_index, ett_x509ce_PolicyConstraintsSyntax);

  return offset;
}



static int
dissect_x509ce_CRLNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_integer(pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_cRLNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_CRLNumber(TRUE, tvb, offset, pinfo, tree, hf_x509ce_cRLNumber);
}


static const value_string CRLReason_vals[] = {
  {   0, "unspecified" },
  {   1, "keyCompromise" },
  {   2, "cACompromise" },
  {   3, "affiliationChanged" },
  {   4, "superseded" },
  {   5, "cessationOfOperation" },
  {   6, "certificateHold" },
  {   8, "removeFromCRL" },
  {   9, "privilegeWithdrawn" },
  {  10, "aaCompromise" },
  { 0, NULL }
};


static int
dissect_x509ce_CRLReason(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_integer(pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static int
dissect_x509ce_HoldInstruction(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset,
                                         hf_index, NULL);

  return offset;
}


static const value_string DistributionPointName_vals[] = {
  {   0, "fullName" },
  {   1, "nameRelativeToCRLIssuer" },
  { 0, NULL }
};

static ber_choice DistributionPointName_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_fullName_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_nameRelativeToCRLIssuer_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x509ce_DistributionPointName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              DistributionPointName_choice, hf_index, ett_x509ce_DistributionPointName);

  return offset;
}
static int dissect_distributionPoint_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_DistributionPointName(TRUE, tvb, offset, pinfo, tree, hf_x509ce_distributionPoint);
}

static asn_namedbit OnlyCertificateTypes_bits[] = {
  {  0, &hf_x509ce_OnlyCertificateTypes_userPublicKey, -1, -1, NULL, NULL },
  {  1, &hf_x509ce_OnlyCertificateTypes_cA, -1, -1, NULL, NULL },
  {  2, &hf_x509ce_OnlyCertificateTypes_userAttribute, -1, -1, NULL, NULL },
  {  3, &hf_x509ce_OnlyCertificateTypes_aA, -1, -1, NULL, NULL },
  {  4, &hf_x509ce_OnlyCertificateTypes_sOAPublicKey, -1, -1, NULL, NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_x509ce_OnlyCertificateTypes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                 OnlyCertificateTypes_bits, hf_index, ett_x509ce_OnlyCertificateTypes,
                                 NULL);

  return offset;
}
static int dissect_onlyContains_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_OnlyCertificateTypes(TRUE, tvb, offset, pinfo, tree, hf_x509ce_onlyContains);
}

static asn_namedbit ReasonFlags_bits[] = {
  {  0, &hf_x509ce_ReasonFlags_unused, -1, -1, NULL, NULL },
  {  1, &hf_x509ce_ReasonFlags_keyCompromise, -1, -1, NULL, NULL },
  {  2, &hf_x509ce_ReasonFlags_cACompromise, -1, -1, NULL, NULL },
  {  3, &hf_x509ce_ReasonFlags_affiliationChanged, -1, -1, NULL, NULL },
  {  4, &hf_x509ce_ReasonFlags_superseded, -1, -1, NULL, NULL },
  {  5, &hf_x509ce_ReasonFlags_cessationOfOperation, -1, -1, NULL, NULL },
  {  6, &hf_x509ce_ReasonFlags_certificateHold, -1, -1, NULL, NULL },
  {  7, &hf_x509ce_ReasonFlags_privilegeWithdrawn, -1, -1, NULL, NULL },
  {  8, &hf_x509ce_ReasonFlags_aACompromise, -1, -1, NULL, NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_x509ce_ReasonFlags(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                 ReasonFlags_bits, hf_index, ett_x509ce_ReasonFlags,
                                 NULL);

  return offset;
}
static int dissect_onlySomeReasons_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_ReasonFlags(TRUE, tvb, offset, pinfo, tree, hf_x509ce_onlySomeReasons);
}
static int dissect_reasons_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_ReasonFlags(TRUE, tvb, offset, pinfo, tree, hf_x509ce_reasons);
}

static ber_sequence NumberRange_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_startingNumber_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_endingNumber_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_modulus },
  { 0, 0, 0, NULL }
};

static int
dissect_x509ce_NumberRange(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                NumberRange_sequence, hf_index, ett_x509ce_NumberRange);

  return offset;
}
static int dissect_serialNumberRange_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_NumberRange(TRUE, tvb, offset, pinfo, tree, hf_x509ce_serialNumberRange);
}
static int dissect_subjectKeyIdRange_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_NumberRange(TRUE, tvb, offset, pinfo, tree, hf_x509ce_subjectKeyIdRange);
}



static int
dissect_x509ce_CRLStreamIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_integer(pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_cRLStreamIdentifier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_CRLStreamIdentifier(TRUE, tvb, offset, pinfo, tree, hf_x509ce_cRLStreamIdentifier);
}

static ber_sequence BaseRevocationInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cRLStreamIdentifier_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_cRLNumber_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_baseThisUpdate_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x509ce_BaseRevocationInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                BaseRevocationInfo_sequence, hf_index, ett_x509ce_BaseRevocationInfo);

  return offset;
}
static int dissect_baseRevocationInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_BaseRevocationInfo(TRUE, tvb, offset, pinfo, tree, hf_x509ce_baseRevocationInfo);
}

static ber_sequence PerAuthorityScope_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_authorityName_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_distributionPoint_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_onlyContains_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_onlySomeReasons_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_serialNumberRange_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_subjectKeyIdRange_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_nameSubtrees_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_baseRevocationInfo_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x509ce_PerAuthorityScope(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                PerAuthorityScope_sequence, hf_index, ett_x509ce_PerAuthorityScope);

  return offset;
}
static int dissect_CRLScopeSyntax_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_PerAuthorityScope(FALSE, tvb, offset, pinfo, tree, hf_x509ce_CRLScopeSyntax_item);
}

static ber_sequence CRLScopeSyntax_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_CRLScopeSyntax_item },
};

static int
dissect_x509ce_CRLScopeSyntax(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   CRLScopeSyntax_sequence_of, hf_index, ett_x509ce_CRLScopeSyntax);

  return offset;
}
static int dissect_cRLScope(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_CRLScopeSyntax(FALSE, tvb, offset, pinfo, tree, hf_x509ce_cRLScope);
}

static ber_sequence DeltaRefInfo_sequence[] = {
  { BER_CLASS_CON, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_deltaLocation },
  { BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_lastDelta },
  { 0, 0, 0, NULL }
};

static int
dissect_x509ce_DeltaRefInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                DeltaRefInfo_sequence, hf_index, ett_x509ce_DeltaRefInfo);

  return offset;
}
static int dissect_deltaRefInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_DeltaRefInfo(TRUE, tvb, offset, pinfo, tree, hf_x509ce_deltaRefInfo);
}

static ber_sequence CRLReferral_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_issuer_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_location_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_deltaRefInfo_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cRLScope },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lastUpdate_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lastChangedCRL_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x509ce_CRLReferral(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                CRLReferral_sequence, hf_index, ett_x509ce_CRLReferral);

  return offset;
}
static int dissect_cRLReferral_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_CRLReferral(TRUE, tvb, offset, pinfo, tree, hf_x509ce_cRLReferral);
}


static const value_string StatusReferral_vals[] = {
  {   0, "cRLReferral" },
  { 0, NULL }
};

static ber_choice StatusReferral_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_cRLReferral_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x509ce_StatusReferral(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              StatusReferral_choice, hf_index, ett_x509ce_StatusReferral);

  return offset;
}
static int dissect_StatusReferrals_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_StatusReferral(FALSE, tvb, offset, pinfo, tree, hf_x509ce_StatusReferrals_item);
}

static ber_sequence StatusReferrals_sequence_of[1] = {
  { BER_CLASS_CON, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_StatusReferrals_item },
};

static int
dissect_x509ce_StatusReferrals(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   StatusReferrals_sequence_of, hf_index, ett_x509ce_StatusReferrals);

  return offset;
}


static const value_string OrderedListSyntax_vals[] = {
  {   0, "ascSerialNum" },
  {   1, "ascRevDate" },
  { 0, NULL }
};


static int
dissect_x509ce_OrderedListSyntax(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_integer(pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}

static ber_sequence DeltaInformation_sequence[] = {
  { BER_CLASS_CON, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_deltaLocation },
  { BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_nextDelta },
  { 0, 0, 0, NULL }
};

static int
dissect_x509ce_DeltaInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                DeltaInformation_sequence, hf_index, ett_x509ce_DeltaInformation);

  return offset;
}

static ber_sequence DistributionPoint_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_distributionPoint_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_reasons_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cRLIssuer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x509ce_DistributionPoint(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                DistributionPoint_sequence, hf_index, ett_x509ce_DistributionPoint);

  return offset;
}
static int dissect_CRLDistPointsSyntax_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_DistributionPoint(FALSE, tvb, offset, pinfo, tree, hf_x509ce_CRLDistPointsSyntax_item);
}

static ber_sequence CRLDistPointsSyntax_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_CRLDistPointsSyntax_item },
};

static int
dissect_x509ce_CRLDistPointsSyntax(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   CRLDistPointsSyntax_sequence_of, hf_index, ett_x509ce_CRLDistPointsSyntax);

  return offset;
}

static ber_sequence IssuingDistPointSyntax_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_distributionPoint_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_containsUserPublicKeyCerts_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_containsCACerts_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_onlySomeReasons_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_indirectCRL_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_containsUserAttributeCerts_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_containsAACerts_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_containsSOAPublicKeyCerts_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_x509ce_IssuingDistPointSyntax(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                IssuingDistPointSyntax_sequence, hf_index, ett_x509ce_IssuingDistPointSyntax);

  return offset;
}


static int
dissect_x509ce_BaseCRLNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_x509ce_CRLNumber(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}


/*--- End of included file: packet-x509ce-fn.c ---*/



static void
dissect_x509ce_subjectDirectoryAttributes_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_AttributesSyntax(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_subjectDirectoryAttributes);
}

static void
dissect_x509ce_subjectKeyIdentifier_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_SubjectKeyIdentifier(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_subjectKeyIdentifier);
}

static void
dissect_x509ce_keyUsage_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_KeyUsage(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_keyUsage);
}

static void
dissect_x509ce_privateKeyUsagePeriod_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_PrivateKeyUsagePeriod(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_privateKeyUsagePeriod);
}

static void
dissect_x509ce_subjectAltName_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_GeneralNames(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_subjectAltName);
}

static void
dissect_x509ce_issuerAltName_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_GeneralNames(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_issuerAltName);
}

static void
dissect_x509ce_basicConstraints_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_BasicConstraintsSyntax(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_basicConstraints);
}

static void
dissect_x509ce_cRLNumber_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_CRLNumber(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_cRLNumber);
}

static void
dissect_x509ce_reasonCode_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_CRLReason(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_reasonCode);
}

static void
dissect_x509ce_instructionCode_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_HoldInstruction(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_instructionCode);
}

static void
dissect_x509ce_invalidityDate_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_GeneralizedTime(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_invalidityDate);
}

static void
dissect_x509ce_deltaCRLIndicator_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_BaseCRLNumber(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_deltaCRLIndicator);
}

static void
dissect_x509ce_issuingDistributionPoint_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_IssuingDistPointSyntax(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_issuingDistributionPoint);
}

static void
dissect_x509ce_certificateIssuer_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_GeneralNames(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_certificateIssuer);
}

static void
dissect_x509ce_nameConstraints_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_NameConstraintsSyntax(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_nameConstraints);
}

static void
dissect_x509ce_cRLDistributionPoints_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_CRLDistPointsSyntax(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_cRLDistributionPoints);
}

static void
dissect_x509ce_certificatePolicies_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_CertificatePoliciesSyntax(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_certificatePolicies);
}

static void
dissect_x509ce_policyMappings_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_PolicyMappingsSyntax(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_policyMappings);
}

static void
dissect_x509ce_authorityKeyIdentifier_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_AuthorityKeyIdentifier(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_authorityKeyIdentifier);
}

static void
dissect_x509ce_policyConstraints_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_PolicyConstraintsSyntax(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_policyConstraints);
}

static void
dissect_x509ce_extKeyUsage_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_KeyPurposeIDs(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_extKeyUsage);
}

static void
dissect_x509ce_cRLStreamIdentifier_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_CRLStreamIdentifier(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_cRLStreamIdentifier);
}

static void
dissect_x509ce_cRLScope_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_CRLScopeSyntax(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_cRLScope);
}

static void
dissect_x509ce_statusReferrals_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_StatusReferrals(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_statusReferrals);
}

static void
dissect_x509ce_freshestCRL_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_CRLDistPointsSyntax(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_freshestCRL);
}

static void
dissect_x509ce_orderedList_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_OrderedListSyntax(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_orderedList);
}

static void
dissect_x509ce_baseUpdateTime_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_GeneralizedTime(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_baseUpdateTime);
}

static void
dissect_x509ce_deltaInfo_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_DeltaInformation(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_deltaInfo);
}

static void
dissect_x509ce_inhibitAnyPolicy_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_SkipCerts(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_inhibitAnyPolicy);
}

/*--- proto_register_x509ce ----------------------------------------------*/
void proto_register_x509ce(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_x509ce_id_ce_inhibitAnyPolicy,
      { "inhibitAnyPolicy", "x509ce.id_ce_inhibitAnyPolicy",
        FT_UINT32, BASE_DEC, NULL, 0,
        "inhibitAnyPolicy", HFILL }},
    { &hf_x509ce_id_ce_deltaInfo,
      { "deltaInfo", "x509ce.id_ce_deltaInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "deltaInfo", HFILL }},
    { &hf_x509ce_id_ce_baseUpdateTime,
      { "baseUpdateTime", "x509ce.id_ce_baseUpdateTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "baseUpdateTime", HFILL }},
    { &hf_x509ce_id_ce_orderedList,
      { "orderedList", "x509ce.id_ce_orderedList",
        FT_UINT32, BASE_DEC, VALS(OrderedListSyntax_vals), 0,
        "orderedList", HFILL }},
    { &hf_x509ce_id_ce_freshestCRL,
      { "freshestCRL", "x509ce.id_ce_freshestCRL",
        FT_NONE, BASE_NONE, NULL, 0,
        "freshestCRL", HFILL }},
    { &hf_x509ce_id_ce_statusReferrals,
      { "statusReferrals", "x509ce.id_ce_statusReferrals",
        FT_NONE, BASE_NONE, NULL, 0,
        "statusReferrals", HFILL }},
    { &hf_x509ce_id_ce_cRLScope,
      { "cRLScope", "x509ce.id_ce_cRLScope",
        FT_NONE, BASE_NONE, NULL, 0,
        "cRLScope", HFILL }},
    { &hf_x509ce_id_ce_cRLStreamIdentifier,
      { "cRLStreamIdentifier", "x509ce.id_ce_cRLStreamIdentifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "cRLStreamIdentifier", HFILL }},
    { &hf_x509ce_id_ce_extKeyUsage,
      { "extKeyUsage", "x509ce.id_ce_extKeyUsage",
        FT_NONE, BASE_NONE, NULL, 0,
        "extKeyUsage", HFILL }},
    { &hf_x509ce_id_ce_policyConstraints,
      { "policyConstraints", "x509ce.id_ce_policyConstraints",
        FT_NONE, BASE_NONE, NULL, 0,
        "policyConstraints", HFILL }},
    { &hf_x509ce_id_ce_authorityKeyIdentifier,
      { "authorityKeyIdentifier", "x509ce.id_ce_authorityKeyIdentifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "authorityKeyIdentifier", HFILL }},
    { &hf_x509ce_id_ce_policyMappings,
      { "policyMappings", "x509ce.id_ce_policyMappings",
        FT_NONE, BASE_NONE, NULL, 0,
        "policyMappings", HFILL }},
    { &hf_x509ce_id_ce_certificatePolicies,
      { "certificatePolicies", "x509ce.id_ce_certificatePolicies",
        FT_NONE, BASE_NONE, NULL, 0,
        "certificatePolicies", HFILL }},
    { &hf_x509ce_id_ce_cRLDistributionPoints,
      { "cRLDistributionPoints", "x509ce.id_ce_cRLDistributionPoints",
        FT_NONE, BASE_NONE, NULL, 0,
        "cRLDistributionPoints", HFILL }},
    { &hf_x509ce_id_ce_nameConstraints,
      { "nameConstraints", "x509ce.id_ce_nameConstraints",
        FT_NONE, BASE_NONE, NULL, 0,
        "nameConstraints", HFILL }},
    { &hf_x509ce_id_ce_certificateIssuer,
      { "certificateIssuer", "x509ce.id_ce_certificateIssuer",
        FT_NONE, BASE_NONE, NULL, 0,
        "certificateIssuer", HFILL }},
    { &hf_x509ce_id_ce_issuingDistributionPoint,
      { "issuingDistributionPoint", "x509ce.id_ce_issuingDistributionPoint",
        FT_NONE, BASE_NONE, NULL, 0,
        "issuingDistributionPoint", HFILL }},
    { &hf_x509ce_id_ce_deltaCRLIndicator,
      { "deltaCRLIndicator", "x509ce.id_ce_deltaCRLIndicator",
        FT_UINT32, BASE_DEC, VALS(CRLReason_vals), 0,
        "deltaCRLIndicator", HFILL }},
    { &hf_x509ce_id_ce_invalidityDate,
      { "invalidityDate", "x509ce.id_ce_invalidityDate",
        FT_STRING, BASE_NONE, NULL, 0,
        "invalidityDate", HFILL }},
    { &hf_x509ce_id_ce_instructionCode,
      { "instructionCode", "x509ce.id_ce_instructionCode",
        FT_STRING, BASE_NONE, NULL, 0,
        "instructionCode", HFILL }},
    { &hf_x509ce_id_ce_reasonCode,
      { "reasonCode", "x509ce.id_ce_reasonCode",
        FT_UINT32, BASE_DEC, VALS(CRLReason_vals), 0,
        "reasonCode", HFILL }},
    { &hf_x509ce_id_ce_cRLNumber,
      { "cRLNumber", "x509ce.id_ce_cRLNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cRLNumber", HFILL }},
    { &hf_x509ce_id_ce_basicConstraints,
      { "basicConstraints", "x509ce.id_ce_basicConstraints",
        FT_NONE, BASE_NONE, NULL, 0,
        "basicConstraints", HFILL }},
    { &hf_x509ce_id_ce_issuerAltName,
      { "issuerAltName", "x509ce.id_ce_issuerAltName",
        FT_NONE, BASE_NONE, NULL, 0,
        "issuerAltName", HFILL }},
    { &hf_x509ce_id_ce_subjectAltName,
      { "subjectAltName", "x509ce.id_ce_subjectAltName",
        FT_NONE, BASE_NONE, NULL, 0,
        "subjectAltName", HFILL }},
    { &hf_x509ce_id_ce_privateKeyUsagePeriod,
      { "privateKeyUsagePeriod", "x509ce.id_ce_privateKeyUsagePeriod",
        FT_NONE, BASE_NONE, NULL, 0,
        "privateKeyUsagePeriod", HFILL }},
    { &hf_x509ce_id_ce_subjectDirectoryAttributes,
      { "subjectDirectoryAttributes", "x509ce.id_ce_subjectDirectoryAttributes",
        FT_NONE, BASE_NONE, NULL, 0,
        "subjectDirectoryAttributes", HFILL }},
    { &hf_x509ce_id_ce_subjectKeyIdentifier,
      { "subjectKeyIdentifier", "x509ce.id_ce_subjectKeyIdentifier",
        FT_BYTES, BASE_HEX, NULL, 0,
        "subjectKeyIdentifier", HFILL }},
    { &hf_x509ce_id_ce_keyUsage,
      { "keyUsage", "x509ce.id_ce_keyUsage",
        FT_BYTES, BASE_HEX, NULL, 0,
        "keyUsage", HFILL }},

/*--- Included file: packet-x509ce-hfarr.c ---*/

/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* packet-x509ce-hfarr.c                                                      */
/* ../../tools/asn2eth.py -X -b -p x509ce -c x509ce.cnf -s packet-x509ce-template CertificateExtensions.asn */

    { &hf_x509ce_keyIdentifier,
      { "keyIdentifier", "x509ce.keyIdentifier",
        FT_BYTES, BASE_HEX, NULL, 0,
        "AuthorityKeyIdentifier/keyIdentifier", HFILL }},
    { &hf_x509ce_authorityCertIssuer,
      { "authorityCertIssuer", "x509ce.authorityCertIssuer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AuthorityKeyIdentifier/authorityCertIssuer", HFILL }},
    { &hf_x509ce_authorityCertSerialNumber,
      { "authorityCertSerialNumber", "x509ce.authorityCertSerialNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        "AuthorityKeyIdentifier/authorityCertSerialNumber", HFILL }},
    { &hf_x509ce_KeyPurposeIDs_item,
      { "Item[##]", "x509ce.KeyPurposeIDs_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "KeyPurposeIDs/_item", HFILL }},
    { &hf_x509ce_notBefore,
      { "notBefore", "x509ce.notBefore",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrivateKeyUsagePeriod/notBefore", HFILL }},
    { &hf_x509ce_notAfter,
      { "notAfter", "x509ce.notAfter",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrivateKeyUsagePeriod/notAfter", HFILL }},
    { &hf_x509ce_CertificatePoliciesSyntax_item,
      { "Item[##]", "x509ce.CertificatePoliciesSyntax_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertificatePoliciesSyntax/_item", HFILL }},
    { &hf_x509ce_policyIdentifier,
      { "policyIdentifier", "x509ce.policyIdentifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "PolicyInformation/policyIdentifier", HFILL }},
    { &hf_x509ce_policyQualifiers,
      { "policyQualifiers", "x509ce.policyQualifiers",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PolicyInformation/policyQualifiers", HFILL }},
    { &hf_x509ce_policyQualifiers_item,
      { "Item[##]", "x509ce.policyQualifiers_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "PolicyInformation/policyQualifiers/_item", HFILL }},
    { &hf_x509ce_PolicyMappingsSyntax_item,
      { "Item[##]", "x509ce.PolicyMappingsSyntax_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "PolicyMappingsSyntax/_item", HFILL }},
    { &hf_x509ce_issuerDomainPolicy,
      { "issuerDomainPolicy", "x509ce.issuerDomainPolicy",
        FT_STRING, BASE_NONE, NULL, 0,
        "PolicyMappingsSyntax/_item/issuerDomainPolicy", HFILL }},
    { &hf_x509ce_subjectDomainPolicy,
      { "subjectDomainPolicy", "x509ce.subjectDomainPolicy",
        FT_STRING, BASE_NONE, NULL, 0,
        "PolicyMappingsSyntax/_item/subjectDomainPolicy", HFILL }},
    { &hf_x509ce_GeneralNames_item,
      { "Item[##]", "x509ce.GeneralNames_item",
        FT_UINT32, BASE_DEC, VALS(GeneralName_vals), 0,
        "GeneralNames/_item", HFILL }},
    { &hf_x509ce_rfc822Name,
      { "rfc822Name", "x509ce.rfc822Name",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralName/rfc822Name", HFILL }},
    { &hf_x509ce_dNSName,
      { "dNSName", "x509ce.dNSName",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralName/dNSName", HFILL }},
    { &hf_x509ce_directoryName,
      { "directoryName", "x509ce.directoryName",
        FT_UINT32, BASE_DEC, VALS(Name_vals), 0,
        "GeneralName/directoryName", HFILL }},
    { &hf_x509ce_uniformResourceIdentifier,
      { "uniformResourceIdentifier", "x509ce.uniformResourceIdentifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralName/uniformResourceIdentifier", HFILL }},
    { &hf_x509ce_iPAddress,
      { "iPAddress", "x509ce.iPAddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "GeneralName/iPAddress", HFILL }},
    { &hf_x509ce_registeredID,
      { "registeredID", "x509ce.registeredID",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralName/registeredID", HFILL }},
    { &hf_x509ce_AttributesSyntax_item,
      { "Item[##]", "x509ce.AttributesSyntax_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributesSyntax/_item", HFILL }},
    { &hf_x509ce_cA,
      { "cA", "x509ce.cA",
        FT_BOOLEAN, 8, NULL, 0,
        "BasicConstraintsSyntax/cA", HFILL }},
    { &hf_x509ce_pathLenConstraint,
      { "pathLenConstraint", "x509ce.pathLenConstraint",
        FT_INT32, BASE_DEC, NULL, 0,
        "BasicConstraintsSyntax/pathLenConstraint", HFILL }},
    { &hf_x509ce_permittedSubtrees,
      { "permittedSubtrees", "x509ce.permittedSubtrees",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NameConstraintsSyntax/permittedSubtrees", HFILL }},
    { &hf_x509ce_excludedSubtrees,
      { "excludedSubtrees", "x509ce.excludedSubtrees",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NameConstraintsSyntax/excludedSubtrees", HFILL }},
    { &hf_x509ce_GeneralSubtrees_item,
      { "Item[##]", "x509ce.GeneralSubtrees_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "GeneralSubtrees/_item", HFILL }},
    { &hf_x509ce_base,
      { "base", "x509ce.base",
        FT_UINT32, BASE_DEC, VALS(GeneralName_vals), 0,
        "GeneralSubtree/base", HFILL }},
    { &hf_x509ce_minimum,
      { "minimum", "x509ce.minimum",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GeneralSubtree/minimum", HFILL }},
    { &hf_x509ce_maximum,
      { "maximum", "x509ce.maximum",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GeneralSubtree/maximum", HFILL }},
    { &hf_x509ce_requireExplicitPolicy,
      { "requireExplicitPolicy", "x509ce.requireExplicitPolicy",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PolicyConstraintsSyntax/requireExplicitPolicy", HFILL }},
    { &hf_x509ce_inhibitPolicyMapping,
      { "inhibitPolicyMapping", "x509ce.inhibitPolicyMapping",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PolicyConstraintsSyntax/inhibitPolicyMapping", HFILL }},
    { &hf_x509ce_CRLScopeSyntax_item,
      { "Item[##]", "x509ce.CRLScopeSyntax_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "CRLScopeSyntax/_item", HFILL }},
    { &hf_x509ce_authorityName,
      { "authorityName", "x509ce.authorityName",
        FT_UINT32, BASE_DEC, VALS(GeneralName_vals), 0,
        "PerAuthorityScope/authorityName", HFILL }},
    { &hf_x509ce_distributionPoint,
      { "distributionPoint", "x509ce.distributionPoint",
        FT_UINT32, BASE_DEC, VALS(DistributionPointName_vals), 0,
        "", HFILL }},
    { &hf_x509ce_onlyContains,
      { "onlyContains", "x509ce.onlyContains",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PerAuthorityScope/onlyContains", HFILL }},
    { &hf_x509ce_onlySomeReasons,
      { "onlySomeReasons", "x509ce.onlySomeReasons",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_x509ce_serialNumberRange,
      { "serialNumberRange", "x509ce.serialNumberRange",
        FT_NONE, BASE_NONE, NULL, 0,
        "PerAuthorityScope/serialNumberRange", HFILL }},
    { &hf_x509ce_subjectKeyIdRange,
      { "subjectKeyIdRange", "x509ce.subjectKeyIdRange",
        FT_NONE, BASE_NONE, NULL, 0,
        "PerAuthorityScope/subjectKeyIdRange", HFILL }},
    { &hf_x509ce_nameSubtrees,
      { "nameSubtrees", "x509ce.nameSubtrees",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PerAuthorityScope/nameSubtrees", HFILL }},
    { &hf_x509ce_baseRevocationInfo,
      { "baseRevocationInfo", "x509ce.baseRevocationInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "PerAuthorityScope/baseRevocationInfo", HFILL }},
    { &hf_x509ce_startingNumber,
      { "startingNumber", "x509ce.startingNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        "NumberRange/startingNumber", HFILL }},
    { &hf_x509ce_endingNumber,
      { "endingNumber", "x509ce.endingNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        "NumberRange/endingNumber", HFILL }},
    { &hf_x509ce_modulus,
      { "modulus", "x509ce.modulus",
        FT_INT32, BASE_DEC, NULL, 0,
        "NumberRange/modulus", HFILL }},
    { &hf_x509ce_cRLStreamIdentifier,
      { "cRLStreamIdentifier", "x509ce.cRLStreamIdentifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        "BaseRevocationInfo/cRLStreamIdentifier", HFILL }},
    { &hf_x509ce_cRLNumber,
      { "cRLNumber", "x509ce.cRLNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "BaseRevocationInfo/cRLNumber", HFILL }},
    { &hf_x509ce_baseThisUpdate,
      { "baseThisUpdate", "x509ce.baseThisUpdate",
        FT_STRING, BASE_NONE, NULL, 0,
        "BaseRevocationInfo/baseThisUpdate", HFILL }},
    { &hf_x509ce_StatusReferrals_item,
      { "Item[##]", "x509ce.StatusReferrals_item",
        FT_UINT32, BASE_DEC, VALS(StatusReferral_vals), 0,
        "StatusReferrals/_item", HFILL }},
    { &hf_x509ce_cRLReferral,
      { "cRLReferral", "x509ce.cRLReferral",
        FT_NONE, BASE_NONE, NULL, 0,
        "StatusReferral/cRLReferral", HFILL }},
    { &hf_x509ce_issuer,
      { "issuer", "x509ce.issuer",
        FT_UINT32, BASE_DEC, VALS(GeneralName_vals), 0,
        "CRLReferral/issuer", HFILL }},
    { &hf_x509ce_location,
      { "location", "x509ce.location",
        FT_UINT32, BASE_DEC, VALS(GeneralName_vals), 0,
        "CRLReferral/location", HFILL }},
    { &hf_x509ce_deltaRefInfo,
      { "deltaRefInfo", "x509ce.deltaRefInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "CRLReferral/deltaRefInfo", HFILL }},
    { &hf_x509ce_cRLScope,
      { "cRLScope", "x509ce.cRLScope",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CRLReferral/cRLScope", HFILL }},
    { &hf_x509ce_lastUpdate,
      { "lastUpdate", "x509ce.lastUpdate",
        FT_STRING, BASE_NONE, NULL, 0,
        "CRLReferral/lastUpdate", HFILL }},
    { &hf_x509ce_lastChangedCRL,
      { "lastChangedCRL", "x509ce.lastChangedCRL",
        FT_STRING, BASE_NONE, NULL, 0,
        "CRLReferral/lastChangedCRL", HFILL }},
    { &hf_x509ce_deltaLocation,
      { "deltaLocation", "x509ce.deltaLocation",
        FT_UINT32, BASE_DEC, VALS(GeneralName_vals), 0,
        "", HFILL }},
    { &hf_x509ce_lastDelta,
      { "lastDelta", "x509ce.lastDelta",
        FT_STRING, BASE_NONE, NULL, 0,
        "DeltaRefInfo/lastDelta", HFILL }},
    { &hf_x509ce_nextDelta,
      { "nextDelta", "x509ce.nextDelta",
        FT_STRING, BASE_NONE, NULL, 0,
        "DeltaInformation/nextDelta", HFILL }},
    { &hf_x509ce_CRLDistPointsSyntax_item,
      { "Item[##]", "x509ce.CRLDistPointsSyntax_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "CRLDistPointsSyntax/_item", HFILL }},
    { &hf_x509ce_reasons,
      { "reasons", "x509ce.reasons",
        FT_BYTES, BASE_HEX, NULL, 0,
        "DistributionPoint/reasons", HFILL }},
    { &hf_x509ce_cRLIssuer,
      { "cRLIssuer", "x509ce.cRLIssuer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DistributionPoint/cRLIssuer", HFILL }},
    { &hf_x509ce_fullName,
      { "fullName", "x509ce.fullName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DistributionPointName/fullName", HFILL }},
    { &hf_x509ce_nameRelativeToCRLIssuer,
      { "nameRelativeToCRLIssuer", "x509ce.nameRelativeToCRLIssuer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DistributionPointName/nameRelativeToCRLIssuer", HFILL }},
    { &hf_x509ce_containsUserPublicKeyCerts,
      { "containsUserPublicKeyCerts", "x509ce.containsUserPublicKeyCerts",
        FT_BOOLEAN, 8, NULL, 0,
        "IssuingDistPointSyntax/containsUserPublicKeyCerts", HFILL }},
    { &hf_x509ce_containsCACerts,
      { "containsCACerts", "x509ce.containsCACerts",
        FT_BOOLEAN, 8, NULL, 0,
        "IssuingDistPointSyntax/containsCACerts", HFILL }},
    { &hf_x509ce_indirectCRL,
      { "indirectCRL", "x509ce.indirectCRL",
        FT_BOOLEAN, 8, NULL, 0,
        "IssuingDistPointSyntax/indirectCRL", HFILL }},
    { &hf_x509ce_containsUserAttributeCerts,
      { "containsUserAttributeCerts", "x509ce.containsUserAttributeCerts",
        FT_BOOLEAN, 8, NULL, 0,
        "IssuingDistPointSyntax/containsUserAttributeCerts", HFILL }},
    { &hf_x509ce_containsAACerts,
      { "containsAACerts", "x509ce.containsAACerts",
        FT_BOOLEAN, 8, NULL, 0,
        "IssuingDistPointSyntax/containsAACerts", HFILL }},
    { &hf_x509ce_containsSOAPublicKeyCerts,
      { "containsSOAPublicKeyCerts", "x509ce.containsSOAPublicKeyCerts",
        FT_BOOLEAN, 8, NULL, 0,
        "IssuingDistPointSyntax/containsSOAPublicKeyCerts", HFILL }},
    { &hf_x509ce_KeyUsage_digitalSignature,
      { "digitalSignature", "x509ce.digitalSignature",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_x509ce_KeyUsage_nonRepudiation,
      { "nonRepudiation", "x509ce.nonRepudiation",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_x509ce_KeyUsage_keyEncipherment,
      { "keyEncipherment", "x509ce.keyEncipherment",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_x509ce_KeyUsage_dataEncipherment,
      { "dataEncipherment", "x509ce.dataEncipherment",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_x509ce_KeyUsage_keyAgreement,
      { "keyAgreement", "x509ce.keyAgreement",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_x509ce_KeyUsage_keyCertSign,
      { "keyCertSign", "x509ce.keyCertSign",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_x509ce_KeyUsage_cRLSign,
      { "cRLSign", "x509ce.cRLSign",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_x509ce_KeyUsage_encipherOnly,
      { "encipherOnly", "x509ce.encipherOnly",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_x509ce_KeyUsage_decipherOnly,
      { "decipherOnly", "x509ce.decipherOnly",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_x509ce_OnlyCertificateTypes_userPublicKey,
      { "userPublicKey", "x509ce.userPublicKey",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_x509ce_OnlyCertificateTypes_cA,
      { "cA", "x509ce.cA",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_x509ce_OnlyCertificateTypes_userAttribute,
      { "userAttribute", "x509ce.userAttribute",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_x509ce_OnlyCertificateTypes_aA,
      { "aA", "x509ce.aA",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_x509ce_OnlyCertificateTypes_sOAPublicKey,
      { "sOAPublicKey", "x509ce.sOAPublicKey",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_x509ce_ReasonFlags_unused,
      { "unused", "x509ce.unused",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_x509ce_ReasonFlags_keyCompromise,
      { "keyCompromise", "x509ce.keyCompromise",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_x509ce_ReasonFlags_cACompromise,
      { "cACompromise", "x509ce.cACompromise",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_x509ce_ReasonFlags_affiliationChanged,
      { "affiliationChanged", "x509ce.affiliationChanged",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_x509ce_ReasonFlags_superseded,
      { "superseded", "x509ce.superseded",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_x509ce_ReasonFlags_cessationOfOperation,
      { "cessationOfOperation", "x509ce.cessationOfOperation",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_x509ce_ReasonFlags_certificateHold,
      { "certificateHold", "x509ce.certificateHold",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_x509ce_ReasonFlags_privilegeWithdrawn,
      { "privilegeWithdrawn", "x509ce.privilegeWithdrawn",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_x509ce_ReasonFlags_aACompromise,
      { "aACompromise", "x509ce.aACompromise",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},

/*--- End of included file: packet-x509ce-hfarr.c ---*/

  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-x509ce-ettarr.c ---*/

/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* packet-x509ce-ettarr.c                                                     */
/* ../../tools/asn2eth.py -X -b -p x509ce -c x509ce.cnf -s packet-x509ce-template CertificateExtensions.asn */

    &ett_x509ce_AuthorityKeyIdentifier,
    &ett_x509ce_KeyUsage,
    &ett_x509ce_KeyPurposeIDs,
    &ett_x509ce_PrivateKeyUsagePeriod,
    &ett_x509ce_CertificatePoliciesSyntax,
    &ett_x509ce_PolicyInformation,
    &ett_x509ce_SEQUNCE_OF_PolicyQualifierInfo,
    &ett_x509ce_PolicyQualifierInfo,
    &ett_x509ce_PolicyMappingsSyntax,
    &ett_x509ce_PolicyMappingsSyntax_item,
    &ett_x509ce_GeneralNames,
    &ett_x509ce_GeneralName,
    &ett_x509ce_AttributesSyntax,
    &ett_x509ce_BasicConstraintsSyntax,
    &ett_x509ce_NameConstraintsSyntax,
    &ett_x509ce_GeneralSubtrees,
    &ett_x509ce_GeneralSubtree,
    &ett_x509ce_PolicyConstraintsSyntax,
    &ett_x509ce_CRLScopeSyntax,
    &ett_x509ce_PerAuthorityScope,
    &ett_x509ce_OnlyCertificateTypes,
    &ett_x509ce_NumberRange,
    &ett_x509ce_BaseRevocationInfo,
    &ett_x509ce_StatusReferrals,
    &ett_x509ce_StatusReferral,
    &ett_x509ce_CRLReferral,
    &ett_x509ce_DeltaRefInfo,
    &ett_x509ce_DeltaInformation,
    &ett_x509ce_CRLDistPointsSyntax,
    &ett_x509ce_DistributionPoint,
    &ett_x509ce_DistributionPointName,
    &ett_x509ce_ReasonFlags,
    &ett_x509ce_IssuingDistPointSyntax,

/*--- End of included file: packet-x509ce-ettarr.c ---*/

  };

  /* Register protocol */
  proto_x509ce = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_x509ce, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_x509ce -------------------------------------------*/
void proto_reg_handoff_x509ce(void) {
	register_ber_oid_dissector("2.5.29.9", dissect_x509ce_subjectDirectoryAttributes_callback, proto_x509ce, "id-ce-subjectDirectoryAttributes");
	register_ber_oid_dissector("2.5.29.14", dissect_x509ce_subjectKeyIdentifier_callback, proto_x509ce, "id-ce-subjectKeyIdentifier");
	register_ber_oid_dissector("2.5.29.15", dissect_x509ce_keyUsage_callback, proto_x509ce, "id-ce-keyUsage");
	register_ber_oid_dissector("2.5.29.16", dissect_x509ce_privateKeyUsagePeriod_callback, proto_x509ce, "id-ce-privateKeyUsagePeriod");
	register_ber_oid_dissector("2.5.29.17", dissect_x509ce_subjectAltName_callback, proto_x509ce, "id-ce-subjectAltName");
	register_ber_oid_dissector("2.5.29.18", dissect_x509ce_issuerAltName_callback, proto_x509ce, "id-ce-issuerAltName");
	register_ber_oid_dissector("2.5.29.19", dissect_x509ce_basicConstraints_callback, proto_x509ce, "id-ce-basicConstraints");
	register_ber_oid_dissector("2.5.29.20", dissect_x509ce_cRLNumber_callback, proto_x509ce, "id-ce-cRLNumber");
	register_ber_oid_dissector("2.5.29.21", dissect_x509ce_reasonCode_callback, proto_x509ce, "id-ce-reasonCode");
	register_ber_oid_dissector("2.5.29.23", dissect_x509ce_instructionCode_callback, proto_x509ce, "id-ce-instructionCode");
	register_ber_oid_dissector("2.5.29.24", dissect_x509ce_invalidityDate_callback, proto_x509ce, "id-ce-invalidityDate");
	register_ber_oid_dissector("2.5.29.27", dissect_x509ce_deltaCRLIndicator_callback, proto_x509ce, "id-ce-deltaCRLIndicator");
	register_ber_oid_dissector("2.5.29.28", dissect_x509ce_issuingDistributionPoint_callback, proto_x509ce, "id-ce-issuingDistributionPoint");
	register_ber_oid_dissector("2.5.29.29", dissect_x509ce_certificateIssuer_callback, proto_x509ce, "id-ce-certificateIssuer");
	register_ber_oid_dissector("2.5.29.30", dissect_x509ce_nameConstraints_callback, proto_x509ce, "id-ce-nameConstraints");
	register_ber_oid_dissector("2.5.29.31", dissect_x509ce_cRLDistributionPoints_callback, proto_x509ce, "id-ce-cRLDistributionPoints");
	register_ber_oid_dissector("2.5.29.32", dissect_x509ce_certificatePolicies_callback, proto_x509ce, "id-ce-certificatePolicies");
	register_ber_oid_dissector("2.5.29.33", dissect_x509ce_policyMappings_callback, proto_x509ce, "id-ce-policyMappings");
	register_ber_oid_dissector("2.5.29.35", dissect_x509ce_authorityKeyIdentifier_callback, proto_x509ce, "id-ce-authorityKeyIdentifier");
	register_ber_oid_dissector("2.5.29.36", dissect_x509ce_policyConstraints_callback, proto_x509ce, "id-ce-policyConstraints");
	register_ber_oid_dissector("2.5.29.37", dissect_x509ce_extKeyUsage_callback, proto_x509ce, "id-ce-extKeyUsage");
	register_ber_oid_dissector("2.5.29.40", dissect_x509ce_cRLStreamIdentifier_callback, proto_x509ce, "id-ce-cRLStreamIdentifier");
	register_ber_oid_dissector("2.5.29.44", dissect_x509ce_cRLScope_callback, proto_x509ce, "id-ce-cRLScope");
	register_ber_oid_dissector("2.5.29.45", dissect_x509ce_statusReferrals_callback, proto_x509ce, "id-ce-statusReferrals");
	register_ber_oid_dissector("2.5.29.46", dissect_x509ce_freshestCRL_callback, proto_x509ce, "id-ce-freshestCRL");
	register_ber_oid_dissector("2.5.29.47", dissect_x509ce_orderedList_callback, proto_x509ce, "id-ce-orderedList");
	register_ber_oid_dissector("2.5.29.51", dissect_x509ce_baseUpdateTime_callback, proto_x509ce, "id-ce-baseUpdateTime");
	register_ber_oid_dissector("2.5.29.53", dissect_x509ce_deltaInfo_callback, proto_x509ce, "id-ce-deltaInfo");
	register_ber_oid_dissector("2.5.29.54", dissect_x509ce_inhibitAnyPolicy_callback, proto_x509ce, "id-ce-inhibitAnyPolicy");
}

