/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* .\packet-x509ce.c                                                          */
/* ../../tools/asn2eth.py -X -b -e -p x509ce -c x509ce.cnf -s packet-x509ce-template CertificateExtensions.asn */

/* Input file: packet-x509ce-template.c */

/* packet-x509ce.c
 * Routines for X.509 Certificate Extensions packet dissection
 *  Ronnie Sahlberg 2004
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
#include "packet-x509ce.h"
#include "packet-x509af.h"
#include "packet-x509if.h"
#include "packet-x509sat.h"

#define PNAME  "X.509 Certificate Extensions"
#define PSNAME "X509CE"
#define PFNAME "x509ce"

/* Initialize the protocol and registered fields */
int proto_x509ce = -1;
static int hf_x509ce_id_ce_invalidityDate = -1;
static int hf_x509ce_id_ce_baseUpdateTime = -1;
static int hf_x509ce_object_identifier_id = -1;
static int hf_x509ce_IPAddress = -1;

/*--- Included file: packet-x509ce-hf.c ---*/

static int hf_x509ce_AuthorityKeyIdentifier_PDU = -1;  /* AuthorityKeyIdentifier */
static int hf_x509ce_SubjectKeyIdentifier_PDU = -1;  /* SubjectKeyIdentifier */
static int hf_x509ce_KeyUsage_PDU = -1;           /* KeyUsage */
static int hf_x509ce_KeyPurposeIDs_PDU = -1;      /* KeyPurposeIDs */
static int hf_x509ce_PrivateKeyUsagePeriod_PDU = -1;  /* PrivateKeyUsagePeriod */
static int hf_x509ce_CertificatePoliciesSyntax_PDU = -1;  /* CertificatePoliciesSyntax */
static int hf_x509ce_PolicyMappingsSyntax_PDU = -1;  /* PolicyMappingsSyntax */
static int hf_x509ce_GeneralNames_PDU = -1;       /* GeneralNames */
static int hf_x509ce_AttributesSyntax_PDU = -1;   /* AttributesSyntax */
static int hf_x509ce_BasicConstraintsSyntax_PDU = -1;  /* BasicConstraintsSyntax */
static int hf_x509ce_NameConstraintsSyntax_PDU = -1;  /* NameConstraintsSyntax */
static int hf_x509ce_PolicyConstraintsSyntax_PDU = -1;  /* PolicyConstraintsSyntax */
static int hf_x509ce_SkipCerts_PDU = -1;          /* SkipCerts */
static int hf_x509ce_CRLNumber_PDU = -1;          /* CRLNumber */
static int hf_x509ce_CRLReason_PDU = -1;          /* CRLReason */
static int hf_x509ce_HoldInstruction_PDU = -1;    /* HoldInstruction */
static int hf_x509ce_CRLScopeSyntax_PDU = -1;     /* CRLScopeSyntax */
static int hf_x509ce_StatusReferrals_PDU = -1;    /* StatusReferrals */
static int hf_x509ce_CRLStreamIdentifier_PDU = -1;  /* CRLStreamIdentifier */
static int hf_x509ce_OrderedListSyntax_PDU = -1;  /* OrderedListSyntax */
static int hf_x509ce_DeltaInformation_PDU = -1;   /* DeltaInformation */
static int hf_x509ce_CRLDistPointsSyntax_PDU = -1;  /* CRLDistPointsSyntax */
static int hf_x509ce_IssuingDistPointSyntax_PDU = -1;  /* IssuingDistPointSyntax */
static int hf_x509ce_BaseCRLNumber_PDU = -1;      /* BaseCRLNumber */
static int hf_x509ce_keyIdentifier = -1;          /* KeyIdentifier */
static int hf_x509ce_authorityCertIssuer = -1;    /* GeneralNames */
static int hf_x509ce_authorityCertSerialNumber = -1;  /* CertificateSerialNumber */
static int hf_x509ce_KeyPurposeIDs_item = -1;     /* KeyPurposeId */
static int hf_x509ce_notBefore = -1;              /* GeneralizedTime */
static int hf_x509ce_notAfter = -1;               /* GeneralizedTime */
static int hf_x509ce_CertificatePoliciesSyntax_item = -1;  /* PolicyInformation */
static int hf_x509ce_policyIdentifier = -1;       /* CertPolicyId */
static int hf_x509ce_policyQualifiers = -1;       /* SEQUENCE_SIZE_1_MAX_OF_PolicyQualifierInfo */
static int hf_x509ce_policyQualifiers_item = -1;  /* PolicyQualifierInfo */
static int hf_x509ce_policyQualifierId = -1;      /* PolicyQualifierId */
static int hf_x509ce_qualifier = -1;              /* PolicyQualifierValue */
static int hf_x509ce_PolicyMappingsSyntax_item = -1;  /* PolicyMappingsSyntax_item */
static int hf_x509ce_issuerDomainPolicy = -1;     /* CertPolicyId */
static int hf_x509ce_subjectDomainPolicy = -1;    /* CertPolicyId */
static int hf_x509ce_GeneralNames_item = -1;      /* GeneralName */
static int hf_x509ce_rfc822Name = -1;             /* IA5String */
static int hf_x509ce_dNSName = -1;                /* IA5String */
static int hf_x509ce_directoryName = -1;          /* Name */
static int hf_x509ce_ediPartyName = -1;           /* EDIPartyName */
static int hf_x509ce_uniformResourceIdentifier = -1;  /* IA5String */
static int hf_x509ce_iPAddress = -1;              /* T_iPAddress */
static int hf_x509ce_registeredID = -1;           /* OBJECT_IDENTIFIER */
static int hf_x509ce_nameAssigner = -1;           /* DirectoryString */
static int hf_x509ce_partyName = -1;              /* DirectoryString */
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
static int hf_x509ce_crlr_issuer = -1;            /* GeneralName */
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
static int hf_x509ce_serialNumber = -1;           /* CertificateSerialNumber */
static int hf_x509ce_issuer = -1;                 /* Name */
static int hf_x509ce_subjectKeyIdentifier = -1;   /* SubjectKeyIdentifier */
static int hf_x509ce_authorityKeyIdentifier = -1;  /* AuthorityKeyIdentifier */
static int hf_x509ce_privateKeyValid = -1;        /* GeneralizedTime */
static int hf_x509ce_subjectPublicKeyAlgID = -1;  /* OBJECT_IDENTIFIER */
static int hf_x509ce_keyUsage = -1;               /* KeyUsage */
static int hf_x509ce_subjectAltName = -1;         /* AltNameType */
static int hf_x509ce_policy = -1;                 /* CertPolicySet */
static int hf_x509ce_pathToName = -1;             /* Name */
static int hf_x509ce_subject = -1;                /* Name */
static int hf_x509ce_nameConstraints = -1;        /* NameConstraintsSyntax */
static int hf_x509ce_builtinNameForm = -1;        /* T_builtinNameForm */
static int hf_x509ce_otherNameForm = -1;          /* OBJECT_IDENTIFIER */
static int hf_x509ce_CertPolicySet_item = -1;     /* CertPolicyId */
static int hf_x509ce_cpea_issuedToThisCAAssertion = -1;  /* CertificateExactAssertion */
static int hf_x509ce_cpea_issuedByThisCAAssertion = -1;  /* CertificateExactAssertion */
static int hf_x509ce_issuedToThisCAAssertion = -1;  /* CertificateAssertion */
static int hf_x509ce_issuedByThisCAAssertion = -1;  /* CertificateAssertion */
static int hf_x509ce_minCRLNumber = -1;           /* CRLNumber */
static int hf_x509ce_maxCRLNumber = -1;           /* CRLNumber */
static int hf_x509ce_reasonFlags = -1;            /* ReasonFlags */
static int hf_x509ce_firstIssuer = -1;            /* Name */
static int hf_x509ce_lastSubject = -1;            /* Name */
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

static gint ett_x509ce_AuthorityKeyIdentifier = -1;
static gint ett_x509ce_KeyUsage = -1;
static gint ett_x509ce_KeyPurposeIDs = -1;
static gint ett_x509ce_PrivateKeyUsagePeriod = -1;
static gint ett_x509ce_CertificatePoliciesSyntax = -1;
static gint ett_x509ce_PolicyInformation = -1;
static gint ett_x509ce_SEQUENCE_SIZE_1_MAX_OF_PolicyQualifierInfo = -1;
static gint ett_x509ce_PolicyQualifierInfo = -1;
static gint ett_x509ce_PolicyMappingsSyntax = -1;
static gint ett_x509ce_PolicyMappingsSyntax_item = -1;
static gint ett_x509ce_GeneralNames = -1;
static gint ett_x509ce_GeneralName = -1;
static gint ett_x509ce_EDIPartyName = -1;
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
static gint ett_x509ce_CertificateExactAssertion = -1;
static gint ett_x509ce_CertificateAssertion = -1;
static gint ett_x509ce_AltNameType = -1;
static gint ett_x509ce_CertPolicySet = -1;
static gint ett_x509ce_CertificatePairExactAssertion = -1;
static gint ett_x509ce_CertificatePairAssertion = -1;
static gint ett_x509ce_CertificateListExactAssertion = -1;
static gint ett_x509ce_CertificateListAssertion = -1;
static gint ett_x509ce_PkiPathMatchSyntax = -1;

/*--- End of included file: packet-x509ce-ett.c ---*/


static const char *object_identifier_id;


/*--- Included file: packet-x509ce-fn.c ---*/

/*--- Fields for imported types ---*/

static int dissect_authorityCertSerialNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_CertificateSerialNumber(TRUE, tvb, offset, pinfo, tree, hf_x509ce_authorityCertSerialNumber);
}
static int dissect_directoryName_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Name(TRUE, tvb, offset, pinfo, tree, hf_x509ce_directoryName);
}
static int dissect_nameAssigner_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_DirectoryString(TRUE, tvb, offset, pinfo, tree, hf_x509ce_nameAssigner);
}
static int dissect_partyName_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_DirectoryString(TRUE, tvb, offset, pinfo, tree, hf_x509ce_partyName);
}
static int dissect_AttributesSyntax_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Attribute(FALSE, tvb, offset, pinfo, tree, hf_x509ce_AttributesSyntax_item);
}
static int dissect_nameRelativeToCRLIssuer_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_RelativeDistinguishedName(TRUE, tvb, offset, pinfo, tree, hf_x509ce_nameRelativeToCRLIssuer);
}
static int dissect_serialNumber(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_CertificateSerialNumber(FALSE, tvb, offset, pinfo, tree, hf_x509ce_serialNumber);
}
static int dissect_serialNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_CertificateSerialNumber(TRUE, tvb, offset, pinfo, tree, hf_x509ce_serialNumber);
}
static int dissect_issuer(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Name(FALSE, tvb, offset, pinfo, tree, hf_x509ce_issuer);
}
static int dissect_issuer_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Name(TRUE, tvb, offset, pinfo, tree, hf_x509ce_issuer);
}
static int dissect_pathToName_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Name(TRUE, tvb, offset, pinfo, tree, hf_x509ce_pathToName);
}
static int dissect_subject_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Name(TRUE, tvb, offset, pinfo, tree, hf_x509ce_subject);
}
static int dissect_firstIssuer(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Name(FALSE, tvb, offset, pinfo, tree, hf_x509ce_firstIssuer);
}
static int dissect_lastSubject(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Name(FALSE, tvb, offset, pinfo, tree, hf_x509ce_lastSubject);
}



int
dissect_x509ce_KeyIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_keyIdentifier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_KeyIdentifier(TRUE, tvb, offset, pinfo, tree, hf_x509ce_keyIdentifier);
}



static int
dissect_x509ce_IA5String(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
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


static const ber_sequence_t EDIPartyName_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_nameAssigner_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_partyName_impl },
  { 0, 0, 0, NULL }
};

int
dissect_x509ce_EDIPartyName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   EDIPartyName_sequence, hf_index, ett_x509ce_EDIPartyName);

  return offset;
}
static int dissect_ediPartyName_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_EDIPartyName(TRUE, tvb, offset, pinfo, tree, hf_x509ce_ediPartyName);
}



static int
dissect_x509ce_T_iPAddress(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
	proto_tree_add_item(tree, hf_x509ce_IPAddress, tvb, offset, 4, FALSE);
	offset+=4;


  return offset;
}
static int dissect_iPAddress_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_T_iPAddress(TRUE, tvb, offset, pinfo, tree, hf_x509ce_iPAddress);
}



static int
dissect_x509ce_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_registeredID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_OBJECT_IDENTIFIER(TRUE, tvb, offset, pinfo, tree, hf_x509ce_registeredID);
}
static int dissect_subjectPublicKeyAlgID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_OBJECT_IDENTIFIER(TRUE, tvb, offset, pinfo, tree, hf_x509ce_subjectPublicKeyAlgID);
}
static int dissect_otherNameForm(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_x509ce_otherNameForm);
}


const value_string x509ce_GeneralName_vals[] = {
  {   1, "rfc822Name" },
  {   2, "dNSName" },
  {   4, "directoryName" },
  {   5, "ediPartyName" },
  {   6, "uniformResourceIdentifier" },
  {   7, "iPAddress" },
  {   8, "registeredID" },
  { 0, NULL }
};

static const ber_choice_t GeneralName_choice[] = {
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_rfc822Name_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_dNSName_impl },
  {   4, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_directoryName_impl },
  {   5, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_ediPartyName_impl },
  {   6, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_uniformResourceIdentifier_impl },
  {   7, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_iPAddress_impl },
  {   8, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_registeredID_impl },
  { 0, 0, 0, 0, NULL }
};

int
dissect_x509ce_GeneralName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 GeneralName_choice, hf_index, ett_x509ce_GeneralName,
                                 NULL);

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
static int dissect_crlr_issuer_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_GeneralName(TRUE, tvb, offset, pinfo, tree, hf_x509ce_crlr_issuer);
}
static int dissect_location_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_GeneralName(TRUE, tvb, offset, pinfo, tree, hf_x509ce_location);
}
static int dissect_deltaLocation(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_GeneralName(FALSE, tvb, offset, pinfo, tree, hf_x509ce_deltaLocation);
}


static const ber_sequence_t GeneralNames_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_GeneralNames_item },
};

int
dissect_x509ce_GeneralNames(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
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


static const ber_sequence_t AuthorityKeyIdentifier_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_keyIdentifier_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_authorityCertIssuer_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_authorityCertSerialNumber_impl },
  { 0, 0, 0, NULL }
};

int
dissect_x509ce_AuthorityKeyIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AuthorityKeyIdentifier_sequence, hf_index, ett_x509ce_AuthorityKeyIdentifier);

  return offset;
}
static int dissect_authorityKeyIdentifier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_AuthorityKeyIdentifier(TRUE, tvb, offset, pinfo, tree, hf_x509ce_authorityKeyIdentifier);
}



int
dissect_x509ce_SubjectKeyIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x509ce_KeyIdentifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_subjectKeyIdentifier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_SubjectKeyIdentifier(TRUE, tvb, offset, pinfo, tree, hf_x509ce_subjectKeyIdentifier);
}


static const asn_namedbit KeyUsage_bits[] = {
  {  0, &hf_x509ce_KeyUsage_digitalSignature, -1, -1, "digitalSignature", NULL },
  {  1, &hf_x509ce_KeyUsage_nonRepudiation, -1, -1, "nonRepudiation", NULL },
  {  2, &hf_x509ce_KeyUsage_keyEncipherment, -1, -1, "keyEncipherment", NULL },
  {  3, &hf_x509ce_KeyUsage_dataEncipherment, -1, -1, "dataEncipherment", NULL },
  {  4, &hf_x509ce_KeyUsage_keyAgreement, -1, -1, "keyAgreement", NULL },
  {  5, &hf_x509ce_KeyUsage_keyCertSign, -1, -1, "keyCertSign", NULL },
  {  6, &hf_x509ce_KeyUsage_cRLSign, -1, -1, "cRLSign", NULL },
  {  7, &hf_x509ce_KeyUsage_encipherOnly, -1, -1, "encipherOnly", NULL },
  {  8, &hf_x509ce_KeyUsage_decipherOnly, -1, -1, "decipherOnly", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

int
dissect_x509ce_KeyUsage(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    KeyUsage_bits, hf_index, ett_x509ce_KeyUsage,
                                    NULL);

  return offset;
}
static int dissect_keyUsage_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_KeyUsage(TRUE, tvb, offset, pinfo, tree, hf_x509ce_keyUsage);
}



int
dissect_x509ce_KeyPurposeId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_KeyPurposeIDs_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_KeyPurposeId(FALSE, tvb, offset, pinfo, tree, hf_x509ce_KeyPurposeIDs_item);
}


static const ber_sequence_t KeyPurposeIDs_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_KeyPurposeIDs_item },
};

int
dissect_x509ce_KeyPurposeIDs(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      KeyPurposeIDs_sequence_of, hf_index, ett_x509ce_KeyPurposeIDs);

  return offset;
}



static int
dissect_x509ce_GeneralizedTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, pinfo, tree, tvb, offset, hf_index);

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
static int dissect_privateKeyValid_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_GeneralizedTime(TRUE, tvb, offset, pinfo, tree, hf_x509ce_privateKeyValid);
}


static const ber_sequence_t PrivateKeyUsagePeriod_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_notBefore_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_notAfter_impl },
  { 0, 0, 0, NULL }
};

int
dissect_x509ce_PrivateKeyUsagePeriod(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PrivateKeyUsagePeriod_sequence, hf_index, ett_x509ce_PrivateKeyUsagePeriod);

  return offset;
}



static int
dissect_x509ce_CertPolicyId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

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
static int dissect_CertPolicySet_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_CertPolicyId(FALSE, tvb, offset, pinfo, tree, hf_x509ce_CertPolicySet_item);
}



static int
dissect_x509ce_PolicyQualifierId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, pinfo, tree, tvb, offset, hf_x509ce_object_identifier_id, &object_identifier_id);

  return offset;
}
static int dissect_policyQualifierId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_PolicyQualifierId(FALSE, tvb, offset, pinfo, tree, hf_x509ce_policyQualifierId);
}



static int
dissect_x509ce_PolicyQualifierValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, pinfo, tree);


  return offset;
}
static int dissect_qualifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_PolicyQualifierValue(FALSE, tvb, offset, pinfo, tree, hf_x509ce_qualifier);
}


static const ber_sequence_t PolicyQualifierInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_policyQualifierId },
  { BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qualifier },
  { 0, 0, 0, NULL }
};

int
dissect_x509ce_PolicyQualifierInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PolicyQualifierInfo_sequence, hf_index, ett_x509ce_PolicyQualifierInfo);

  return offset;
}
static int dissect_policyQualifiers_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_PolicyQualifierInfo(FALSE, tvb, offset, pinfo, tree, hf_x509ce_policyQualifiers_item);
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_PolicyQualifierInfo_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_policyQualifiers_item },
};

static int
dissect_x509ce_SEQUENCE_SIZE_1_MAX_OF_PolicyQualifierInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_PolicyQualifierInfo_sequence_of, hf_index, ett_x509ce_SEQUENCE_SIZE_1_MAX_OF_PolicyQualifierInfo);

  return offset;
}
static int dissect_policyQualifiers(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_SEQUENCE_SIZE_1_MAX_OF_PolicyQualifierInfo(FALSE, tvb, offset, pinfo, tree, hf_x509ce_policyQualifiers);
}


static const ber_sequence_t PolicyInformation_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_policyIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_policyQualifiers },
  { 0, 0, 0, NULL }
};

int
dissect_x509ce_PolicyInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PolicyInformation_sequence, hf_index, ett_x509ce_PolicyInformation);

  return offset;
}
static int dissect_CertificatePoliciesSyntax_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_PolicyInformation(FALSE, tvb, offset, pinfo, tree, hf_x509ce_CertificatePoliciesSyntax_item);
}


static const ber_sequence_t CertificatePoliciesSyntax_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_CertificatePoliciesSyntax_item },
};

int
dissect_x509ce_CertificatePoliciesSyntax(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      CertificatePoliciesSyntax_sequence_of, hf_index, ett_x509ce_CertificatePoliciesSyntax);

  return offset;
}


static const ber_sequence_t PolicyMappingsSyntax_item_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_issuerDomainPolicy },
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_subjectDomainPolicy },
  { 0, 0, 0, NULL }
};

static int
dissect_x509ce_PolicyMappingsSyntax_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PolicyMappingsSyntax_item_sequence, hf_index, ett_x509ce_PolicyMappingsSyntax_item);

  return offset;
}
static int dissect_PolicyMappingsSyntax_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_PolicyMappingsSyntax_item(FALSE, tvb, offset, pinfo, tree, hf_x509ce_PolicyMappingsSyntax_item);
}


static const ber_sequence_t PolicyMappingsSyntax_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_PolicyMappingsSyntax_item },
};

int
dissect_x509ce_PolicyMappingsSyntax(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      PolicyMappingsSyntax_sequence_of, hf_index, ett_x509ce_PolicyMappingsSyntax);

  return offset;
}


static const ber_sequence_t AttributesSyntax_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_AttributesSyntax_item },
};

int
dissect_x509ce_AttributesSyntax(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      AttributesSyntax_sequence_of, hf_index, ett_x509ce_AttributesSyntax);

  return offset;
}



static int
dissect_x509ce_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, pinfo, tree, tvb, offset, hf_index);

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
dissect_x509ce_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

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


static const ber_sequence_t BasicConstraintsSyntax_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cA },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_pathLenConstraint },
  { 0, 0, 0, NULL }
};

int
dissect_x509ce_BasicConstraintsSyntax(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   BasicConstraintsSyntax_sequence, hf_index, ett_x509ce_BasicConstraintsSyntax);

  return offset;
}



int
dissect_x509ce_BaseDistance(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_minimum_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_BaseDistance(TRUE, tvb, offset, pinfo, tree, hf_x509ce_minimum);
}
static int dissect_maximum_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_BaseDistance(TRUE, tvb, offset, pinfo, tree, hf_x509ce_maximum);
}


static const ber_sequence_t GeneralSubtree_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_base },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_minimum_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_maximum_impl },
  { 0, 0, 0, NULL }
};

int
dissect_x509ce_GeneralSubtree(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   GeneralSubtree_sequence, hf_index, ett_x509ce_GeneralSubtree);

  return offset;
}
static int dissect_GeneralSubtrees_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_GeneralSubtree(FALSE, tvb, offset, pinfo, tree, hf_x509ce_GeneralSubtrees_item);
}


static const ber_sequence_t GeneralSubtrees_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_GeneralSubtrees_item },
};

int
dissect_x509ce_GeneralSubtrees(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
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


static const ber_sequence_t NameConstraintsSyntax_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_permittedSubtrees_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_excludedSubtrees_impl },
  { 0, 0, 0, NULL }
};

int
dissect_x509ce_NameConstraintsSyntax(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   NameConstraintsSyntax_sequence, hf_index, ett_x509ce_NameConstraintsSyntax);

  return offset;
}
static int dissect_nameConstraints_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_NameConstraintsSyntax(TRUE, tvb, offset, pinfo, tree, hf_x509ce_nameConstraints);
}



int
dissect_x509ce_SkipCerts(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_requireExplicitPolicy_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_SkipCerts(TRUE, tvb, offset, pinfo, tree, hf_x509ce_requireExplicitPolicy);
}
static int dissect_inhibitPolicyMapping_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_SkipCerts(TRUE, tvb, offset, pinfo, tree, hf_x509ce_inhibitPolicyMapping);
}


static const ber_sequence_t PolicyConstraintsSyntax_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_requireExplicitPolicy_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_inhibitPolicyMapping_impl },
  { 0, 0, 0, NULL }
};

int
dissect_x509ce_PolicyConstraintsSyntax(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PolicyConstraintsSyntax_sequence, hf_index, ett_x509ce_PolicyConstraintsSyntax);

  return offset;
}



int
dissect_x509ce_CRLNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_cRLNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_CRLNumber(TRUE, tvb, offset, pinfo, tree, hf_x509ce_cRLNumber);
}
static int dissect_minCRLNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_CRLNumber(TRUE, tvb, offset, pinfo, tree, hf_x509ce_minCRLNumber);
}
static int dissect_maxCRLNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_CRLNumber(TRUE, tvb, offset, pinfo, tree, hf_x509ce_maxCRLNumber);
}


const value_string x509ce_CRLReason_vals[] = {
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


int
dissect_x509ce_CRLReason(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



int
dissect_x509ce_HoldInstruction(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}


const value_string x509ce_DistributionPointName_vals[] = {
  {   0, "fullName" },
  {   1, "nameRelativeToCRLIssuer" },
  { 0, NULL }
};

static const ber_choice_t DistributionPointName_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_fullName_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_nameRelativeToCRLIssuer_impl },
  { 0, 0, 0, 0, NULL }
};

int
dissect_x509ce_DistributionPointName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 DistributionPointName_choice, hf_index, ett_x509ce_DistributionPointName,
                                 NULL);

  return offset;
}
static int dissect_distributionPoint(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_DistributionPointName(FALSE, tvb, offset, pinfo, tree, hf_x509ce_distributionPoint);
}
static int dissect_distributionPoint_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_DistributionPointName(TRUE, tvb, offset, pinfo, tree, hf_x509ce_distributionPoint);
}


static const asn_namedbit OnlyCertificateTypes_bits[] = {
  {  0, &hf_x509ce_OnlyCertificateTypes_userPublicKey, -1, -1, "userPublicKey", NULL },
  {  1, &hf_x509ce_OnlyCertificateTypes_cA, -1, -1, "cA", NULL },
  {  2, &hf_x509ce_OnlyCertificateTypes_userAttribute, -1, -1, "userAttribute", NULL },
  {  3, &hf_x509ce_OnlyCertificateTypes_aA, -1, -1, "aA", NULL },
  {  4, &hf_x509ce_OnlyCertificateTypes_sOAPublicKey, -1, -1, "sOAPublicKey", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

int
dissect_x509ce_OnlyCertificateTypes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    OnlyCertificateTypes_bits, hf_index, ett_x509ce_OnlyCertificateTypes,
                                    NULL);

  return offset;
}
static int dissect_onlyContains_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_OnlyCertificateTypes(TRUE, tvb, offset, pinfo, tree, hf_x509ce_onlyContains);
}


static const asn_namedbit ReasonFlags_bits[] = {
  {  0, &hf_x509ce_ReasonFlags_unused, -1, -1, "unused", NULL },
  {  1, &hf_x509ce_ReasonFlags_keyCompromise, -1, -1, "keyCompromise", NULL },
  {  2, &hf_x509ce_ReasonFlags_cACompromise, -1, -1, "cACompromise", NULL },
  {  3, &hf_x509ce_ReasonFlags_affiliationChanged, -1, -1, "affiliationChanged", NULL },
  {  4, &hf_x509ce_ReasonFlags_superseded, -1, -1, "superseded", NULL },
  {  5, &hf_x509ce_ReasonFlags_cessationOfOperation, -1, -1, "cessationOfOperation", NULL },
  {  6, &hf_x509ce_ReasonFlags_certificateHold, -1, -1, "certificateHold", NULL },
  {  7, &hf_x509ce_ReasonFlags_privilegeWithdrawn, -1, -1, "privilegeWithdrawn", NULL },
  {  8, &hf_x509ce_ReasonFlags_aACompromise, -1, -1, "aACompromise", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

int
dissect_x509ce_ReasonFlags(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
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
static int dissect_reasonFlags(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_ReasonFlags(FALSE, tvb, offset, pinfo, tree, hf_x509ce_reasonFlags);
}


static const ber_sequence_t NumberRange_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_startingNumber_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_endingNumber_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_modulus },
  { 0, 0, 0, NULL }
};

int
dissect_x509ce_NumberRange(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
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



int
dissect_x509ce_CRLStreamIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_cRLStreamIdentifier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_CRLStreamIdentifier(TRUE, tvb, offset, pinfo, tree, hf_x509ce_cRLStreamIdentifier);
}


static const ber_sequence_t BaseRevocationInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cRLStreamIdentifier_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_cRLNumber_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_baseThisUpdate_impl },
  { 0, 0, 0, NULL }
};

int
dissect_x509ce_BaseRevocationInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   BaseRevocationInfo_sequence, hf_index, ett_x509ce_BaseRevocationInfo);

  return offset;
}
static int dissect_baseRevocationInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_BaseRevocationInfo(TRUE, tvb, offset, pinfo, tree, hf_x509ce_baseRevocationInfo);
}


static const ber_sequence_t PerAuthorityScope_sequence[] = {
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

int
dissect_x509ce_PerAuthorityScope(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PerAuthorityScope_sequence, hf_index, ett_x509ce_PerAuthorityScope);

  return offset;
}
static int dissect_CRLScopeSyntax_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_PerAuthorityScope(FALSE, tvb, offset, pinfo, tree, hf_x509ce_CRLScopeSyntax_item);
}


static const ber_sequence_t CRLScopeSyntax_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_CRLScopeSyntax_item },
};

int
dissect_x509ce_CRLScopeSyntax(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      CRLScopeSyntax_sequence_of, hf_index, ett_x509ce_CRLScopeSyntax);

  return offset;
}
static int dissect_cRLScope(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_CRLScopeSyntax(FALSE, tvb, offset, pinfo, tree, hf_x509ce_cRLScope);
}


static const ber_sequence_t DeltaRefInfo_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_deltaLocation },
  { BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_lastDelta },
  { 0, 0, 0, NULL }
};

int
dissect_x509ce_DeltaRefInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DeltaRefInfo_sequence, hf_index, ett_x509ce_DeltaRefInfo);

  return offset;
}
static int dissect_deltaRefInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_DeltaRefInfo(TRUE, tvb, offset, pinfo, tree, hf_x509ce_deltaRefInfo);
}


static const ber_sequence_t CRLReferral_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_crlr_issuer_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_location_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_deltaRefInfo_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cRLScope },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lastUpdate_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lastChangedCRL_impl },
  { 0, 0, 0, NULL }
};

int
dissect_x509ce_CRLReferral(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CRLReferral_sequence, hf_index, ett_x509ce_CRLReferral);

  return offset;
}
static int dissect_cRLReferral_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_CRLReferral(TRUE, tvb, offset, pinfo, tree, hf_x509ce_cRLReferral);
}


const value_string x509ce_StatusReferral_vals[] = {
  {   0, "cRLReferral" },
  { 0, NULL }
};

static const ber_choice_t StatusReferral_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_cRLReferral_impl },
  { 0, 0, 0, 0, NULL }
};

int
dissect_x509ce_StatusReferral(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 StatusReferral_choice, hf_index, ett_x509ce_StatusReferral,
                                 NULL);

  return offset;
}
static int dissect_StatusReferrals_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_StatusReferral(FALSE, tvb, offset, pinfo, tree, hf_x509ce_StatusReferrals_item);
}


static const ber_sequence_t StatusReferrals_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_StatusReferrals_item },
};

int
dissect_x509ce_StatusReferrals(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      StatusReferrals_sequence_of, hf_index, ett_x509ce_StatusReferrals);

  return offset;
}


const value_string x509ce_OrderedListSyntax_vals[] = {
  {   0, "ascSerialNum" },
  {   1, "ascRevDate" },
  { 0, NULL }
};


int
dissect_x509ce_OrderedListSyntax(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t DeltaInformation_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_deltaLocation },
  { BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_nextDelta },
  { 0, 0, 0, NULL }
};

int
dissect_x509ce_DeltaInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DeltaInformation_sequence, hf_index, ett_x509ce_DeltaInformation);

  return offset;
}


static const ber_sequence_t DistributionPoint_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_distributionPoint_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_reasons_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cRLIssuer_impl },
  { 0, 0, 0, NULL }
};

int
dissect_x509ce_DistributionPoint(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DistributionPoint_sequence, hf_index, ett_x509ce_DistributionPoint);

  return offset;
}
static int dissect_CRLDistPointsSyntax_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_DistributionPoint(FALSE, tvb, offset, pinfo, tree, hf_x509ce_CRLDistPointsSyntax_item);
}


static const ber_sequence_t CRLDistPointsSyntax_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_CRLDistPointsSyntax_item },
};

int
dissect_x509ce_CRLDistPointsSyntax(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      CRLDistPointsSyntax_sequence_of, hf_index, ett_x509ce_CRLDistPointsSyntax);

  return offset;
}


static const ber_sequence_t IssuingDistPointSyntax_sequence[] = {
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

int
dissect_x509ce_IssuingDistPointSyntax(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   IssuingDistPointSyntax_sequence, hf_index, ett_x509ce_IssuingDistPointSyntax);

  return offset;
}



int
dissect_x509ce_BaseCRLNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x509ce_CRLNumber(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static const ber_sequence_t CertificateExactAssertion_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_serialNumber },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_issuer },
  { 0, 0, 0, NULL }
};

int
dissect_x509ce_CertificateExactAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CertificateExactAssertion_sequence, hf_index, ett_x509ce_CertificateExactAssertion);

  return offset;
}
static int dissect_cpea_issuedToThisCAAssertion_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_CertificateExactAssertion(TRUE, tvb, offset, pinfo, tree, hf_x509ce_cpea_issuedToThisCAAssertion);
}
static int dissect_cpea_issuedByThisCAAssertion_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_CertificateExactAssertion(TRUE, tvb, offset, pinfo, tree, hf_x509ce_cpea_issuedByThisCAAssertion);
}


static const value_string x509ce_T_builtinNameForm_vals[] = {
  {   1, "rfc822Name" },
  {   2, "dNSName" },
  {   3, "x400Address" },
  {   4, "directoryName" },
  {   5, "ediPartyName" },
  {   6, "uniformResourceIdentifier" },
  {   7, "iPAddress" },
  {   8, "registeredId" },
  { 0, NULL }
};


static int
dissect_x509ce_T_builtinNameForm(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_builtinNameForm(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_T_builtinNameForm(FALSE, tvb, offset, pinfo, tree, hf_x509ce_builtinNameForm);
}


const value_string x509ce_AltNameType_vals[] = {
  {   0, "builtinNameForm" },
  {   1, "otherNameForm" },
  { 0, NULL }
};

static const ber_choice_t AltNameType_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_builtinNameForm },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_otherNameForm },
  { 0, 0, 0, 0, NULL }
};

int
dissect_x509ce_AltNameType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 AltNameType_choice, hf_index, ett_x509ce_AltNameType,
                                 NULL);

  return offset;
}
static int dissect_subjectAltName_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_AltNameType(TRUE, tvb, offset, pinfo, tree, hf_x509ce_subjectAltName);
}


static const ber_sequence_t CertPolicySet_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_CertPolicySet_item },
};

int
dissect_x509ce_CertPolicySet(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      CertPolicySet_sequence_of, hf_index, ett_x509ce_CertPolicySet);

  return offset;
}
static int dissect_policy_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_CertPolicySet(TRUE, tvb, offset, pinfo, tree, hf_x509ce_policy);
}


static const ber_sequence_t CertificateAssertion_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_serialNumber_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_issuer_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_subjectKeyIdentifier_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_authorityKeyIdentifier_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_privateKeyValid_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_subjectPublicKeyAlgID_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_keyUsage_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_subjectAltName_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_policy_impl },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pathToName_impl },
  { BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_subject_impl },
  { BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_nameConstraints_impl },
  { 0, 0, 0, NULL }
};

int
dissect_x509ce_CertificateAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CertificateAssertion_sequence, hf_index, ett_x509ce_CertificateAssertion);

  return offset;
}
static int dissect_issuedToThisCAAssertion_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_CertificateAssertion(TRUE, tvb, offset, pinfo, tree, hf_x509ce_issuedToThisCAAssertion);
}
static int dissect_issuedByThisCAAssertion_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_CertificateAssertion(TRUE, tvb, offset, pinfo, tree, hf_x509ce_issuedByThisCAAssertion);
}


static const ber_sequence_t CertificatePairExactAssertion_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cpea_issuedToThisCAAssertion_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cpea_issuedByThisCAAssertion_impl },
  { 0, 0, 0, NULL }
};

int
dissect_x509ce_CertificatePairExactAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CertificatePairExactAssertion_sequence, hf_index, ett_x509ce_CertificatePairExactAssertion);

  return offset;
}


static const ber_sequence_t CertificatePairAssertion_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_issuedToThisCAAssertion_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_issuedByThisCAAssertion_impl },
  { 0, 0, 0, NULL }
};

int
dissect_x509ce_CertificatePairAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CertificatePairAssertion_sequence, hf_index, ett_x509ce_CertificatePairAssertion);

  return offset;
}


static const ber_sequence_t CertificateListExactAssertion_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_issuer },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_distributionPoint },
  { 0, 0, 0, NULL }
};

int
dissect_x509ce_CertificateListExactAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CertificateListExactAssertion_sequence, hf_index, ett_x509ce_CertificateListExactAssertion);

  return offset;
}


static const ber_sequence_t CertificateListAssertion_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_issuer },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_minCRLNumber_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_maxCRLNumber_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_reasonFlags },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_distributionPoint_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_authorityKeyIdentifier_impl },
  { 0, 0, 0, NULL }
};

int
dissect_x509ce_CertificateListAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CertificateListAssertion_sequence, hf_index, ett_x509ce_CertificateListAssertion);

  return offset;
}


static const ber_sequence_t PkiPathMatchSyntax_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_firstIssuer },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_lastSubject },
  { 0, 0, 0, NULL }
};

int
dissect_x509ce_PkiPathMatchSyntax(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PkiPathMatchSyntax_sequence, hf_index, ett_x509ce_PkiPathMatchSyntax);

  return offset;
}

/*--- PDUs ---*/

static void dissect_AuthorityKeyIdentifier_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509ce_AuthorityKeyIdentifier(FALSE, tvb, 0, pinfo, tree, hf_x509ce_AuthorityKeyIdentifier_PDU);
}
static void dissect_SubjectKeyIdentifier_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509ce_SubjectKeyIdentifier(FALSE, tvb, 0, pinfo, tree, hf_x509ce_SubjectKeyIdentifier_PDU);
}
static void dissect_KeyUsage_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509ce_KeyUsage(FALSE, tvb, 0, pinfo, tree, hf_x509ce_KeyUsage_PDU);
}
static void dissect_KeyPurposeIDs_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509ce_KeyPurposeIDs(FALSE, tvb, 0, pinfo, tree, hf_x509ce_KeyPurposeIDs_PDU);
}
static void dissect_PrivateKeyUsagePeriod_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509ce_PrivateKeyUsagePeriod(FALSE, tvb, 0, pinfo, tree, hf_x509ce_PrivateKeyUsagePeriod_PDU);
}
static void dissect_CertificatePoliciesSyntax_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509ce_CertificatePoliciesSyntax(FALSE, tvb, 0, pinfo, tree, hf_x509ce_CertificatePoliciesSyntax_PDU);
}
static void dissect_PolicyMappingsSyntax_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509ce_PolicyMappingsSyntax(FALSE, tvb, 0, pinfo, tree, hf_x509ce_PolicyMappingsSyntax_PDU);
}
static void dissect_GeneralNames_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509ce_GeneralNames(FALSE, tvb, 0, pinfo, tree, hf_x509ce_GeneralNames_PDU);
}
static void dissect_AttributesSyntax_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509ce_AttributesSyntax(FALSE, tvb, 0, pinfo, tree, hf_x509ce_AttributesSyntax_PDU);
}
static void dissect_BasicConstraintsSyntax_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509ce_BasicConstraintsSyntax(FALSE, tvb, 0, pinfo, tree, hf_x509ce_BasicConstraintsSyntax_PDU);
}
static void dissect_NameConstraintsSyntax_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509ce_NameConstraintsSyntax(FALSE, tvb, 0, pinfo, tree, hf_x509ce_NameConstraintsSyntax_PDU);
}
static void dissect_PolicyConstraintsSyntax_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509ce_PolicyConstraintsSyntax(FALSE, tvb, 0, pinfo, tree, hf_x509ce_PolicyConstraintsSyntax_PDU);
}
static void dissect_SkipCerts_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509ce_SkipCerts(FALSE, tvb, 0, pinfo, tree, hf_x509ce_SkipCerts_PDU);
}
static void dissect_CRLNumber_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509ce_CRLNumber(FALSE, tvb, 0, pinfo, tree, hf_x509ce_CRLNumber_PDU);
}
static void dissect_CRLReason_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509ce_CRLReason(FALSE, tvb, 0, pinfo, tree, hf_x509ce_CRLReason_PDU);
}
static void dissect_HoldInstruction_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509ce_HoldInstruction(FALSE, tvb, 0, pinfo, tree, hf_x509ce_HoldInstruction_PDU);
}
static void dissect_CRLScopeSyntax_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509ce_CRLScopeSyntax(FALSE, tvb, 0, pinfo, tree, hf_x509ce_CRLScopeSyntax_PDU);
}
static void dissect_StatusReferrals_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509ce_StatusReferrals(FALSE, tvb, 0, pinfo, tree, hf_x509ce_StatusReferrals_PDU);
}
static void dissect_CRLStreamIdentifier_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509ce_CRLStreamIdentifier(FALSE, tvb, 0, pinfo, tree, hf_x509ce_CRLStreamIdentifier_PDU);
}
static void dissect_OrderedListSyntax_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509ce_OrderedListSyntax(FALSE, tvb, 0, pinfo, tree, hf_x509ce_OrderedListSyntax_PDU);
}
static void dissect_DeltaInformation_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509ce_DeltaInformation(FALSE, tvb, 0, pinfo, tree, hf_x509ce_DeltaInformation_PDU);
}
static void dissect_CRLDistPointsSyntax_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509ce_CRLDistPointsSyntax(FALSE, tvb, 0, pinfo, tree, hf_x509ce_CRLDistPointsSyntax_PDU);
}
static void dissect_IssuingDistPointSyntax_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509ce_IssuingDistPointSyntax(FALSE, tvb, 0, pinfo, tree, hf_x509ce_IssuingDistPointSyntax_PDU);
}
static void dissect_BaseCRLNumber_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509ce_BaseCRLNumber(FALSE, tvb, 0, pinfo, tree, hf_x509ce_BaseCRLNumber_PDU);
}


/*--- End of included file: packet-x509ce-fn.c ---*/



static void
dissect_x509ce_invalidityDate_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_GeneralizedTime(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_invalidityDate);
}

static void
dissect_x509ce_baseUpdateTime_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_GeneralizedTime(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_baseUpdateTime);
}

/*--- proto_register_x509ce ----------------------------------------------*/
void proto_register_x509ce(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_x509ce_id_ce_baseUpdateTime,
      { "baseUpdateTime", "x509ce.id_ce_baseUpdateTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "baseUpdateTime", HFILL }},
    { &hf_x509ce_id_ce_invalidityDate,
      { "invalidityDate", "x509ce.id_ce_invalidityDate",
        FT_STRING, BASE_NONE, NULL, 0,
        "invalidityDate", HFILL }},
    { &hf_x509ce_object_identifier_id, 
      { "Id", "x509ce.id", FT_STRING, BASE_NONE, NULL, 0,
	"Object identifier Id", HFILL }},
    { &hf_x509ce_IPAddress,
      { "iPAddress", "x509ce.IPAddress", FT_IPv4, BASE_NONE, NULL, 0,
        "IP Address", HFILL }},


/*--- Included file: packet-x509ce-hfarr.c ---*/

    { &hf_x509ce_AuthorityKeyIdentifier_PDU,
      { "AuthorityKeyIdentifier", "x509ce.AuthorityKeyIdentifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "AuthorityKeyIdentifier", HFILL }},
    { &hf_x509ce_SubjectKeyIdentifier_PDU,
      { "SubjectKeyIdentifier", "x509ce.SubjectKeyIdentifier",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SubjectKeyIdentifier", HFILL }},
    { &hf_x509ce_KeyUsage_PDU,
      { "KeyUsage", "x509ce.KeyUsage",
        FT_BYTES, BASE_HEX, NULL, 0,
        "KeyUsage", HFILL }},
    { &hf_x509ce_KeyPurposeIDs_PDU,
      { "KeyPurposeIDs", "x509ce.KeyPurposeIDs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "KeyPurposeIDs", HFILL }},
    { &hf_x509ce_PrivateKeyUsagePeriod_PDU,
      { "PrivateKeyUsagePeriod", "x509ce.PrivateKeyUsagePeriod",
        FT_NONE, BASE_NONE, NULL, 0,
        "PrivateKeyUsagePeriod", HFILL }},
    { &hf_x509ce_CertificatePoliciesSyntax_PDU,
      { "CertificatePoliciesSyntax", "x509ce.CertificatePoliciesSyntax",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CertificatePoliciesSyntax", HFILL }},
    { &hf_x509ce_PolicyMappingsSyntax_PDU,
      { "PolicyMappingsSyntax", "x509ce.PolicyMappingsSyntax",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PolicyMappingsSyntax", HFILL }},
    { &hf_x509ce_GeneralNames_PDU,
      { "GeneralNames", "x509ce.GeneralNames",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GeneralNames", HFILL }},
    { &hf_x509ce_AttributesSyntax_PDU,
      { "AttributesSyntax", "x509ce.AttributesSyntax",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AttributesSyntax", HFILL }},
    { &hf_x509ce_BasicConstraintsSyntax_PDU,
      { "BasicConstraintsSyntax", "x509ce.BasicConstraintsSyntax",
        FT_NONE, BASE_NONE, NULL, 0,
        "BasicConstraintsSyntax", HFILL }},
    { &hf_x509ce_NameConstraintsSyntax_PDU,
      { "NameConstraintsSyntax", "x509ce.NameConstraintsSyntax",
        FT_NONE, BASE_NONE, NULL, 0,
        "NameConstraintsSyntax", HFILL }},
    { &hf_x509ce_PolicyConstraintsSyntax_PDU,
      { "PolicyConstraintsSyntax", "x509ce.PolicyConstraintsSyntax",
        FT_NONE, BASE_NONE, NULL, 0,
        "PolicyConstraintsSyntax", HFILL }},
    { &hf_x509ce_SkipCerts_PDU,
      { "SkipCerts", "x509ce.SkipCerts",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SkipCerts", HFILL }},
    { &hf_x509ce_CRLNumber_PDU,
      { "CRLNumber", "x509ce.CRLNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CRLNumber", HFILL }},
    { &hf_x509ce_CRLReason_PDU,
      { "CRLReason", "x509ce.CRLReason",
        FT_UINT32, BASE_DEC, VALS(x509ce_CRLReason_vals), 0,
        "CRLReason", HFILL }},
    { &hf_x509ce_HoldInstruction_PDU,
      { "HoldInstruction", "x509ce.HoldInstruction",
        FT_STRING, BASE_NONE, NULL, 0,
        "HoldInstruction", HFILL }},
    { &hf_x509ce_CRLScopeSyntax_PDU,
      { "CRLScopeSyntax", "x509ce.CRLScopeSyntax",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CRLScopeSyntax", HFILL }},
    { &hf_x509ce_StatusReferrals_PDU,
      { "StatusReferrals", "x509ce.StatusReferrals",
        FT_UINT32, BASE_DEC, NULL, 0,
        "StatusReferrals", HFILL }},
    { &hf_x509ce_CRLStreamIdentifier_PDU,
      { "CRLStreamIdentifier", "x509ce.CRLStreamIdentifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CRLStreamIdentifier", HFILL }},
    { &hf_x509ce_OrderedListSyntax_PDU,
      { "OrderedListSyntax", "x509ce.OrderedListSyntax",
        FT_UINT32, BASE_DEC, VALS(x509ce_OrderedListSyntax_vals), 0,
        "OrderedListSyntax", HFILL }},
    { &hf_x509ce_DeltaInformation_PDU,
      { "DeltaInformation", "x509ce.DeltaInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeltaInformation", HFILL }},
    { &hf_x509ce_CRLDistPointsSyntax_PDU,
      { "CRLDistPointsSyntax", "x509ce.CRLDistPointsSyntax",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CRLDistPointsSyntax", HFILL }},
    { &hf_x509ce_IssuingDistPointSyntax_PDU,
      { "IssuingDistPointSyntax", "x509ce.IssuingDistPointSyntax",
        FT_NONE, BASE_NONE, NULL, 0,
        "IssuingDistPointSyntax", HFILL }},
    { &hf_x509ce_BaseCRLNumber_PDU,
      { "BaseCRLNumber", "x509ce.BaseCRLNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "BaseCRLNumber", HFILL }},
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
      { "Item", "x509ce.KeyPurposeIDs_item",
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
      { "Item", "x509ce.CertificatePoliciesSyntax_item",
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
      { "Item", "x509ce.policyQualifiers_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "PolicyInformation/policyQualifiers/_item", HFILL }},
    { &hf_x509ce_policyQualifierId,
      { "policyQualifierId", "x509ce.policyQualifierId",
        FT_STRING, BASE_NONE, NULL, 0,
        "PolicyQualifierInfo/policyQualifierId", HFILL }},
    { &hf_x509ce_qualifier,
      { "qualifier", "x509ce.qualifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "PolicyQualifierInfo/qualifier", HFILL }},
    { &hf_x509ce_PolicyMappingsSyntax_item,
      { "Item", "x509ce.PolicyMappingsSyntax_item",
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
      { "Item", "x509ce.GeneralNames_item",
        FT_UINT32, BASE_DEC, VALS(x509ce_GeneralName_vals), 0,
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
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "GeneralName/directoryName", HFILL }},
    { &hf_x509ce_ediPartyName,
      { "ediPartyName", "x509ce.ediPartyName",
        FT_NONE, BASE_NONE, NULL, 0,
        "GeneralName/ediPartyName", HFILL }},
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
    { &hf_x509ce_nameAssigner,
      { "nameAssigner", "x509ce.nameAssigner",
        FT_STRING, BASE_NONE, NULL, 0,
        "EDIPartyName/nameAssigner", HFILL }},
    { &hf_x509ce_partyName,
      { "partyName", "x509ce.partyName",
        FT_STRING, BASE_NONE, NULL, 0,
        "EDIPartyName/partyName", HFILL }},
    { &hf_x509ce_AttributesSyntax_item,
      { "Item", "x509ce.AttributesSyntax_item",
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
      { "Item", "x509ce.GeneralSubtrees_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "GeneralSubtrees/_item", HFILL }},
    { &hf_x509ce_base,
      { "base", "x509ce.base",
        FT_UINT32, BASE_DEC, VALS(x509ce_GeneralName_vals), 0,
        "GeneralSubtree/base", HFILL }},
    { &hf_x509ce_minimum,
      { "minimum", "x509ce.minimum",
        FT_INT32, BASE_DEC, NULL, 0,
        "GeneralSubtree/minimum", HFILL }},
    { &hf_x509ce_maximum,
      { "maximum", "x509ce.maximum",
        FT_INT32, BASE_DEC, NULL, 0,
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
      { "Item", "x509ce.CRLScopeSyntax_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "CRLScopeSyntax/_item", HFILL }},
    { &hf_x509ce_authorityName,
      { "authorityName", "x509ce.authorityName",
        FT_UINT32, BASE_DEC, VALS(x509ce_GeneralName_vals), 0,
        "PerAuthorityScope/authorityName", HFILL }},
    { &hf_x509ce_distributionPoint,
      { "distributionPoint", "x509ce.distributionPoint",
        FT_UINT32, BASE_DEC, VALS(x509ce_DistributionPointName_vals), 0,
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
      { "Item", "x509ce.StatusReferrals_item",
        FT_UINT32, BASE_DEC, VALS(x509ce_StatusReferral_vals), 0,
        "StatusReferrals/_item", HFILL }},
    { &hf_x509ce_cRLReferral,
      { "cRLReferral", "x509ce.cRLReferral",
        FT_NONE, BASE_NONE, NULL, 0,
        "StatusReferral/cRLReferral", HFILL }},
    { &hf_x509ce_crlr_issuer,
      { "issuer", "x509ce.issuer",
        FT_UINT32, BASE_DEC, VALS(x509ce_GeneralName_vals), 0,
        "CRLReferral/issuer", HFILL }},
    { &hf_x509ce_location,
      { "location", "x509ce.location",
        FT_UINT32, BASE_DEC, VALS(x509ce_GeneralName_vals), 0,
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
        FT_UINT32, BASE_DEC, VALS(x509ce_GeneralName_vals), 0,
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
      { "Item", "x509ce.CRLDistPointsSyntax_item",
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
    { &hf_x509ce_serialNumber,
      { "serialNumber", "x509ce.serialNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_x509ce_issuer,
      { "issuer", "x509ce.issuer",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "", HFILL }},
    { &hf_x509ce_subjectKeyIdentifier,
      { "subjectKeyIdentifier", "x509ce.subjectKeyIdentifier",
        FT_BYTES, BASE_HEX, NULL, 0,
        "CertificateAssertion/subjectKeyIdentifier", HFILL }},
    { &hf_x509ce_authorityKeyIdentifier,
      { "authorityKeyIdentifier", "x509ce.authorityKeyIdentifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x509ce_privateKeyValid,
      { "privateKeyValid", "x509ce.privateKeyValid",
        FT_STRING, BASE_NONE, NULL, 0,
        "CertificateAssertion/privateKeyValid", HFILL }},
    { &hf_x509ce_subjectPublicKeyAlgID,
      { "subjectPublicKeyAlgID", "x509ce.subjectPublicKeyAlgID",
        FT_STRING, BASE_NONE, NULL, 0,
        "CertificateAssertion/subjectPublicKeyAlgID", HFILL }},
    { &hf_x509ce_keyUsage,
      { "keyUsage", "x509ce.keyUsage",
        FT_BYTES, BASE_HEX, NULL, 0,
        "CertificateAssertion/keyUsage", HFILL }},
    { &hf_x509ce_subjectAltName,
      { "subjectAltName", "x509ce.subjectAltName",
        FT_UINT32, BASE_DEC, VALS(x509ce_AltNameType_vals), 0,
        "CertificateAssertion/subjectAltName", HFILL }},
    { &hf_x509ce_policy,
      { "policy", "x509ce.policy",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CertificateAssertion/policy", HFILL }},
    { &hf_x509ce_pathToName,
      { "pathToName", "x509ce.pathToName",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "CertificateAssertion/pathToName", HFILL }},
    { &hf_x509ce_subject,
      { "subject", "x509ce.subject",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "CertificateAssertion/subject", HFILL }},
    { &hf_x509ce_nameConstraints,
      { "nameConstraints", "x509ce.nameConstraints",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertificateAssertion/nameConstraints", HFILL }},
    { &hf_x509ce_builtinNameForm,
      { "builtinNameForm", "x509ce.builtinNameForm",
        FT_UINT32, BASE_DEC, VALS(x509ce_T_builtinNameForm_vals), 0,
        "AltNameType/builtinNameForm", HFILL }},
    { &hf_x509ce_otherNameForm,
      { "otherNameForm", "x509ce.otherNameForm",
        FT_STRING, BASE_NONE, NULL, 0,
        "AltNameType/otherNameForm", HFILL }},
    { &hf_x509ce_CertPolicySet_item,
      { "Item", "x509ce.CertPolicySet_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "CertPolicySet/_item", HFILL }},
    { &hf_x509ce_cpea_issuedToThisCAAssertion,
      { "issuedToThisCAAssertion", "x509ce.issuedToThisCAAssertion",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertificatePairExactAssertion/issuedToThisCAAssertion", HFILL }},
    { &hf_x509ce_cpea_issuedByThisCAAssertion,
      { "issuedByThisCAAssertion", "x509ce.issuedByThisCAAssertion",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertificatePairExactAssertion/issuedByThisCAAssertion", HFILL }},
    { &hf_x509ce_issuedToThisCAAssertion,
      { "issuedToThisCAAssertion", "x509ce.issuedToThisCAAssertion",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertificatePairAssertion/issuedToThisCAAssertion", HFILL }},
    { &hf_x509ce_issuedByThisCAAssertion,
      { "issuedByThisCAAssertion", "x509ce.issuedByThisCAAssertion",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertificatePairAssertion/issuedByThisCAAssertion", HFILL }},
    { &hf_x509ce_minCRLNumber,
      { "minCRLNumber", "x509ce.minCRLNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CertificateListAssertion/minCRLNumber", HFILL }},
    { &hf_x509ce_maxCRLNumber,
      { "maxCRLNumber", "x509ce.maxCRLNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CertificateListAssertion/maxCRLNumber", HFILL }},
    { &hf_x509ce_reasonFlags,
      { "reasonFlags", "x509ce.reasonFlags",
        FT_BYTES, BASE_HEX, NULL, 0,
        "CertificateListAssertion/reasonFlags", HFILL }},
    { &hf_x509ce_firstIssuer,
      { "firstIssuer", "x509ce.firstIssuer",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "PkiPathMatchSyntax/firstIssuer", HFILL }},
    { &hf_x509ce_lastSubject,
      { "lastSubject", "x509ce.lastSubject",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "PkiPathMatchSyntax/lastSubject", HFILL }},
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

    &ett_x509ce_AuthorityKeyIdentifier,
    &ett_x509ce_KeyUsage,
    &ett_x509ce_KeyPurposeIDs,
    &ett_x509ce_PrivateKeyUsagePeriod,
    &ett_x509ce_CertificatePoliciesSyntax,
    &ett_x509ce_PolicyInformation,
    &ett_x509ce_SEQUENCE_SIZE_1_MAX_OF_PolicyQualifierInfo,
    &ett_x509ce_PolicyQualifierInfo,
    &ett_x509ce_PolicyMappingsSyntax,
    &ett_x509ce_PolicyMappingsSyntax_item,
    &ett_x509ce_GeneralNames,
    &ett_x509ce_GeneralName,
    &ett_x509ce_EDIPartyName,
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
    &ett_x509ce_CertificateExactAssertion,
    &ett_x509ce_CertificateAssertion,
    &ett_x509ce_AltNameType,
    &ett_x509ce_CertPolicySet,
    &ett_x509ce_CertificatePairExactAssertion,
    &ett_x509ce_CertificatePairAssertion,
    &ett_x509ce_CertificateListExactAssertion,
    &ett_x509ce_CertificateListAssertion,
    &ett_x509ce_PkiPathMatchSyntax,

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

/*--- Included file: packet-x509ce-dis-tab.c ---*/

  register_ber_oid_dissector("2.5.29.9", dissect_AttributesSyntax_PDU, proto_x509ce, "id-ce-subjectDirectoryAttributes");
  register_ber_oid_dissector("2.5.29.14", dissect_SubjectKeyIdentifier_PDU, proto_x509ce, "id-ce-subjectKeyIdentifier");
  register_ber_oid_dissector("2.5.29.15", dissect_KeyUsage_PDU, proto_x509ce, "id-ce-keyUsage");
  register_ber_oid_dissector("2.5.29.16", dissect_PrivateKeyUsagePeriod_PDU, proto_x509ce, "id-ce-privateKeyUsagePeriod");
  register_ber_oid_dissector("2.5.29.17", dissect_GeneralNames_PDU, proto_x509ce, "id-ce-subjectAltName");
  register_ber_oid_dissector("2.5.29.18", dissect_GeneralNames_PDU, proto_x509ce, "id-ce-issuerAltName");
  register_ber_oid_dissector("2.5.29.19", dissect_BasicConstraintsSyntax_PDU, proto_x509ce, "id-ce-basicConstraints");
  register_ber_oid_dissector("2.5.29.20", dissect_CRLNumber_PDU, proto_x509ce, "id-ce-cRLNumber");
  register_ber_oid_dissector("2.5.29.21", dissect_CRLReason_PDU, proto_x509ce, "id-ce-reasonCode");
  register_ber_oid_dissector("2.5.29.23", dissect_HoldInstruction_PDU, proto_x509ce, "id-ce-instructionCode");
  register_ber_oid_dissector("2.5.29.27", dissect_BaseCRLNumber_PDU, proto_x509ce, "id-ce-deltaCRLIndicator");
  register_ber_oid_dissector("2.5.29.28", dissect_IssuingDistPointSyntax_PDU, proto_x509ce, "id-ce-issuingDistributionPoint");
  register_ber_oid_dissector("2.5.29.29", dissect_GeneralNames_PDU, proto_x509ce, "id-ce-certificateIssuer");
  register_ber_oid_dissector("2.5.29.30", dissect_NameConstraintsSyntax_PDU, proto_x509ce, "id-ce-nameConstraints");
  register_ber_oid_dissector("2.5.29.31", dissect_CRLDistPointsSyntax_PDU, proto_x509ce, "id-ce-cRLDistributionPoints");
  register_ber_oid_dissector("2.5.29.32", dissect_CertificatePoliciesSyntax_PDU, proto_x509ce, "id-ce-certificatePolicies");
  register_ber_oid_dissector("2.5.29.33", dissect_PolicyMappingsSyntax_PDU, proto_x509ce, "id-ce-policyMappings");
  register_ber_oid_dissector("2.5.29.35", dissect_AuthorityKeyIdentifier_PDU, proto_x509ce, "id-ce-authorityKeyIdentifier");
  register_ber_oid_dissector("2.5.29.36", dissect_PolicyConstraintsSyntax_PDU, proto_x509ce, "id-ce-policyConstraints");
  register_ber_oid_dissector("2.5.29.37", dissect_KeyPurposeIDs_PDU, proto_x509ce, "id-ce-extKeyUsage");
  register_ber_oid_dissector("2.5.29.40", dissect_CRLStreamIdentifier_PDU, proto_x509ce, "id-ce-cRLStreamIdentifier");
  register_ber_oid_dissector("2.5.29.44", dissect_CRLScopeSyntax_PDU, proto_x509ce, "id-ce-cRLScope");
  register_ber_oid_dissector("2.5.29.45", dissect_StatusReferrals_PDU, proto_x509ce, "id-ce-statusReferrals");
  register_ber_oid_dissector("2.5.29.46", dissect_CRLDistPointsSyntax_PDU, proto_x509ce, "id-ce-freshestCRL");
  register_ber_oid_dissector("2.5.29.47", dissect_OrderedListSyntax_PDU, proto_x509ce, "id-ce-orderedList");
  register_ber_oid_dissector("2.5.29.53", dissect_DeltaInformation_PDU, proto_x509ce, "id-ce-deltaInfo");
  register_ber_oid_dissector("2.5.29.54", dissect_SkipCerts_PDU, proto_x509ce, "id-ce-inhibitAnyPolicy");


/*--- End of included file: packet-x509ce-dis-tab.c ---*/

	register_ber_oid_dissector("2.5.29.24", dissect_x509ce_invalidityDate_callback, proto_x509ce, "id-ce-invalidityDate");
	register_ber_oid_dissector("2.5.29.51", dissect_x509ce_baseUpdateTime_callback, proto_x509ce, "id-ce-baseUpdateTime");
}

