/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-x509ce.c                                                            */
/* asn2wrs.py -b -q -L -p x509ce -c ./x509ce.cnf -s ./packet-x509ce-template -D . -O ../.. CertificateExtensions.asn CertificateExtensionsRFC9310.asn CertificateExtensionsCiplus.asn */

/* packet-x509ce.c
 * Routines for X.509 Certificate Extensions packet dissection
 *  Ronnie Sahlberg 2004
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
#include "packet-x509ce.h"
#include "packet-x509af.h"
#include "packet-x509if.h"
#include "packet-x509sat.h"
#include "packet-p1.h"

#define PNAME  "X.509 Certificate Extensions"
#define PSNAME "X509CE"
#define PFNAME "x509ce"

void proto_register_x509ce(void);
void proto_reg_handoff_x509ce(void);

/* Initialize the protocol and registered fields */
static int proto_x509ce;
static int hf_x509ce_id_ce_invalidityDate;
static int hf_x509ce_id_ce_baseUpdateTime;
static int hf_x509ce_object_identifier_id;
static int hf_x509ce_IPAddress_ipv4;
static int hf_x509ce_IPAddress_ipv4_mask;
static int hf_x509ce_IPAddress_ipv6;
static int hf_x509ce_IPAddress_ipv6_mask;
static int hf_x509ce_IPAddress_unknown;
static int hf_x509ce_AuthorityKeyIdentifier_PDU;  /* AuthorityKeyIdentifier */
static int hf_x509ce_SubjectKeyIdentifier_PDU;    /* SubjectKeyIdentifier */
static int hf_x509ce_KeyUsage_PDU;                /* KeyUsage */
static int hf_x509ce_KeyPurposeIDs_PDU;           /* KeyPurposeIDs */
static int hf_x509ce_PrivateKeyUsagePeriod_PDU;   /* PrivateKeyUsagePeriod */
static int hf_x509ce_CertificatePoliciesSyntax_PDU;  /* CertificatePoliciesSyntax */
static int hf_x509ce_PolicyMappingsSyntax_PDU;    /* PolicyMappingsSyntax */
static int hf_x509ce_GeneralNames_PDU;            /* GeneralNames */
static int hf_x509ce_AttributesSyntax_PDU;        /* AttributesSyntax */
static int hf_x509ce_BasicConstraintsSyntax_PDU;  /* BasicConstraintsSyntax */
static int hf_x509ce_NameConstraintsSyntax_PDU;   /* NameConstraintsSyntax */
static int hf_x509ce_PolicyConstraintsSyntax_PDU;  /* PolicyConstraintsSyntax */
static int hf_x509ce_SkipCerts_PDU;               /* SkipCerts */
static int hf_x509ce_CRLNumber_PDU;               /* CRLNumber */
static int hf_x509ce_CRLReason_PDU;               /* CRLReason */
static int hf_x509ce_HoldInstruction_PDU;         /* HoldInstruction */
static int hf_x509ce_CRLScopeSyntax_PDU;          /* CRLScopeSyntax */
static int hf_x509ce_StatusReferrals_PDU;         /* StatusReferrals */
static int hf_x509ce_CRLStreamIdentifier_PDU;     /* CRLStreamIdentifier */
static int hf_x509ce_OrderedListSyntax_PDU;       /* OrderedListSyntax */
static int hf_x509ce_DeltaInformation_PDU;        /* DeltaInformation */
static int hf_x509ce_CRLDistPointsSyntax_PDU;     /* CRLDistPointsSyntax */
static int hf_x509ce_IssuingDistPointSyntax_PDU;  /* IssuingDistPointSyntax */
static int hf_x509ce_BaseCRLNumber_PDU;           /* BaseCRLNumber */
static int hf_x509ce_ToBeRevokedSyntax_PDU;       /* ToBeRevokedSyntax */
static int hf_x509ce_RevokedGroupsSyntax_PDU;     /* RevokedGroupsSyntax */
static int hf_x509ce_ExpiredCertsOnCRL_PDU;       /* ExpiredCertsOnCRL */
static int hf_x509ce_AAIssuingDistPointSyntax_PDU;  /* AAIssuingDistPointSyntax */
static int hf_x509ce_CertificateAssertion_PDU;    /* CertificateAssertion */
static int hf_x509ce_CertificatePairExactAssertion_PDU;  /* CertificatePairExactAssertion */
static int hf_x509ce_CertificatePairAssertion_PDU;  /* CertificatePairAssertion */
static int hf_x509ce_CertificateListExactAssertion_PDU;  /* CertificateListExactAssertion */
static int hf_x509ce_CertificateListAssertion_PDU;  /* CertificateListAssertion */
static int hf_x509ce_PkiPathMatchSyntax_PDU;      /* PkiPathMatchSyntax */
static int hf_x509ce_EnhancedCertificateAssertion_PDU;  /* EnhancedCertificateAssertion */
static int hf_x509ce_CertificateTemplate_PDU;     /* CertificateTemplate */
static int hf_x509ce_NtdsCaSecurity_PDU;          /* NtdsCaSecurity */
static int hf_x509ce_NtdsObjectSid_PDU;           /* NtdsObjectSid */
static int hf_x509ce_EntrustVersionInfo_PDU;      /* EntrustVersionInfo */
static int hf_x509ce_NFTypes_PDU;                 /* NFTypes */
static int hf_x509ce_ScramblerCapabilities_PDU;   /* ScramblerCapabilities */
static int hf_x509ce_CiplusInfo_PDU;              /* CiplusInfo */
static int hf_x509ce_CicamBrandId_PDU;            /* CicamBrandId */
static int hf_x509ce_SecurityLevel_PDU;           /* SecurityLevel */
static int hf_x509ce_keyIdentifier;               /* KeyIdentifier */
static int hf_x509ce_authorityCertIssuer;         /* GeneralNames */
static int hf_x509ce_authorityCertSerialNumber;   /* CertificateSerialNumber */
static int hf_x509ce_KeyPurposeIDs_item;          /* KeyPurposeId */
static int hf_x509ce_notBefore;                   /* GeneralizedTime */
static int hf_x509ce_notAfter;                    /* GeneralizedTime */
static int hf_x509ce_CertificatePoliciesSyntax_item;  /* PolicyInformation */
static int hf_x509ce_policyIdentifier;            /* CertPolicyId */
static int hf_x509ce_policyQualifiers;            /* SEQUENCE_SIZE_1_MAX_OF_PolicyQualifierInfo */
static int hf_x509ce_policyQualifiers_item;       /* PolicyQualifierInfo */
static int hf_x509ce_policyQualifierId;           /* T_policyQualifierId */
static int hf_x509ce_qualifier;                   /* T_qualifier */
static int hf_x509ce_PolicyMappingsSyntax_item;   /* PolicyMappingsSyntax_item */
static int hf_x509ce_issuerDomainPolicy;          /* CertPolicyId */
static int hf_x509ce_subjectDomainPolicy;         /* CertPolicyId */
static int hf_x509ce_GeneralNames_item;           /* GeneralName */
static int hf_x509ce_otherName;                   /* OtherName */
static int hf_x509ce_rfc822Name;                  /* IA5String */
static int hf_x509ce_dNSName;                     /* IA5String */
static int hf_x509ce_x400Address;                 /* ORAddress */
static int hf_x509ce_directoryName;               /* Name */
static int hf_x509ce_ediPartyName;                /* EDIPartyName */
static int hf_x509ce_uniformResourceIdentifier;   /* T_uniformResourceIdentifier */
static int hf_x509ce_iPAddress;                   /* T_iPAddress */
static int hf_x509ce_registeredID;                /* OBJECT_IDENTIFIER */
static int hf_x509ce_type_id;                     /* OtherNameType */
static int hf_x509ce_value;                       /* OtherNameValue */
static int hf_x509ce_nameAssigner;                /* DirectoryString */
static int hf_x509ce_partyName;                   /* DirectoryString */
static int hf_x509ce_AttributesSyntax_item;       /* Attribute */
static int hf_x509ce_cA;                          /* BOOLEAN */
static int hf_x509ce_pathLenConstraint;           /* INTEGER_0_MAX */
static int hf_x509ce_permittedSubtrees;           /* GeneralSubtrees */
static int hf_x509ce_excludedSubtrees;            /* GeneralSubtrees */
static int hf_x509ce_GeneralSubtrees_item;        /* GeneralSubtree */
static int hf_x509ce_base;                        /* GeneralName */
static int hf_x509ce_minimum;                     /* BaseDistance */
static int hf_x509ce_maximum;                     /* BaseDistance */
static int hf_x509ce_requireExplicitPolicy;       /* SkipCerts */
static int hf_x509ce_inhibitPolicyMapping;        /* SkipCerts */
static int hf_x509ce_CRLScopeSyntax_item;         /* PerAuthorityScope */
static int hf_x509ce_authorityName;               /* GeneralName */
static int hf_x509ce_distributionPoint;           /* DistributionPointName */
static int hf_x509ce_onlyContains;                /* OnlyCertificateTypes */
static int hf_x509ce_onlySomeReasons;             /* ReasonFlags */
static int hf_x509ce_serialNumberRange;           /* NumberRange */
static int hf_x509ce_subjectKeyIdRange;           /* NumberRange */
static int hf_x509ce_nameSubtrees;                /* GeneralNames */
static int hf_x509ce_baseRevocationInfo;          /* BaseRevocationInfo */
static int hf_x509ce_startingNumber;              /* INTEGER */
static int hf_x509ce_endingNumber;                /* INTEGER */
static int hf_x509ce_modulus;                     /* INTEGER */
static int hf_x509ce_cRLStreamIdentifier;         /* CRLStreamIdentifier */
static int hf_x509ce_cRLNumber;                   /* CRLNumber */
static int hf_x509ce_baseThisUpdate;              /* GeneralizedTime */
static int hf_x509ce_StatusReferrals_item;        /* StatusReferral */
static int hf_x509ce_cRLReferral;                 /* CRLReferral */
static int hf_x509ce_crlr_issuer;                 /* GeneralName */
static int hf_x509ce_location;                    /* GeneralName */
static int hf_x509ce_deltaRefInfo;                /* DeltaRefInfo */
static int hf_x509ce_cRLScope;                    /* CRLScopeSyntax */
static int hf_x509ce_lastUpdate;                  /* GeneralizedTime */
static int hf_x509ce_lastChangedCRL;              /* GeneralizedTime */
static int hf_x509ce_deltaLocation;               /* GeneralName */
static int hf_x509ce_lastDelta;                   /* GeneralizedTime */
static int hf_x509ce_nextDelta;                   /* GeneralizedTime */
static int hf_x509ce_CRLDistPointsSyntax_item;    /* DistributionPoint */
static int hf_x509ce_reasons;                     /* ReasonFlags */
static int hf_x509ce_cRLIssuer;                   /* GeneralNames */
static int hf_x509ce_fullName;                    /* GeneralNames */
static int hf_x509ce_nameRelativeToCRLIssuer;     /* RelativeDistinguishedName */
static int hf_x509ce_onlyContainsUserPublicKeyCerts;  /* BOOLEAN */
static int hf_x509ce_onlyContainsCACerts;         /* BOOLEAN */
static int hf_x509ce_indirectCRL;                 /* BOOLEAN */
static int hf_x509ce_ToBeRevokedSyntax_item;      /* ToBeRevokedGroup */
static int hf_x509ce_certificateIssuer;           /* GeneralName */
static int hf_x509ce_reasonInfo;                  /* ReasonInfo */
static int hf_x509ce_revocationTime;              /* GeneralizedTime */
static int hf_x509ce_certificateGroup;            /* CertificateGroup */
static int hf_x509ce_reasonCode;                  /* CRLReason */
static int hf_x509ce_holdInstructionCode;         /* HoldInstruction */
static int hf_x509ce_serialNumbers;               /* CertificateSerialNumbers */
static int hf_x509ce_certificateGroupNumberRange;  /* CertificateGroupNumberRange */
static int hf_x509ce_nameSubtree;                 /* GeneralName */
static int hf_x509ce_CertificateSerialNumbers_item;  /* CertificateSerialNumber */
static int hf_x509ce_RevokedGroupsSyntax_item;    /* RevokedGroup */
static int hf_x509ce_invalidityDate;              /* GeneralizedTime */
static int hf_x509ce_revokedcertificateGroup;     /* RevokedCertificateGroup */
static int hf_x509ce_containsUserAttributeCerts;  /* BOOLEAN */
static int hf_x509ce_containsAACerts;             /* BOOLEAN */
static int hf_x509ce_containsSOAPublicKeyCerts;   /* BOOLEAN */
static int hf_x509ce_serialNumber;                /* CertificateSerialNumber */
static int hf_x509ce_issuer;                      /* Name */
static int hf_x509ce_subjectKeyIdentifier;        /* SubjectKeyIdentifier */
static int hf_x509ce_authorityKeyIdentifier;      /* AuthorityKeyIdentifier */
static int hf_x509ce_certificateValid;            /* Time */
static int hf_x509ce_privateKeyValid;             /* GeneralizedTime */
static int hf_x509ce_subjectPublicKeyAlgID;       /* OBJECT_IDENTIFIER */
static int hf_x509ce_keyUsage;                    /* KeyUsage */
static int hf_x509ce_subjectAltNameType;          /* AltNameType */
static int hf_x509ce_policy;                      /* CertPolicySet */
static int hf_x509ce_pathToName;                  /* Name */
static int hf_x509ce_subject;                     /* Name */
static int hf_x509ce_nameConstraints;             /* NameConstraintsSyntax */
static int hf_x509ce_builtinNameForm;             /* T_builtinNameForm */
static int hf_x509ce_otherNameForm;               /* OBJECT_IDENTIFIER */
static int hf_x509ce_CertPolicySet_item;          /* CertPolicyId */
static int hf_x509ce_cpea_issuedToThisCAAssertion;  /* CertificateExactAssertion */
static int hf_x509ce_cpea_issuedByThisCAAssertion;  /* CertificateExactAssertion */
static int hf_x509ce_issuedToThisCAAssertion;     /* CertificateAssertion */
static int hf_x509ce_issuedByThisCAAssertion;     /* CertificateAssertion */
static int hf_x509ce_thisUpdate;                  /* Time */
static int hf_x509ce_minCRLNumber;                /* CRLNumber */
static int hf_x509ce_maxCRLNumber;                /* CRLNumber */
static int hf_x509ce_reasonFlags;                 /* ReasonFlags */
static int hf_x509ce_dateAndTime;                 /* Time */
static int hf_x509ce_firstIssuer;                 /* Name */
static int hf_x509ce_lastSubject;                 /* Name */
static int hf_x509ce_subjectAltName;              /* AltName */
static int hf_x509ce_enhancedPathToName;          /* GeneralNames */
static int hf_x509ce_altnameType;                 /* AltNameType */
static int hf_x509ce_altNameValue;                /* GeneralName */
static int hf_x509ce_templateID;                  /* OBJECT_IDENTIFIER */
static int hf_x509ce_templateMajorVersion;        /* INTEGER */
static int hf_x509ce_templateMinorVersion;        /* INTEGER */
static int hf_x509ce_ntdsObjectSid;               /* NtdsObjectSid */
static int hf_x509ce_type_id_01;                  /* OBJECT_IDENTIFIER */
static int hf_x509ce_sid;                         /* PrintableString */
static int hf_x509ce_entrustVers;                 /* GeneralString */
static int hf_x509ce_entrustVersInfoFlags;        /* EntrustInfoFlags */
static int hf_x509ce_NFTypes_item;                /* NFType */
static int hf_x509ce_capability;                  /* INTEGER_0_MAX */
static int hf_x509ce_version;                     /* INTEGER_0_MAX */
/* named bits */
static int hf_x509ce_KeyUsage_digitalSignature;
static int hf_x509ce_KeyUsage_contentCommitment;
static int hf_x509ce_KeyUsage_keyEncipherment;
static int hf_x509ce_KeyUsage_dataEncipherment;
static int hf_x509ce_KeyUsage_keyAgreement;
static int hf_x509ce_KeyUsage_keyCertSign;
static int hf_x509ce_KeyUsage_cRLSign;
static int hf_x509ce_KeyUsage_encipherOnly;
static int hf_x509ce_KeyUsage_decipherOnly;
static int hf_x509ce_OnlyCertificateTypes_user;
static int hf_x509ce_OnlyCertificateTypes_authority;
static int hf_x509ce_OnlyCertificateTypes_attribute;
static int hf_x509ce_ReasonFlags_unused;
static int hf_x509ce_ReasonFlags_keyCompromise;
static int hf_x509ce_ReasonFlags_cACompromise;
static int hf_x509ce_ReasonFlags_affiliationChanged;
static int hf_x509ce_ReasonFlags_superseded;
static int hf_x509ce_ReasonFlags_cessationOfOperation;
static int hf_x509ce_ReasonFlags_certificateHold;
static int hf_x509ce_ReasonFlags_privilegeWithdrawn;
static int hf_x509ce_ReasonFlags_aACompromise;
static int hf_x509ce_EntrustInfoFlags_keyUpdateAllowed;
static int hf_x509ce_EntrustInfoFlags_newExtensions;
static int hf_x509ce_EntrustInfoFlags_pKIXCertificate;
static int hf_x509ce_EntrustInfoFlags_enterpriseCategory;
static int hf_x509ce_EntrustInfoFlags_webCategory;
static int hf_x509ce_EntrustInfoFlags_sETCategory;

/* Initialize the subtree pointers */
static int ett_x509ce_AuthorityKeyIdentifier;
static int ett_x509ce_KeyUsage;
static int ett_x509ce_KeyPurposeIDs;
static int ett_x509ce_PrivateKeyUsagePeriod;
static int ett_x509ce_CertificatePoliciesSyntax;
static int ett_x509ce_PolicyInformation;
static int ett_x509ce_SEQUENCE_SIZE_1_MAX_OF_PolicyQualifierInfo;
static int ett_x509ce_PolicyQualifierInfo;
static int ett_x509ce_PolicyMappingsSyntax;
static int ett_x509ce_PolicyMappingsSyntax_item;
static int ett_x509ce_GeneralNames;
static int ett_x509ce_GeneralName;
static int ett_x509ce_OtherName;
static int ett_x509ce_EDIPartyName;
static int ett_x509ce_AttributesSyntax;
static int ett_x509ce_BasicConstraintsSyntax;
static int ett_x509ce_NameConstraintsSyntax;
static int ett_x509ce_GeneralSubtrees;
static int ett_x509ce_GeneralSubtree;
static int ett_x509ce_PolicyConstraintsSyntax;
static int ett_x509ce_CRLScopeSyntax;
static int ett_x509ce_PerAuthorityScope;
static int ett_x509ce_OnlyCertificateTypes;
static int ett_x509ce_NumberRange;
static int ett_x509ce_BaseRevocationInfo;
static int ett_x509ce_StatusReferrals;
static int ett_x509ce_StatusReferral;
static int ett_x509ce_CRLReferral;
static int ett_x509ce_DeltaRefInfo;
static int ett_x509ce_DeltaInformation;
static int ett_x509ce_CRLDistPointsSyntax;
static int ett_x509ce_DistributionPoint;
static int ett_x509ce_DistributionPointName;
static int ett_x509ce_ReasonFlags;
static int ett_x509ce_IssuingDistPointSyntax;
static int ett_x509ce_ToBeRevokedSyntax;
static int ett_x509ce_ToBeRevokedGroup;
static int ett_x509ce_ReasonInfo;
static int ett_x509ce_CertificateGroup;
static int ett_x509ce_CertificateGroupNumberRange;
static int ett_x509ce_CertificateSerialNumbers;
static int ett_x509ce_RevokedGroupsSyntax;
static int ett_x509ce_RevokedGroup;
static int ett_x509ce_RevokedCertificateGroup;
static int ett_x509ce_AAIssuingDistPointSyntax;
static int ett_x509ce_CertificateExactAssertion;
static int ett_x509ce_CertificateAssertion;
static int ett_x509ce_AltNameType;
static int ett_x509ce_CertPolicySet;
static int ett_x509ce_CertificatePairExactAssertion;
static int ett_x509ce_CertificatePairAssertion;
static int ett_x509ce_CertificateListExactAssertion;
static int ett_x509ce_CertificateListAssertion;
static int ett_x509ce_PkiPathMatchSyntax;
static int ett_x509ce_EnhancedCertificateAssertion;
static int ett_x509ce_AltName;
static int ett_x509ce_CertificateTemplate;
static int ett_x509ce_NtdsCaSecurity;
static int ett_x509ce_NtdsObjectSid_U;
static int ett_x509ce_EntrustVersionInfo;
static int ett_x509ce_EntrustInfoFlags;
static int ett_x509ce_NFTypes;
static int ett_x509ce_ScramblerCapabilities;


int
dissect_x509ce_KeyIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_x509ce_OtherNameType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &actx->external.direct_reference);

  return offset;
}



static int
dissect_x509ce_OtherNameValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset=call_ber_oid_callback(actx->external.direct_reference, tvb, offset, actx->pinfo, tree, NULL);


  return offset;
}


static const ber_sequence_t OtherName_sequence[] = {
  { &hf_x509ce_type_id      , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509ce_OtherNameType },
  { &hf_x509ce_value        , BER_CLASS_CON, 0, 0, dissect_x509ce_OtherNameValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x509ce_OtherName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OtherName_sequence, hf_index, ett_x509ce_OtherName);

  return offset;
}



static int
dissect_x509ce_IA5String(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t EDIPartyName_sequence[] = {
  { &hf_x509ce_nameAssigner , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509sat_DirectoryString },
  { &hf_x509ce_partyName    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_x509sat_DirectoryString },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509ce_EDIPartyName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EDIPartyName_sequence, hf_index, ett_x509ce_EDIPartyName);

  return offset;
}



static int
dissect_x509ce_T_uniformResourceIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);


  proto_item_set_url(actx->created_item);

  return offset;
}



static int
dissect_x509ce_T_iPAddress(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  uint32_t len = tvb_reported_length(tvb);
  switch (len) {
  case 4: /* IPv4 */
    proto_tree_add_item(tree, hf_x509ce_IPAddress_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    break;
  case 8: /* IPv4 + Mask*/
    proto_tree_add_item(tree, hf_x509ce_IPAddress_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_x509ce_IPAddress_ipv4_mask, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    break;
  case 16: /* IPv6 */
    proto_tree_add_item(tree, hf_x509ce_IPAddress_ipv6, tvb, offset, 16, ENC_NA);
    offset += 16;
    break;
  case 32: /* IPv6 + Mask */
    proto_tree_add_item(tree, hf_x509ce_IPAddress_ipv6, tvb, offset, 16, ENC_NA);
    offset += 16;
    proto_tree_add_item(tree, hf_x509ce_IPAddress_ipv6_mask, tvb, offset, 16, ENC_NA);
    offset += 16;
    break;
  default: /* Unknown */
    proto_tree_add_item(tree, hf_x509ce_IPAddress_unknown, tvb, offset, len, ENC_NA);
    offset += len;
    break;
  }


  return offset;
}



static int
dissect_x509ce_OBJECT_IDENTIFIER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


const value_string x509ce_GeneralName_vals[] = {
  {   0, "otherName" },
  {   1, "rfc822Name" },
  {   2, "dNSName" },
  {   3, "x400Address" },
  {   4, "directoryName" },
  {   5, "ediPartyName" },
  {   6, "uniformResourceIdentifier" },
  {   7, "iPAddress" },
  {   8, "registeredID" },
  { 0, NULL }
};

static const ber_choice_t GeneralName_choice[] = {
  {   0, &hf_x509ce_otherName    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x509ce_OtherName },
  {   1, &hf_x509ce_rfc822Name   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_x509ce_IA5String },
  {   2, &hf_x509ce_dNSName      , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_x509ce_IA5String },
  {   3, &hf_x509ce_x400Address  , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_p1_ORAddress },
  {   4, &hf_x509ce_directoryName, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_x509if_Name },
  {   5, &hf_x509ce_ediPartyName , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_x509ce_EDIPartyName },
  {   6, &hf_x509ce_uniformResourceIdentifier, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_x509ce_T_uniformResourceIdentifier },
  {   7, &hf_x509ce_iPAddress    , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_x509ce_T_iPAddress },
  {   8, &hf_x509ce_registeredID , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_x509ce_OBJECT_IDENTIFIER },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_x509ce_GeneralName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 GeneralName_choice, hf_index, ett_x509ce_GeneralName,
                                 NULL);

  return offset;
}


static const ber_sequence_t GeneralNames_sequence_of[1] = {
  { &hf_x509ce_GeneralNames_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x509ce_GeneralName },
};

int
dissect_x509ce_GeneralNames(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      GeneralNames_sequence_of, hf_index, ett_x509ce_GeneralNames);

  return offset;
}


static const ber_sequence_t AuthorityKeyIdentifier_sequence[] = {
  { &hf_x509ce_keyIdentifier, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_KeyIdentifier },
  { &hf_x509ce_authorityCertIssuer, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_GeneralNames },
  { &hf_x509ce_authorityCertSerialNumber, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509af_CertificateSerialNumber },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509ce_AuthorityKeyIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AuthorityKeyIdentifier_sequence, hf_index, ett_x509ce_AuthorityKeyIdentifier);

  return offset;
}



int
dissect_x509ce_SubjectKeyIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509ce_KeyIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static int * const KeyUsage_bits[] = {
  &hf_x509ce_KeyUsage_digitalSignature,
  &hf_x509ce_KeyUsage_contentCommitment,
  &hf_x509ce_KeyUsage_keyEncipherment,
  &hf_x509ce_KeyUsage_dataEncipherment,
  &hf_x509ce_KeyUsage_keyAgreement,
  &hf_x509ce_KeyUsage_keyCertSign,
  &hf_x509ce_KeyUsage_cRLSign,
  &hf_x509ce_KeyUsage_encipherOnly,
  &hf_x509ce_KeyUsage_decipherOnly,
  NULL
};

int
dissect_x509ce_KeyUsage(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    KeyUsage_bits, 9, hf_index, ett_x509ce_KeyUsage,
                                    NULL);

  return offset;
}



int
dissect_x509ce_KeyPurposeId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t KeyPurposeIDs_sequence_of[1] = {
  { &hf_x509ce_KeyPurposeIDs_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509ce_KeyPurposeId },
};

int
dissect_x509ce_KeyPurposeIDs(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      KeyPurposeIDs_sequence_of, hf_index, ett_x509ce_KeyPurposeIDs);

  return offset;
}



static int
dissect_x509ce_GeneralizedTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t PrivateKeyUsagePeriod_sequence[] = {
  { &hf_x509ce_notBefore    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_GeneralizedTime },
  { &hf_x509ce_notAfter     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_GeneralizedTime },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509ce_PrivateKeyUsagePeriod(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PrivateKeyUsagePeriod_sequence, hf_index, ett_x509ce_PrivateKeyUsagePeriod);

  return offset;
}



static int
dissect_x509ce_CertPolicyId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_x509ce_T_policyQualifierId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_x509ce_object_identifier_id, &actx->external.direct_reference);

  return offset;
}



static int
dissect_x509ce_T_qualifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset=call_ber_oid_callback(actx->external.direct_reference, tvb, offset, actx->pinfo, tree, NULL);


  return offset;
}


static const ber_sequence_t PolicyQualifierInfo_sequence[] = {
  { &hf_x509ce_policyQualifierId, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509ce_T_policyQualifierId },
  { &hf_x509ce_qualifier    , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509ce_T_qualifier },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509ce_PolicyQualifierInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PolicyQualifierInfo_sequence, hf_index, ett_x509ce_PolicyQualifierInfo);

  return offset;
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_PolicyQualifierInfo_sequence_of[1] = {
  { &hf_x509ce_policyQualifiers_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509ce_PolicyQualifierInfo },
};

static int
dissect_x509ce_SEQUENCE_SIZE_1_MAX_OF_PolicyQualifierInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_PolicyQualifierInfo_sequence_of, hf_index, ett_x509ce_SEQUENCE_SIZE_1_MAX_OF_PolicyQualifierInfo);

  return offset;
}


static const ber_sequence_t PolicyInformation_sequence[] = {
  { &hf_x509ce_policyIdentifier, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509ce_CertPolicyId },
  { &hf_x509ce_policyQualifiers, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509ce_SEQUENCE_SIZE_1_MAX_OF_PolicyQualifierInfo },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509ce_PolicyInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PolicyInformation_sequence, hf_index, ett_x509ce_PolicyInformation);

  return offset;
}


static const ber_sequence_t CertificatePoliciesSyntax_sequence_of[1] = {
  { &hf_x509ce_CertificatePoliciesSyntax_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509ce_PolicyInformation },
};

int
dissect_x509ce_CertificatePoliciesSyntax(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      CertificatePoliciesSyntax_sequence_of, hf_index, ett_x509ce_CertificatePoliciesSyntax);

  return offset;
}


static const ber_sequence_t PolicyMappingsSyntax_item_sequence[] = {
  { &hf_x509ce_issuerDomainPolicy, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509ce_CertPolicyId },
  { &hf_x509ce_subjectDomainPolicy, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509ce_CertPolicyId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x509ce_PolicyMappingsSyntax_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PolicyMappingsSyntax_item_sequence, hf_index, ett_x509ce_PolicyMappingsSyntax_item);

  return offset;
}


static const ber_sequence_t PolicyMappingsSyntax_sequence_of[1] = {
  { &hf_x509ce_PolicyMappingsSyntax_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509ce_PolicyMappingsSyntax_item },
};

int
dissect_x509ce_PolicyMappingsSyntax(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      PolicyMappingsSyntax_sequence_of, hf_index, ett_x509ce_PolicyMappingsSyntax);

  return offset;
}


static const ber_sequence_t AttributesSyntax_sequence_of[1] = {
  { &hf_x509ce_AttributesSyntax_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_Attribute },
};

int
dissect_x509ce_AttributesSyntax(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      AttributesSyntax_sequence_of, hf_index, ett_x509ce_AttributesSyntax);

  return offset;
}



static int
dissect_x509ce_BOOLEAN(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_x509ce_INTEGER_0_MAX(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer64(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t BasicConstraintsSyntax_sequence[] = {
  { &hf_x509ce_cA           , BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509ce_BOOLEAN },
  { &hf_x509ce_pathLenConstraint, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509ce_INTEGER_0_MAX },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509ce_BasicConstraintsSyntax(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   BasicConstraintsSyntax_sequence, hf_index, ett_x509ce_BasicConstraintsSyntax);

  return offset;
}



int
dissect_x509ce_BaseDistance(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer64(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t GeneralSubtree_sequence[] = {
  { &hf_x509ce_base         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x509ce_GeneralName },
  { &hf_x509ce_minimum      , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_BaseDistance },
  { &hf_x509ce_maximum      , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_BaseDistance },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509ce_GeneralSubtree(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GeneralSubtree_sequence, hf_index, ett_x509ce_GeneralSubtree);

  return offset;
}


static const ber_sequence_t GeneralSubtrees_sequence_of[1] = {
  { &hf_x509ce_GeneralSubtrees_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509ce_GeneralSubtree },
};

int
dissect_x509ce_GeneralSubtrees(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      GeneralSubtrees_sequence_of, hf_index, ett_x509ce_GeneralSubtrees);

  return offset;
}


static const ber_sequence_t NameConstraintsSyntax_sequence[] = {
  { &hf_x509ce_permittedSubtrees, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_GeneralSubtrees },
  { &hf_x509ce_excludedSubtrees, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_GeneralSubtrees },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509ce_NameConstraintsSyntax(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NameConstraintsSyntax_sequence, hf_index, ett_x509ce_NameConstraintsSyntax);

  return offset;
}



int
dissect_x509ce_SkipCerts(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer64(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t PolicyConstraintsSyntax_sequence[] = {
  { &hf_x509ce_requireExplicitPolicy, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_SkipCerts },
  { &hf_x509ce_inhibitPolicyMapping, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_SkipCerts },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509ce_PolicyConstraintsSyntax(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PolicyConstraintsSyntax_sequence, hf_index, ett_x509ce_PolicyConstraintsSyntax);

  return offset;
}



int
dissect_x509ce_CRLNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer64(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
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
dissect_x509ce_CRLReason(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



int
dissect_x509ce_HoldInstruction(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


const value_string x509ce_DistributionPointName_vals[] = {
  {   0, "fullName" },
  {   1, "nameRelativeToCRLIssuer" },
  { 0, NULL }
};

static const ber_choice_t DistributionPointName_choice[] = {
  {   0, &hf_x509ce_fullName     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x509ce_GeneralNames },
  {   1, &hf_x509ce_nameRelativeToCRLIssuer, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_x509if_RelativeDistinguishedName },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_x509ce_DistributionPointName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 DistributionPointName_choice, hf_index, ett_x509ce_DistributionPointName,
                                 NULL);

  return offset;
}


static int * const OnlyCertificateTypes_bits[] = {
  &hf_x509ce_OnlyCertificateTypes_user,
  &hf_x509ce_OnlyCertificateTypes_authority,
  &hf_x509ce_OnlyCertificateTypes_attribute,
  NULL
};

int
dissect_x509ce_OnlyCertificateTypes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    OnlyCertificateTypes_bits, 3, hf_index, ett_x509ce_OnlyCertificateTypes,
                                    NULL);

  return offset;
}


static int * const ReasonFlags_bits[] = {
  &hf_x509ce_ReasonFlags_unused,
  &hf_x509ce_ReasonFlags_keyCompromise,
  &hf_x509ce_ReasonFlags_cACompromise,
  &hf_x509ce_ReasonFlags_affiliationChanged,
  &hf_x509ce_ReasonFlags_superseded,
  &hf_x509ce_ReasonFlags_cessationOfOperation,
  &hf_x509ce_ReasonFlags_certificateHold,
  &hf_x509ce_ReasonFlags_privilegeWithdrawn,
  &hf_x509ce_ReasonFlags_aACompromise,
  NULL
};

int
dissect_x509ce_ReasonFlags(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    ReasonFlags_bits, 9, hf_index, ett_x509ce_ReasonFlags,
                                    NULL);

  return offset;
}



static int
dissect_x509ce_INTEGER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t NumberRange_sequence[] = {
  { &hf_x509ce_startingNumber, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_INTEGER },
  { &hf_x509ce_endingNumber , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_INTEGER },
  { &hf_x509ce_modulus      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509ce_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509ce_NumberRange(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NumberRange_sequence, hf_index, ett_x509ce_NumberRange);

  return offset;
}



int
dissect_x509ce_CRLStreamIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer64(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t BaseRevocationInfo_sequence[] = {
  { &hf_x509ce_cRLStreamIdentifier, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_CRLStreamIdentifier },
  { &hf_x509ce_cRLNumber    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_x509ce_CRLNumber },
  { &hf_x509ce_baseThisUpdate, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_x509ce_GeneralizedTime },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509ce_BaseRevocationInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   BaseRevocationInfo_sequence, hf_index, ett_x509ce_BaseRevocationInfo);

  return offset;
}


static const ber_sequence_t PerAuthorityScope_sequence[] = {
  { &hf_x509ce_authorityName, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_x509ce_GeneralName },
  { &hf_x509ce_distributionPoint, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_x509ce_DistributionPointName },
  { &hf_x509ce_onlyContains , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_OnlyCertificateTypes },
  { &hf_x509ce_onlySomeReasons, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_ReasonFlags },
  { &hf_x509ce_serialNumberRange, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_NumberRange },
  { &hf_x509ce_subjectKeyIdRange, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_NumberRange },
  { &hf_x509ce_nameSubtrees , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_GeneralNames },
  { &hf_x509ce_baseRevocationInfo, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_BaseRevocationInfo },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509ce_PerAuthorityScope(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PerAuthorityScope_sequence, hf_index, ett_x509ce_PerAuthorityScope);

  return offset;
}


static const ber_sequence_t CRLScopeSyntax_sequence_of[1] = {
  { &hf_x509ce_CRLScopeSyntax_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509ce_PerAuthorityScope },
};

int
dissect_x509ce_CRLScopeSyntax(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      CRLScopeSyntax_sequence_of, hf_index, ett_x509ce_CRLScopeSyntax);

  return offset;
}


static const ber_sequence_t DeltaRefInfo_sequence[] = {
  { &hf_x509ce_deltaLocation, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x509ce_GeneralName },
  { &hf_x509ce_lastDelta    , BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509ce_GeneralizedTime },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509ce_DeltaRefInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DeltaRefInfo_sequence, hf_index, ett_x509ce_DeltaRefInfo);

  return offset;
}


static const ber_sequence_t CRLReferral_sequence[] = {
  { &hf_x509ce_crlr_issuer  , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_x509ce_GeneralName },
  { &hf_x509ce_location     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_x509ce_GeneralName },
  { &hf_x509ce_deltaRefInfo , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_DeltaRefInfo },
  { &hf_x509ce_cRLScope     , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509ce_CRLScopeSyntax },
  { &hf_x509ce_lastUpdate   , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_GeneralizedTime },
  { &hf_x509ce_lastChangedCRL, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_GeneralizedTime },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509ce_CRLReferral(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CRLReferral_sequence, hf_index, ett_x509ce_CRLReferral);

  return offset;
}


const value_string x509ce_StatusReferral_vals[] = {
  {   0, "cRLReferral" },
  { 0, NULL }
};

static const ber_choice_t StatusReferral_choice[] = {
  {   0, &hf_x509ce_cRLReferral  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x509ce_CRLReferral },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_x509ce_StatusReferral(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 StatusReferral_choice, hf_index, ett_x509ce_StatusReferral,
                                 NULL);

  return offset;
}


static const ber_sequence_t StatusReferrals_sequence_of[1] = {
  { &hf_x509ce_StatusReferrals_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x509ce_StatusReferral },
};

int
dissect_x509ce_StatusReferrals(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      StatusReferrals_sequence_of, hf_index, ett_x509ce_StatusReferrals);

  return offset;
}


const value_string x509ce_OrderedListSyntax_vals[] = {
  {   0, "ascSerialNum" },
  {   1, "ascRevDate" },
  { 0, NULL }
};


int
dissect_x509ce_OrderedListSyntax(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t DeltaInformation_sequence[] = {
  { &hf_x509ce_deltaLocation, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x509ce_GeneralName },
  { &hf_x509ce_nextDelta    , BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509ce_GeneralizedTime },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509ce_DeltaInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DeltaInformation_sequence, hf_index, ett_x509ce_DeltaInformation);

  return offset;
}


static const ber_sequence_t DistributionPoint_sequence[] = {
  { &hf_x509ce_distributionPoint, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_x509ce_DistributionPointName },
  { &hf_x509ce_reasons      , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_ReasonFlags },
  { &hf_x509ce_cRLIssuer    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_GeneralNames },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509ce_DistributionPoint(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DistributionPoint_sequence, hf_index, ett_x509ce_DistributionPoint);

  return offset;
}


static const ber_sequence_t CRLDistPointsSyntax_sequence_of[1] = {
  { &hf_x509ce_CRLDistPointsSyntax_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509ce_DistributionPoint },
};

int
dissect_x509ce_CRLDistPointsSyntax(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      CRLDistPointsSyntax_sequence_of, hf_index, ett_x509ce_CRLDistPointsSyntax);

  return offset;
}


static const ber_sequence_t IssuingDistPointSyntax_sequence[] = {
  { &hf_x509ce_distributionPoint, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_x509ce_DistributionPointName },
  { &hf_x509ce_onlyContainsUserPublicKeyCerts, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_BOOLEAN },
  { &hf_x509ce_onlyContainsCACerts, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_BOOLEAN },
  { &hf_x509ce_onlySomeReasons, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_ReasonFlags },
  { &hf_x509ce_indirectCRL  , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509ce_IssuingDistPointSyntax(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IssuingDistPointSyntax_sequence, hf_index, ett_x509ce_IssuingDistPointSyntax);

  return offset;
}



int
dissect_x509ce_BaseCRLNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509ce_CRLNumber(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t ReasonInfo_sequence[] = {
  { &hf_x509ce_reasonCode   , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_x509ce_CRLReason },
  { &hf_x509ce_holdInstructionCode, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509ce_HoldInstruction },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x509ce_ReasonInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReasonInfo_sequence, hf_index, ett_x509ce_ReasonInfo);

  return offset;
}


static const ber_sequence_t CertificateSerialNumbers_sequence_of[1] = {
  { &hf_x509ce_CertificateSerialNumbers_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_x509af_CertificateSerialNumber },
};

static int
dissect_x509ce_CertificateSerialNumbers(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      CertificateSerialNumbers_sequence_of, hf_index, ett_x509ce_CertificateSerialNumbers);

  return offset;
}


static const ber_sequence_t CertificateGroupNumberRange_sequence[] = {
  { &hf_x509ce_startingNumber, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x509ce_INTEGER },
  { &hf_x509ce_endingNumber , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_x509ce_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x509ce_CertificateGroupNumberRange(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CertificateGroupNumberRange_sequence, hf_index, ett_x509ce_CertificateGroupNumberRange);

  return offset;
}


static const value_string x509ce_CertificateGroup_vals[] = {
  {   0, "serialNumbers" },
  {   1, "serialNumberRange" },
  {   2, "nameSubtree" },
  { 0, NULL }
};

static const ber_choice_t CertificateGroup_choice[] = {
  {   0, &hf_x509ce_serialNumbers, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x509ce_CertificateSerialNumbers },
  {   1, &hf_x509ce_certificateGroupNumberRange, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_x509ce_CertificateGroupNumberRange },
  {   2, &hf_x509ce_nameSubtree  , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_x509ce_GeneralName },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x509ce_CertificateGroup(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CertificateGroup_choice, hf_index, ett_x509ce_CertificateGroup,
                                 NULL);

  return offset;
}


static const ber_sequence_t ToBeRevokedGroup_sequence[] = {
  { &hf_x509ce_certificateIssuer, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_x509ce_GeneralName },
  { &hf_x509ce_reasonInfo   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_ReasonInfo },
  { &hf_x509ce_revocationTime, BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_x509ce_GeneralizedTime },
  { &hf_x509ce_certificateGroup, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x509ce_CertificateGroup },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x509ce_ToBeRevokedGroup(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ToBeRevokedGroup_sequence, hf_index, ett_x509ce_ToBeRevokedGroup);

  return offset;
}


static const ber_sequence_t ToBeRevokedSyntax_sequence_of[1] = {
  { &hf_x509ce_ToBeRevokedSyntax_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509ce_ToBeRevokedGroup },
};

static int
dissect_x509ce_ToBeRevokedSyntax(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      ToBeRevokedSyntax_sequence_of, hf_index, ett_x509ce_ToBeRevokedSyntax);

  return offset;
}


static const value_string x509ce_RevokedCertificateGroup_vals[] = {
  {   0, "serialNumberRange" },
  {   1, "nameSubtree" },
  { 0, NULL }
};

static const ber_choice_t RevokedCertificateGroup_choice[] = {
  {   0, &hf_x509ce_serialNumberRange, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509ce_NumberRange },
  {   1, &hf_x509ce_nameSubtree  , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_x509ce_GeneralName },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x509ce_RevokedCertificateGroup(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RevokedCertificateGroup_choice, hf_index, ett_x509ce_RevokedCertificateGroup,
                                 NULL);

  return offset;
}


static const ber_sequence_t RevokedGroup_sequence[] = {
  { &hf_x509ce_certificateIssuer, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_x509ce_GeneralName },
  { &hf_x509ce_reasonInfo   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_ReasonInfo },
  { &hf_x509ce_invalidityDate, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_GeneralizedTime },
  { &hf_x509ce_revokedcertificateGroup, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_x509ce_RevokedCertificateGroup },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x509ce_RevokedGroup(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RevokedGroup_sequence, hf_index, ett_x509ce_RevokedGroup);

  return offset;
}


static const ber_sequence_t RevokedGroupsSyntax_sequence_of[1] = {
  { &hf_x509ce_RevokedGroupsSyntax_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509ce_RevokedGroup },
};

static int
dissect_x509ce_RevokedGroupsSyntax(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      RevokedGroupsSyntax_sequence_of, hf_index, ett_x509ce_RevokedGroupsSyntax);

  return offset;
}



static int
dissect_x509ce_ExpiredCertsOnCRL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t AAIssuingDistPointSyntax_sequence[] = {
  { &hf_x509ce_distributionPoint, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_x509ce_DistributionPointName },
  { &hf_x509ce_onlySomeReasons, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_ReasonFlags },
  { &hf_x509ce_indirectCRL  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_BOOLEAN },
  { &hf_x509ce_containsUserAttributeCerts, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_BOOLEAN },
  { &hf_x509ce_containsAACerts, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_BOOLEAN },
  { &hf_x509ce_containsSOAPublicKeyCerts, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x509ce_AAIssuingDistPointSyntax(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AAIssuingDistPointSyntax_sequence, hf_index, ett_x509ce_AAIssuingDistPointSyntax);

  return offset;
}


static const ber_sequence_t CertificateExactAssertion_sequence[] = {
  { &hf_x509ce_serialNumber , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_x509af_CertificateSerialNumber },
  { &hf_x509ce_issuer       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_x509if_Name },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509ce_CertificateExactAssertion(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CertificateExactAssertion_sequence, hf_index, ett_x509ce_CertificateExactAssertion);

  return offset;
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
dissect_x509ce_T_builtinNameForm(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


const value_string x509ce_AltNameType_vals[] = {
  {   0, "builtinNameForm" },
  {   1, "otherNameForm" },
  { 0, NULL }
};

static const ber_choice_t AltNameType_choice[] = {
  {   0, &hf_x509ce_builtinNameForm, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_x509ce_T_builtinNameForm },
  {   1, &hf_x509ce_otherNameForm, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509ce_OBJECT_IDENTIFIER },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_x509ce_AltNameType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 AltNameType_choice, hf_index, ett_x509ce_AltNameType,
                                 NULL);

  return offset;
}


static const ber_sequence_t CertPolicySet_sequence_of[1] = {
  { &hf_x509ce_CertPolicySet_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509ce_CertPolicyId },
};

int
dissect_x509ce_CertPolicySet(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      CertPolicySet_sequence_of, hf_index, ett_x509ce_CertPolicySet);

  return offset;
}


static const ber_sequence_t CertificateAssertion_sequence[] = {
  { &hf_x509ce_serialNumber , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509af_CertificateSerialNumber },
  { &hf_x509ce_issuer       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509if_Name },
  { &hf_x509ce_subjectKeyIdentifier, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_SubjectKeyIdentifier },
  { &hf_x509ce_authorityKeyIdentifier, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_AuthorityKeyIdentifier },
  { &hf_x509ce_certificateValid, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509af_Time },
  { &hf_x509ce_privateKeyValid, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_GeneralizedTime },
  { &hf_x509ce_subjectPublicKeyAlgID, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_OBJECT_IDENTIFIER },
  { &hf_x509ce_keyUsage     , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_KeyUsage },
  { &hf_x509ce_subjectAltNameType, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_x509ce_AltNameType },
  { &hf_x509ce_policy       , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_CertPolicySet },
  { &hf_x509ce_pathToName   , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509if_Name },
  { &hf_x509ce_subject      , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509if_Name },
  { &hf_x509ce_nameConstraints, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_NameConstraintsSyntax },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509ce_CertificateAssertion(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CertificateAssertion_sequence, hf_index, ett_x509ce_CertificateAssertion);

  return offset;
}


static const ber_sequence_t CertificatePairExactAssertion_sequence[] = {
  { &hf_x509ce_cpea_issuedToThisCAAssertion, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_CertificateExactAssertion },
  { &hf_x509ce_cpea_issuedByThisCAAssertion, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_CertificateExactAssertion },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509ce_CertificatePairExactAssertion(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CertificatePairExactAssertion_sequence, hf_index, ett_x509ce_CertificatePairExactAssertion);

  return offset;
}


static const ber_sequence_t CertificatePairAssertion_sequence[] = {
  { &hf_x509ce_issuedToThisCAAssertion, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_CertificateAssertion },
  { &hf_x509ce_issuedByThisCAAssertion, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_CertificateAssertion },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509ce_CertificatePairAssertion(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CertificatePairAssertion_sequence, hf_index, ett_x509ce_CertificatePairAssertion);

  return offset;
}


static const ber_sequence_t CertificateListExactAssertion_sequence[] = {
  { &hf_x509ce_issuer       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_x509if_Name },
  { &hf_x509ce_thisUpdate   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_x509af_Time },
  { &hf_x509ce_distributionPoint, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x509ce_DistributionPointName },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509ce_CertificateListExactAssertion(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CertificateListExactAssertion_sequence, hf_index, ett_x509ce_CertificateListExactAssertion);

  return offset;
}


static const ber_sequence_t CertificateListAssertion_sequence[] = {
  { &hf_x509ce_issuer       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509if_Name },
  { &hf_x509ce_minCRLNumber , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_CRLNumber },
  { &hf_x509ce_maxCRLNumber , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_CRLNumber },
  { &hf_x509ce_reasonFlags  , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509ce_ReasonFlags },
  { &hf_x509ce_dateAndTime  , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509af_Time },
  { &hf_x509ce_distributionPoint, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_x509ce_DistributionPointName },
  { &hf_x509ce_authorityKeyIdentifier, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_AuthorityKeyIdentifier },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509ce_CertificateListAssertion(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CertificateListAssertion_sequence, hf_index, ett_x509ce_CertificateListAssertion);

  return offset;
}


static const ber_sequence_t PkiPathMatchSyntax_sequence[] = {
  { &hf_x509ce_firstIssuer  , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_x509if_Name },
  { &hf_x509ce_lastSubject  , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_x509if_Name },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509ce_PkiPathMatchSyntax(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PkiPathMatchSyntax_sequence, hf_index, ett_x509ce_PkiPathMatchSyntax);

  return offset;
}


static const ber_sequence_t AltName_sequence[] = {
  { &hf_x509ce_altnameType  , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x509ce_AltNameType },
  { &hf_x509ce_altNameValue , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x509ce_GeneralName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x509ce_AltName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AltName_sequence, hf_index, ett_x509ce_AltName);

  return offset;
}


static const ber_sequence_t EnhancedCertificateAssertion_sequence[] = {
  { &hf_x509ce_serialNumber , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509af_CertificateSerialNumber },
  { &hf_x509ce_issuer       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509if_Name },
  { &hf_x509ce_subjectKeyIdentifier, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_SubjectKeyIdentifier },
  { &hf_x509ce_authorityKeyIdentifier, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_AuthorityKeyIdentifier },
  { &hf_x509ce_certificateValid, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509af_Time },
  { &hf_x509ce_privateKeyValid, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_GeneralizedTime },
  { &hf_x509ce_subjectPublicKeyAlgID, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_OBJECT_IDENTIFIER },
  { &hf_x509ce_keyUsage     , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_KeyUsage },
  { &hf_x509ce_subjectAltName, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_AltName },
  { &hf_x509ce_policy       , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_CertPolicySet },
  { &hf_x509ce_enhancedPathToName, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_GeneralNames },
  { &hf_x509ce_subject      , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509if_Name },
  { &hf_x509ce_nameConstraints, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_x509ce_NameConstraintsSyntax },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x509ce_EnhancedCertificateAssertion(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EnhancedCertificateAssertion_sequence, hf_index, ett_x509ce_EnhancedCertificateAssertion);

  return offset;
}


static const ber_sequence_t CertificateTemplate_sequence[] = {
  { &hf_x509ce_templateID   , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509ce_OBJECT_IDENTIFIER },
  { &hf_x509ce_templateMajorVersion, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_x509ce_INTEGER },
  { &hf_x509ce_templateMinorVersion, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509ce_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x509ce_CertificateTemplate(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CertificateTemplate_sequence, hf_index, ett_x509ce_CertificateTemplate);

  return offset;
}



static int
dissect_x509ce_PrintableString(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t NtdsObjectSid_U_sequence[] = {
  { &hf_x509ce_type_id_01   , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509ce_OBJECT_IDENTIFIER },
  { &hf_x509ce_sid          , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x509ce_PrintableString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x509ce_NtdsObjectSid_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NtdsObjectSid_U_sequence, hf_index, ett_x509ce_NtdsObjectSid_U);

  return offset;
}



static int
dissect_x509ce_NtdsObjectSid(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 0, true, dissect_x509ce_NtdsObjectSid_U);

  return offset;
}


static const ber_sequence_t NtdsCaSecurity_sequence[] = {
  { &hf_x509ce_ntdsObjectSid, BER_CLASS_CON, 0, BER_FLAGS_NOOWNTAG, dissect_x509ce_NtdsObjectSid },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x509ce_NtdsCaSecurity(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NtdsCaSecurity_sequence, hf_index, ett_x509ce_NtdsCaSecurity);

  return offset;
}



static int
dissect_x509ce_GeneralString(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GeneralString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static int * const EntrustInfoFlags_bits[] = {
  &hf_x509ce_EntrustInfoFlags_keyUpdateAllowed,
  &hf_x509ce_EntrustInfoFlags_newExtensions,
  &hf_x509ce_EntrustInfoFlags_pKIXCertificate,
  &hf_x509ce_EntrustInfoFlags_enterpriseCategory,
  &hf_x509ce_EntrustInfoFlags_webCategory,
  &hf_x509ce_EntrustInfoFlags_sETCategory,
  NULL
};

static int
dissect_x509ce_EntrustInfoFlags(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    EntrustInfoFlags_bits, 6, hf_index, ett_x509ce_EntrustInfoFlags,
                                    NULL);

  return offset;
}


static const ber_sequence_t EntrustVersionInfo_sequence[] = {
  { &hf_x509ce_entrustVers  , BER_CLASS_UNI, BER_UNI_TAG_GeneralString, BER_FLAGS_NOOWNTAG, dissect_x509ce_GeneralString },
  { &hf_x509ce_entrustVersInfoFlags, BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509ce_EntrustInfoFlags },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x509ce_EntrustVersionInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EntrustVersionInfo_sequence, hf_index, ett_x509ce_EntrustVersionInfo);

  return offset;
}



static int
dissect_x509ce_NFType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t NFTypes_sequence_of[1] = {
  { &hf_x509ce_NFTypes_item , BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_NOOWNTAG, dissect_x509ce_NFType },
};

static int
dissect_x509ce_NFTypes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      NFTypes_sequence_of, hf_index, ett_x509ce_NFTypes);

  return offset;
}


static const ber_sequence_t ScramblerCapabilities_sequence[] = {
  { &hf_x509ce_capability   , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_x509ce_INTEGER_0_MAX },
  { &hf_x509ce_version      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_x509ce_INTEGER_0_MAX },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509ce_ScramblerCapabilities(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ScramblerCapabilities_sequence, hf_index, ett_x509ce_ScramblerCapabilities);

  return offset;
}



int
dissect_x509ce_CiplusInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
                                    NULL);

  return offset;
}



int
dissect_x509ce_CicamBrandId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



int
dissect_x509ce_SecurityLevel(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer64(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_AuthorityKeyIdentifier_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_AuthorityKeyIdentifier(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_AuthorityKeyIdentifier_PDU);
  return offset;
}
static int dissect_SubjectKeyIdentifier_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_SubjectKeyIdentifier(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_SubjectKeyIdentifier_PDU);
  return offset;
}
static int dissect_KeyUsage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_KeyUsage(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_KeyUsage_PDU);
  return offset;
}
static int dissect_KeyPurposeIDs_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_KeyPurposeIDs(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_KeyPurposeIDs_PDU);
  return offset;
}
static int dissect_PrivateKeyUsagePeriod_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_PrivateKeyUsagePeriod(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_PrivateKeyUsagePeriod_PDU);
  return offset;
}
static int dissect_CertificatePoliciesSyntax_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_CertificatePoliciesSyntax(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_CertificatePoliciesSyntax_PDU);
  return offset;
}
static int dissect_PolicyMappingsSyntax_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_PolicyMappingsSyntax(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_PolicyMappingsSyntax_PDU);
  return offset;
}
static int dissect_GeneralNames_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_GeneralNames(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_GeneralNames_PDU);
  return offset;
}
static int dissect_AttributesSyntax_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_AttributesSyntax(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_AttributesSyntax_PDU);
  return offset;
}
static int dissect_BasicConstraintsSyntax_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_BasicConstraintsSyntax(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_BasicConstraintsSyntax_PDU);
  return offset;
}
static int dissect_NameConstraintsSyntax_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_NameConstraintsSyntax(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_NameConstraintsSyntax_PDU);
  return offset;
}
static int dissect_PolicyConstraintsSyntax_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_PolicyConstraintsSyntax(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_PolicyConstraintsSyntax_PDU);
  return offset;
}
static int dissect_SkipCerts_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_SkipCerts(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_SkipCerts_PDU);
  return offset;
}
static int dissect_CRLNumber_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_CRLNumber(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_CRLNumber_PDU);
  return offset;
}
static int dissect_CRLReason_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_CRLReason(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_CRLReason_PDU);
  return offset;
}
static int dissect_HoldInstruction_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_HoldInstruction(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_HoldInstruction_PDU);
  return offset;
}
static int dissect_CRLScopeSyntax_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_CRLScopeSyntax(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_CRLScopeSyntax_PDU);
  return offset;
}
static int dissect_StatusReferrals_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_StatusReferrals(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_StatusReferrals_PDU);
  return offset;
}
static int dissect_CRLStreamIdentifier_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_CRLStreamIdentifier(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_CRLStreamIdentifier_PDU);
  return offset;
}
static int dissect_OrderedListSyntax_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_OrderedListSyntax(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_OrderedListSyntax_PDU);
  return offset;
}
static int dissect_DeltaInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_DeltaInformation(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_DeltaInformation_PDU);
  return offset;
}
static int dissect_CRLDistPointsSyntax_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_CRLDistPointsSyntax(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_CRLDistPointsSyntax_PDU);
  return offset;
}
static int dissect_IssuingDistPointSyntax_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_IssuingDistPointSyntax(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_IssuingDistPointSyntax_PDU);
  return offset;
}
static int dissect_BaseCRLNumber_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_BaseCRLNumber(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_BaseCRLNumber_PDU);
  return offset;
}
static int dissect_ToBeRevokedSyntax_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_ToBeRevokedSyntax(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_ToBeRevokedSyntax_PDU);
  return offset;
}
static int dissect_RevokedGroupsSyntax_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_RevokedGroupsSyntax(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_RevokedGroupsSyntax_PDU);
  return offset;
}
static int dissect_ExpiredCertsOnCRL_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_ExpiredCertsOnCRL(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_ExpiredCertsOnCRL_PDU);
  return offset;
}
static int dissect_AAIssuingDistPointSyntax_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_AAIssuingDistPointSyntax(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_AAIssuingDistPointSyntax_PDU);
  return offset;
}
static int dissect_CertificateAssertion_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_CertificateAssertion(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_CertificateAssertion_PDU);
  return offset;
}
static int dissect_CertificatePairExactAssertion_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_CertificatePairExactAssertion(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_CertificatePairExactAssertion_PDU);
  return offset;
}
static int dissect_CertificatePairAssertion_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_CertificatePairAssertion(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_CertificatePairAssertion_PDU);
  return offset;
}
static int dissect_CertificateListExactAssertion_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_CertificateListExactAssertion(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_CertificateListExactAssertion_PDU);
  return offset;
}
static int dissect_CertificateListAssertion_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_CertificateListAssertion(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_CertificateListAssertion_PDU);
  return offset;
}
static int dissect_PkiPathMatchSyntax_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_PkiPathMatchSyntax(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_PkiPathMatchSyntax_PDU);
  return offset;
}
static int dissect_EnhancedCertificateAssertion_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_EnhancedCertificateAssertion(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_EnhancedCertificateAssertion_PDU);
  return offset;
}
static int dissect_CertificateTemplate_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_CertificateTemplate(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_CertificateTemplate_PDU);
  return offset;
}
static int dissect_NtdsCaSecurity_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_NtdsCaSecurity(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_NtdsCaSecurity_PDU);
  return offset;
}
static int dissect_NtdsObjectSid_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_NtdsObjectSid(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_NtdsObjectSid_PDU);
  return offset;
}
static int dissect_EntrustVersionInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_EntrustVersionInfo(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_EntrustVersionInfo_PDU);
  return offset;
}
static int dissect_NFTypes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_NFTypes(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_NFTypes_PDU);
  return offset;
}
static int dissect_ScramblerCapabilities_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_ScramblerCapabilities(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_ScramblerCapabilities_PDU);
  return offset;
}
static int dissect_CiplusInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_CiplusInfo(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_CiplusInfo_PDU);
  return offset;
}
static int dissect_CicamBrandId_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_CicamBrandId(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_CicamBrandId_PDU);
  return offset;
}
static int dissect_SecurityLevel_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_x509ce_SecurityLevel(false, tvb, offset, &asn1_ctx, tree, hf_x509ce_SecurityLevel_PDU);
  return offset;
}


static const val64_string ciplus_scr_cap[] = {
    { 0, "DES" },
    { 1, "DES and AES" },
    { 0, NULL }
};

static const val64_string ciplus_security_level[] = {
    { 0, "Standard Security Level" },
    { 1, "ECP Security Level" },
    { 0, NULL }
};

/* CI+ (www.ci-plus.com) defines some X.509 certificate extensions
   that use OIDs which are not officially assigned
   dissection of these extensions can be enabled temporarily using the
   functions below */
void
x509ce_enable_ciplus(void)
{
  dissector_handle_t dh25, dh26, dh27, dh50;

  dh25 = create_dissector_handle(dissect_ScramblerCapabilities_PDU, proto_x509ce);
  dissector_change_string("ber.oid", "1.3.6.1.5.5.7.1.25", dh25);
  dh26 = create_dissector_handle(dissect_CiplusInfo_PDU, proto_x509ce);
  dissector_change_string("ber.oid", "1.3.6.1.5.5.7.1.26", dh26);
  dh27 = create_dissector_handle(dissect_CicamBrandId_PDU, proto_x509ce);
  dissector_change_string("ber.oid", "1.3.6.1.5.5.7.1.27", dh27);
  dh50 = create_dissector_handle(dissect_SecurityLevel_PDU, proto_x509ce);
  dissector_change_string("ber.oid", "1.3.6.1.5.5.7.1.50", dh50);
}

void
x509ce_disable_ciplus(void)
{
  dissector_reset_string("ber.oid", "1.3.6.1.5.5.7.1.25");
  dissector_reset_string("ber.oid", "1.3.6.1.5.5.7.1.26");
  dissector_reset_string("ber.oid", "1.3.6.1.5.5.7.1.27");
  dissector_reset_string("ber.oid", "1.3.6.1.5.5.7.1.50");
}


static int
dissect_x509ce_invalidityDate_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

  return dissect_x509ce_GeneralizedTime(false, tvb, 0, &asn1_ctx, tree, hf_x509ce_id_ce_invalidityDate);
}

static int
dissect_x509ce_baseUpdateTime_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  return dissect_x509ce_GeneralizedTime(false, tvb, 0, &asn1_ctx, tree, hf_x509ce_id_ce_baseUpdateTime);
}

/*--- proto_register_x509ce ----------------------------------------------*/
void proto_register_x509ce(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_x509ce_id_ce_baseUpdateTime,
      { "baseUpdateTime", "x509ce.id_ce_baseUpdateTime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_id_ce_invalidityDate,
      { "invalidityDate", "x509ce.id_ce_invalidityDate",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_object_identifier_id,
      { "Id", "x509ce.id", FT_OID, BASE_NONE, NULL, 0,
        "Object identifier Id", HFILL }},
    { &hf_x509ce_IPAddress_ipv4,
      { "iPAddress", "x509ce.IPAddress.ipv4", FT_IPv4, BASE_NONE, NULL, 0,
        "IPv4 address", HFILL }},
    { &hf_x509ce_IPAddress_ipv4_mask,
      { "iPAddress Mask", "x509ce.IPAddress.ipv4_mask", FT_IPv4, BASE_NONE, NULL, 0,
        "IPv4 address Mask", HFILL }},
    { &hf_x509ce_IPAddress_ipv6,
      { "iPAddress", "x509ce.IPAddress.ipv6", FT_IPv6, BASE_NONE, NULL, 0,
        "IPv6 address", HFILL }},
    { &hf_x509ce_IPAddress_ipv6_mask,
      { "iPAddress Mask", "x509ce.IPAddress.ipv6_mask", FT_IPv6, BASE_NONE, NULL, 0,
        "IPv6 address Mask", HFILL }},
    { &hf_x509ce_IPAddress_unknown,
      { "iPAddress", "x509ce.IPAddress.unknown", FT_BYTES, BASE_NONE, NULL, 0,
        "Unknown Address", HFILL }},

    { &hf_x509ce_AuthorityKeyIdentifier_PDU,
      { "AuthorityKeyIdentifier", "x509ce.AuthorityKeyIdentifier_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_SubjectKeyIdentifier_PDU,
      { "SubjectKeyIdentifier", "x509ce.SubjectKeyIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_KeyUsage_PDU,
      { "KeyUsage", "x509ce.KeyUsage",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_KeyPurposeIDs_PDU,
      { "KeyPurposeIDs", "x509ce.KeyPurposeIDs",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_PrivateKeyUsagePeriod_PDU,
      { "PrivateKeyUsagePeriod", "x509ce.PrivateKeyUsagePeriod_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_CertificatePoliciesSyntax_PDU,
      { "CertificatePoliciesSyntax", "x509ce.CertificatePoliciesSyntax",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_PolicyMappingsSyntax_PDU,
      { "PolicyMappingsSyntax", "x509ce.PolicyMappingsSyntax",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_GeneralNames_PDU,
      { "GeneralNames", "x509ce.GeneralNames",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_AttributesSyntax_PDU,
      { "AttributesSyntax", "x509ce.AttributesSyntax",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_BasicConstraintsSyntax_PDU,
      { "BasicConstraintsSyntax", "x509ce.BasicConstraintsSyntax_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_NameConstraintsSyntax_PDU,
      { "NameConstraintsSyntax", "x509ce.NameConstraintsSyntax_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_PolicyConstraintsSyntax_PDU,
      { "PolicyConstraintsSyntax", "x509ce.PolicyConstraintsSyntax_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_SkipCerts_PDU,
      { "SkipCerts", "x509ce.SkipCerts",
        FT_UINT64, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_CRLNumber_PDU,
      { "CRLNumber", "x509ce.CRLNumber",
        FT_UINT64, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_CRLReason_PDU,
      { "CRLReason", "x509ce.CRLReason",
        FT_UINT32, BASE_DEC, VALS(x509ce_CRLReason_vals), 0,
        NULL, HFILL }},
    { &hf_x509ce_HoldInstruction_PDU,
      { "HoldInstruction", "x509ce.HoldInstruction",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_CRLScopeSyntax_PDU,
      { "CRLScopeSyntax", "x509ce.CRLScopeSyntax",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_StatusReferrals_PDU,
      { "StatusReferrals", "x509ce.StatusReferrals",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_CRLStreamIdentifier_PDU,
      { "CRLStreamIdentifier", "x509ce.CRLStreamIdentifier",
        FT_UINT64, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_OrderedListSyntax_PDU,
      { "OrderedListSyntax", "x509ce.OrderedListSyntax",
        FT_UINT32, BASE_DEC, VALS(x509ce_OrderedListSyntax_vals), 0,
        NULL, HFILL }},
    { &hf_x509ce_DeltaInformation_PDU,
      { "DeltaInformation", "x509ce.DeltaInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_CRLDistPointsSyntax_PDU,
      { "CRLDistPointsSyntax", "x509ce.CRLDistPointsSyntax",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_IssuingDistPointSyntax_PDU,
      { "IssuingDistPointSyntax", "x509ce.IssuingDistPointSyntax_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_BaseCRLNumber_PDU,
      { "BaseCRLNumber", "x509ce.BaseCRLNumber",
        FT_UINT64, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_ToBeRevokedSyntax_PDU,
      { "ToBeRevokedSyntax", "x509ce.ToBeRevokedSyntax",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_RevokedGroupsSyntax_PDU,
      { "RevokedGroupsSyntax", "x509ce.RevokedGroupsSyntax",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_ExpiredCertsOnCRL_PDU,
      { "ExpiredCertsOnCRL", "x509ce.ExpiredCertsOnCRL",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_AAIssuingDistPointSyntax_PDU,
      { "AAIssuingDistPointSyntax", "x509ce.AAIssuingDistPointSyntax_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_CertificateAssertion_PDU,
      { "CertificateAssertion", "x509ce.CertificateAssertion_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_CertificatePairExactAssertion_PDU,
      { "CertificatePairExactAssertion", "x509ce.CertificatePairExactAssertion_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_CertificatePairAssertion_PDU,
      { "CertificatePairAssertion", "x509ce.CertificatePairAssertion_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_CertificateListExactAssertion_PDU,
      { "CertificateListExactAssertion", "x509ce.CertificateListExactAssertion_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_CertificateListAssertion_PDU,
      { "CertificateListAssertion", "x509ce.CertificateListAssertion_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_PkiPathMatchSyntax_PDU,
      { "PkiPathMatchSyntax", "x509ce.PkiPathMatchSyntax_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_EnhancedCertificateAssertion_PDU,
      { "EnhancedCertificateAssertion", "x509ce.EnhancedCertificateAssertion_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_CertificateTemplate_PDU,
      { "CertificateTemplate", "x509ce.CertificateTemplate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_NtdsCaSecurity_PDU,
      { "NtdsCaSecurity", "x509ce.NtdsCaSecurity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_NtdsObjectSid_PDU,
      { "NtdsObjectSid", "x509ce.NtdsObjectSid_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_EntrustVersionInfo_PDU,
      { "EntrustVersionInfo", "x509ce.EntrustVersionInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_NFTypes_PDU,
      { "NFTypes", "x509ce.NFTypes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_ScramblerCapabilities_PDU,
      { "ScramblerCapabilities", "x509ce.ScramblerCapabilities_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_CiplusInfo_PDU,
      { "CiplusInfo", "x509ce.CiplusInfo",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_CicamBrandId_PDU,
      { "CicamBrandId", "x509ce.CicamBrandId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_SecurityLevel_PDU,
      { "SecurityLevel", "x509ce.SecurityLevel",
        FT_UINT64, BASE_DEC|BASE_VAL64_STRING, VALS64(ciplus_security_level), 0,
        NULL, HFILL }},
    { &hf_x509ce_keyIdentifier,
      { "keyIdentifier", "x509ce.keyIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_authorityCertIssuer,
      { "authorityCertIssuer", "x509ce.authorityCertIssuer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GeneralNames", HFILL }},
    { &hf_x509ce_authorityCertSerialNumber,
      { "authorityCertSerialNumber", "x509ce.authorityCertSerialNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        "CertificateSerialNumber", HFILL }},
    { &hf_x509ce_KeyPurposeIDs_item,
      { "KeyPurposeId", "x509ce.KeyPurposeId",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_notBefore,
      { "notBefore", "x509ce.notBefore",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_x509ce_notAfter,
      { "notAfter", "x509ce.notAfter",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_x509ce_CertificatePoliciesSyntax_item,
      { "PolicyInformation", "x509ce.PolicyInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_policyIdentifier,
      { "policyIdentifier", "x509ce.policyIdentifier",
        FT_OID, BASE_NONE, NULL, 0,
        "CertPolicyId", HFILL }},
    { &hf_x509ce_policyQualifiers,
      { "policyQualifiers", "x509ce.policyQualifiers",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_MAX_OF_PolicyQualifierInfo", HFILL }},
    { &hf_x509ce_policyQualifiers_item,
      { "PolicyQualifierInfo", "x509ce.PolicyQualifierInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_policyQualifierId,
      { "policyQualifierId", "x509ce.policyQualifierId",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_qualifier,
      { "qualifier", "x509ce.qualifier_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_PolicyMappingsSyntax_item,
      { "PolicyMappingsSyntax item", "x509ce.PolicyMappingsSyntax_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_issuerDomainPolicy,
      { "issuerDomainPolicy", "x509ce.issuerDomainPolicy",
        FT_OID, BASE_NONE, NULL, 0,
        "CertPolicyId", HFILL }},
    { &hf_x509ce_subjectDomainPolicy,
      { "subjectDomainPolicy", "x509ce.subjectDomainPolicy",
        FT_OID, BASE_NONE, NULL, 0,
        "CertPolicyId", HFILL }},
    { &hf_x509ce_GeneralNames_item,
      { "GeneralName", "x509ce.GeneralName",
        FT_UINT32, BASE_DEC, VALS(x509ce_GeneralName_vals), 0,
        NULL, HFILL }},
    { &hf_x509ce_otherName,
      { "otherName", "x509ce.otherName_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_rfc822Name,
      { "rfc822Name", "x509ce.rfc822Name",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String", HFILL }},
    { &hf_x509ce_dNSName,
      { "dNSName", "x509ce.dNSName",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String", HFILL }},
    { &hf_x509ce_x400Address,
      { "x400Address", "x509ce.x400Address_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ORAddress", HFILL }},
    { &hf_x509ce_directoryName,
      { "directoryName", "x509ce.directoryName",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "Name", HFILL }},
    { &hf_x509ce_ediPartyName,
      { "ediPartyName", "x509ce.ediPartyName_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_uniformResourceIdentifier,
      { "uniformResourceIdentifier", "x509ce.uniformResourceIdentifier",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_iPAddress,
      { "iPAddress", "x509ce.iPAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_registeredID,
      { "registeredID", "x509ce.registeredID",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_x509ce_type_id,
      { "type-id", "x509ce.type_id",
        FT_OID, BASE_NONE, NULL, 0,
        "OtherNameType", HFILL }},
    { &hf_x509ce_value,
      { "value", "x509ce.value_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "OtherNameValue", HFILL }},
    { &hf_x509ce_nameAssigner,
      { "nameAssigner", "x509ce.nameAssigner",
        FT_UINT32, BASE_DEC, VALS(x509sat_DirectoryString_vals), 0,
        "DirectoryString", HFILL }},
    { &hf_x509ce_partyName,
      { "partyName", "x509ce.partyName",
        FT_UINT32, BASE_DEC, VALS(x509sat_DirectoryString_vals), 0,
        "DirectoryString", HFILL }},
    { &hf_x509ce_AttributesSyntax_item,
      { "Attribute", "x509ce.Attribute_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_cA,
      { "cA", "x509ce.cA",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_x509ce_pathLenConstraint,
      { "pathLenConstraint", "x509ce.pathLenConstraint",
        FT_UINT64, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_x509ce_permittedSubtrees,
      { "permittedSubtrees", "x509ce.permittedSubtrees",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GeneralSubtrees", HFILL }},
    { &hf_x509ce_excludedSubtrees,
      { "excludedSubtrees", "x509ce.excludedSubtrees",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GeneralSubtrees", HFILL }},
    { &hf_x509ce_GeneralSubtrees_item,
      { "GeneralSubtree", "x509ce.GeneralSubtree_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_base,
      { "base", "x509ce.base",
        FT_UINT32, BASE_DEC, VALS(x509ce_GeneralName_vals), 0,
        "GeneralName", HFILL }},
    { &hf_x509ce_minimum,
      { "minimum", "x509ce.minimum",
        FT_UINT64, BASE_DEC, NULL, 0,
        "BaseDistance", HFILL }},
    { &hf_x509ce_maximum,
      { "maximum", "x509ce.maximum",
        FT_UINT64, BASE_DEC, NULL, 0,
        "BaseDistance", HFILL }},
    { &hf_x509ce_requireExplicitPolicy,
      { "requireExplicitPolicy", "x509ce.requireExplicitPolicy",
        FT_UINT64, BASE_DEC, NULL, 0,
        "SkipCerts", HFILL }},
    { &hf_x509ce_inhibitPolicyMapping,
      { "inhibitPolicyMapping", "x509ce.inhibitPolicyMapping",
        FT_UINT64, BASE_DEC, NULL, 0,
        "SkipCerts", HFILL }},
    { &hf_x509ce_CRLScopeSyntax_item,
      { "PerAuthorityScope", "x509ce.PerAuthorityScope_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_authorityName,
      { "authorityName", "x509ce.authorityName",
        FT_UINT32, BASE_DEC, VALS(x509ce_GeneralName_vals), 0,
        "GeneralName", HFILL }},
    { &hf_x509ce_distributionPoint,
      { "distributionPoint", "x509ce.distributionPoint",
        FT_UINT32, BASE_DEC, VALS(x509ce_DistributionPointName_vals), 0,
        "DistributionPointName", HFILL }},
    { &hf_x509ce_onlyContains,
      { "onlyContains", "x509ce.onlyContains",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OnlyCertificateTypes", HFILL }},
    { &hf_x509ce_onlySomeReasons,
      { "onlySomeReasons", "x509ce.onlySomeReasons",
        FT_BYTES, BASE_NONE, NULL, 0,
        "ReasonFlags", HFILL }},
    { &hf_x509ce_serialNumberRange,
      { "serialNumberRange", "x509ce.serialNumberRange_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NumberRange", HFILL }},
    { &hf_x509ce_subjectKeyIdRange,
      { "subjectKeyIdRange", "x509ce.subjectKeyIdRange_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NumberRange", HFILL }},
    { &hf_x509ce_nameSubtrees,
      { "nameSubtrees", "x509ce.nameSubtrees",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GeneralNames", HFILL }},
    { &hf_x509ce_baseRevocationInfo,
      { "baseRevocationInfo", "x509ce.baseRevocationInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_startingNumber,
      { "startingNumber", "x509ce.startingNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_x509ce_endingNumber,
      { "endingNumber", "x509ce.endingNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_x509ce_modulus,
      { "modulus", "x509ce.modulus",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_x509ce_cRLStreamIdentifier,
      { "cRLStreamIdentifier", "x509ce.cRLStreamIdentifier",
        FT_UINT64, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_cRLNumber,
      { "cRLNumber", "x509ce.cRLNumber",
        FT_UINT64, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_baseThisUpdate,
      { "baseThisUpdate", "x509ce.baseThisUpdate",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_x509ce_StatusReferrals_item,
      { "StatusReferral", "x509ce.StatusReferral",
        FT_UINT32, BASE_DEC, VALS(x509ce_StatusReferral_vals), 0,
        NULL, HFILL }},
    { &hf_x509ce_cRLReferral,
      { "cRLReferral", "x509ce.cRLReferral_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_crlr_issuer,
      { "issuer", "x509ce.issuer",
        FT_UINT32, BASE_DEC, VALS(x509ce_GeneralName_vals), 0,
        "GeneralName", HFILL }},
    { &hf_x509ce_location,
      { "location", "x509ce.location",
        FT_UINT32, BASE_DEC, VALS(x509ce_GeneralName_vals), 0,
        "GeneralName", HFILL }},
    { &hf_x509ce_deltaRefInfo,
      { "deltaRefInfo", "x509ce.deltaRefInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_cRLScope,
      { "cRLScope", "x509ce.cRLScope",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CRLScopeSyntax", HFILL }},
    { &hf_x509ce_lastUpdate,
      { "lastUpdate", "x509ce.lastUpdate",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_x509ce_lastChangedCRL,
      { "lastChangedCRL", "x509ce.lastChangedCRL",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_x509ce_deltaLocation,
      { "deltaLocation", "x509ce.deltaLocation",
        FT_UINT32, BASE_DEC, VALS(x509ce_GeneralName_vals), 0,
        "GeneralName", HFILL }},
    { &hf_x509ce_lastDelta,
      { "lastDelta", "x509ce.lastDelta",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_x509ce_nextDelta,
      { "nextDelta", "x509ce.nextDelta",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_x509ce_CRLDistPointsSyntax_item,
      { "DistributionPoint", "x509ce.DistributionPoint_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_reasons,
      { "reasons", "x509ce.reasons",
        FT_BYTES, BASE_NONE, NULL, 0,
        "ReasonFlags", HFILL }},
    { &hf_x509ce_cRLIssuer,
      { "cRLIssuer", "x509ce.cRLIssuer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GeneralNames", HFILL }},
    { &hf_x509ce_fullName,
      { "fullName", "x509ce.fullName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GeneralNames", HFILL }},
    { &hf_x509ce_nameRelativeToCRLIssuer,
      { "nameRelativeToCRLIssuer", "x509ce.nameRelativeToCRLIssuer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RelativeDistinguishedName", HFILL }},
    { &hf_x509ce_onlyContainsUserPublicKeyCerts,
      { "onlyContainsUserPublicKeyCerts", "x509ce.onlyContainsUserPublicKeyCerts",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_x509ce_onlyContainsCACerts,
      { "onlyContainsCACerts", "x509ce.onlyContainsCACerts",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_x509ce_indirectCRL,
      { "indirectCRL", "x509ce.indirectCRL",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_x509ce_ToBeRevokedSyntax_item,
      { "ToBeRevokedGroup", "x509ce.ToBeRevokedGroup_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_certificateIssuer,
      { "certificateIssuer", "x509ce.certificateIssuer",
        FT_UINT32, BASE_DEC, VALS(x509ce_GeneralName_vals), 0,
        "GeneralName", HFILL }},
    { &hf_x509ce_reasonInfo,
      { "reasonInfo", "x509ce.reasonInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_revocationTime,
      { "revocationTime", "x509ce.revocationTime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_x509ce_certificateGroup,
      { "certificateGroup", "x509ce.certificateGroup",
        FT_UINT32, BASE_DEC, VALS(x509ce_CertificateGroup_vals), 0,
        NULL, HFILL }},
    { &hf_x509ce_reasonCode,
      { "reasonCode", "x509ce.reasonCode",
        FT_UINT32, BASE_DEC, VALS(x509ce_CRLReason_vals), 0,
        "CRLReason", HFILL }},
    { &hf_x509ce_holdInstructionCode,
      { "holdInstructionCode", "x509ce.holdInstructionCode",
        FT_OID, BASE_NONE, NULL, 0,
        "HoldInstruction", HFILL }},
    { &hf_x509ce_serialNumbers,
      { "serialNumbers", "x509ce.serialNumbers",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CertificateSerialNumbers", HFILL }},
    { &hf_x509ce_certificateGroupNumberRange,
      { "serialNumberRange", "x509ce.serialNumberRange_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertificateGroupNumberRange", HFILL }},
    { &hf_x509ce_nameSubtree,
      { "nameSubtree", "x509ce.nameSubtree",
        FT_UINT32, BASE_DEC, VALS(x509ce_GeneralName_vals), 0,
        "GeneralName", HFILL }},
    { &hf_x509ce_CertificateSerialNumbers_item,
      { "CertificateSerialNumber", "x509ce.CertificateSerialNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_RevokedGroupsSyntax_item,
      { "RevokedGroup", "x509ce.RevokedGroup_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_invalidityDate,
      { "invalidityDate", "x509ce.invalidityDate",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_x509ce_revokedcertificateGroup,
      { "revokedcertificateGroup", "x509ce.revokedcertificateGroup",
        FT_UINT32, BASE_DEC, VALS(x509ce_RevokedCertificateGroup_vals), 0,
        NULL, HFILL }},
    { &hf_x509ce_containsUserAttributeCerts,
      { "containsUserAttributeCerts", "x509ce.containsUserAttributeCerts",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_x509ce_containsAACerts,
      { "containsAACerts", "x509ce.containsAACerts",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_x509ce_containsSOAPublicKeyCerts,
      { "containsSOAPublicKeyCerts", "x509ce.containsSOAPublicKeyCerts",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_x509ce_serialNumber,
      { "serialNumber", "x509ce.serialNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        "CertificateSerialNumber", HFILL }},
    { &hf_x509ce_issuer,
      { "issuer", "x509ce.issuer",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "Name", HFILL }},
    { &hf_x509ce_subjectKeyIdentifier,
      { "subjectKeyIdentifier", "x509ce.subjectKeyIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_authorityKeyIdentifier,
      { "authorityKeyIdentifier", "x509ce.authorityKeyIdentifier_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_certificateValid,
      { "certificateValid", "x509ce.certificateValid",
        FT_UINT32, BASE_DEC, VALS(x509af_Time_vals), 0,
        "Time", HFILL }},
    { &hf_x509ce_privateKeyValid,
      { "privateKeyValid", "x509ce.privateKeyValid",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_x509ce_subjectPublicKeyAlgID,
      { "subjectPublicKeyAlgID", "x509ce.subjectPublicKeyAlgID",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_x509ce_keyUsage,
      { "keyUsage", "x509ce.keyUsage",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_subjectAltNameType,
      { "subjectAltName", "x509ce.subjectAltName",
        FT_UINT32, BASE_DEC, VALS(x509ce_AltNameType_vals), 0,
        "AltNameType", HFILL }},
    { &hf_x509ce_policy,
      { "policy", "x509ce.policy",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CertPolicySet", HFILL }},
    { &hf_x509ce_pathToName,
      { "pathToName", "x509ce.pathToName",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "Name", HFILL }},
    { &hf_x509ce_subject,
      { "subject", "x509ce.subject",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "Name", HFILL }},
    { &hf_x509ce_nameConstraints,
      { "nameConstraints", "x509ce.nameConstraints_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NameConstraintsSyntax", HFILL }},
    { &hf_x509ce_builtinNameForm,
      { "builtinNameForm", "x509ce.builtinNameForm",
        FT_UINT32, BASE_DEC, VALS(x509ce_T_builtinNameForm_vals), 0,
        NULL, HFILL }},
    { &hf_x509ce_otherNameForm,
      { "otherNameForm", "x509ce.otherNameForm",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_x509ce_CertPolicySet_item,
      { "CertPolicyId", "x509ce.CertPolicyId",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_cpea_issuedToThisCAAssertion,
      { "issuedToThisCAAssertion", "x509ce.issuedToThisCAAssertion_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertificateExactAssertion", HFILL }},
    { &hf_x509ce_cpea_issuedByThisCAAssertion,
      { "issuedByThisCAAssertion", "x509ce.issuedByThisCAAssertion_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertificateExactAssertion", HFILL }},
    { &hf_x509ce_issuedToThisCAAssertion,
      { "issuedToThisCAAssertion", "x509ce.issuedToThisCAAssertion_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertificateAssertion", HFILL }},
    { &hf_x509ce_issuedByThisCAAssertion,
      { "issuedByThisCAAssertion", "x509ce.issuedByThisCAAssertion_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertificateAssertion", HFILL }},
    { &hf_x509ce_thisUpdate,
      { "thisUpdate", "x509ce.thisUpdate",
        FT_UINT32, BASE_DEC, VALS(x509af_Time_vals), 0,
        "Time", HFILL }},
    { &hf_x509ce_minCRLNumber,
      { "minCRLNumber", "x509ce.minCRLNumber",
        FT_UINT64, BASE_DEC, NULL, 0,
        "CRLNumber", HFILL }},
    { &hf_x509ce_maxCRLNumber,
      { "maxCRLNumber", "x509ce.maxCRLNumber",
        FT_UINT64, BASE_DEC, NULL, 0,
        "CRLNumber", HFILL }},
    { &hf_x509ce_reasonFlags,
      { "reasonFlags", "x509ce.reasonFlags",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_dateAndTime,
      { "dateAndTime", "x509ce.dateAndTime",
        FT_UINT32, BASE_DEC, VALS(x509af_Time_vals), 0,
        "Time", HFILL }},
    { &hf_x509ce_firstIssuer,
      { "firstIssuer", "x509ce.firstIssuer",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "Name", HFILL }},
    { &hf_x509ce_lastSubject,
      { "lastSubject", "x509ce.lastSubject",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "Name", HFILL }},
    { &hf_x509ce_subjectAltName,
      { "subjectAltName", "x509ce.subjectAltName_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AltName", HFILL }},
    { &hf_x509ce_enhancedPathToName,
      { "pathToName", "x509ce.pathToName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GeneralNames", HFILL }},
    { &hf_x509ce_altnameType,
      { "altnameType", "x509ce.altnameType",
        FT_UINT32, BASE_DEC, VALS(x509ce_AltNameType_vals), 0,
        NULL, HFILL }},
    { &hf_x509ce_altNameValue,
      { "altNameValue", "x509ce.altNameValue",
        FT_UINT32, BASE_DEC, VALS(x509ce_GeneralName_vals), 0,
        "GeneralName", HFILL }},
    { &hf_x509ce_templateID,
      { "templateID", "x509ce.templateID",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_x509ce_templateMajorVersion,
      { "templateMajorVersion", "x509ce.templateMajorVersion",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_x509ce_templateMinorVersion,
      { "templateMinorVersion", "x509ce.templateMinorVersion",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_x509ce_ntdsObjectSid,
      { "ntdsObjectSid", "x509ce.ntdsObjectSid_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_type_id_01,
      { "type-id", "x509ce.type_id",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_x509ce_sid,
      { "sid", "x509ce.sid",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString", HFILL }},
    { &hf_x509ce_entrustVers,
      { "entrustVers", "x509ce.entrustVers",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralString", HFILL }},
    { &hf_x509ce_entrustVersInfoFlags,
      { "entrustVersInfoFlags", "x509ce.entrustVersInfoFlags",
        FT_BYTES, BASE_NONE, NULL, 0,
        "EntrustInfoFlags", HFILL }},
    { &hf_x509ce_NFTypes_item,
      { "NFType", "x509ce.NFType",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509ce_capability,
      { "capability", "x509ce.capability",
        FT_UINT64, BASE_DEC|BASE_VAL64_STRING, VALS64(ciplus_scr_cap), 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_x509ce_version,
      { "version", "x509ce.version",
        FT_UINT64, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_x509ce_KeyUsage_digitalSignature,
      { "digitalSignature", "x509ce.KeyUsage.digitalSignature",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_x509ce_KeyUsage_contentCommitment,
      { "contentCommitment", "x509ce.KeyUsage.contentCommitment",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_x509ce_KeyUsage_keyEncipherment,
      { "keyEncipherment", "x509ce.KeyUsage.keyEncipherment",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_x509ce_KeyUsage_dataEncipherment,
      { "dataEncipherment", "x509ce.KeyUsage.dataEncipherment",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_x509ce_KeyUsage_keyAgreement,
      { "keyAgreement", "x509ce.KeyUsage.keyAgreement",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_x509ce_KeyUsage_keyCertSign,
      { "keyCertSign", "x509ce.KeyUsage.keyCertSign",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_x509ce_KeyUsage_cRLSign,
      { "cRLSign", "x509ce.KeyUsage.cRLSign",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_x509ce_KeyUsage_encipherOnly,
      { "encipherOnly", "x509ce.KeyUsage.encipherOnly",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_x509ce_KeyUsage_decipherOnly,
      { "decipherOnly", "x509ce.KeyUsage.decipherOnly",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_x509ce_OnlyCertificateTypes_user,
      { "user", "x509ce.OnlyCertificateTypes.user",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_x509ce_OnlyCertificateTypes_authority,
      { "authority", "x509ce.OnlyCertificateTypes.authority",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_x509ce_OnlyCertificateTypes_attribute,
      { "attribute", "x509ce.OnlyCertificateTypes.attribute",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_x509ce_ReasonFlags_unused,
      { "unused", "x509ce.ReasonFlags.unused",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_x509ce_ReasonFlags_keyCompromise,
      { "keyCompromise", "x509ce.ReasonFlags.keyCompromise",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_x509ce_ReasonFlags_cACompromise,
      { "cACompromise", "x509ce.ReasonFlags.cACompromise",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_x509ce_ReasonFlags_affiliationChanged,
      { "affiliationChanged", "x509ce.ReasonFlags.affiliationChanged",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_x509ce_ReasonFlags_superseded,
      { "superseded", "x509ce.ReasonFlags.superseded",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_x509ce_ReasonFlags_cessationOfOperation,
      { "cessationOfOperation", "x509ce.ReasonFlags.cessationOfOperation",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_x509ce_ReasonFlags_certificateHold,
      { "certificateHold", "x509ce.ReasonFlags.certificateHold",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_x509ce_ReasonFlags_privilegeWithdrawn,
      { "privilegeWithdrawn", "x509ce.ReasonFlags.privilegeWithdrawn",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_x509ce_ReasonFlags_aACompromise,
      { "aACompromise", "x509ce.ReasonFlags.aACompromise",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_x509ce_EntrustInfoFlags_keyUpdateAllowed,
      { "keyUpdateAllowed", "x509ce.EntrustInfoFlags.keyUpdateAllowed",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_x509ce_EntrustInfoFlags_newExtensions,
      { "newExtensions", "x509ce.EntrustInfoFlags.newExtensions",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_x509ce_EntrustInfoFlags_pKIXCertificate,
      { "pKIXCertificate", "x509ce.EntrustInfoFlags.pKIXCertificate",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_x509ce_EntrustInfoFlags_enterpriseCategory,
      { "enterpriseCategory", "x509ce.EntrustInfoFlags.enterpriseCategory",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_x509ce_EntrustInfoFlags_webCategory,
      { "webCategory", "x509ce.EntrustInfoFlags.webCategory",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_x509ce_EntrustInfoFlags_sETCategory,
      { "sETCategory", "x509ce.EntrustInfoFlags.sETCategory",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
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
    &ett_x509ce_OtherName,
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
    &ett_x509ce_ToBeRevokedSyntax,
    &ett_x509ce_ToBeRevokedGroup,
    &ett_x509ce_ReasonInfo,
    &ett_x509ce_CertificateGroup,
    &ett_x509ce_CertificateGroupNumberRange,
    &ett_x509ce_CertificateSerialNumbers,
    &ett_x509ce_RevokedGroupsSyntax,
    &ett_x509ce_RevokedGroup,
    &ett_x509ce_RevokedCertificateGroup,
    &ett_x509ce_AAIssuingDistPointSyntax,
    &ett_x509ce_CertificateExactAssertion,
    &ett_x509ce_CertificateAssertion,
    &ett_x509ce_AltNameType,
    &ett_x509ce_CertPolicySet,
    &ett_x509ce_CertificatePairExactAssertion,
    &ett_x509ce_CertificatePairAssertion,
    &ett_x509ce_CertificateListExactAssertion,
    &ett_x509ce_CertificateListAssertion,
    &ett_x509ce_PkiPathMatchSyntax,
    &ett_x509ce_EnhancedCertificateAssertion,
    &ett_x509ce_AltName,
    &ett_x509ce_CertificateTemplate,
    &ett_x509ce_NtdsCaSecurity,
    &ett_x509ce_NtdsObjectSid_U,
    &ett_x509ce_EntrustVersionInfo,
    &ett_x509ce_EntrustInfoFlags,
    &ett_x509ce_NFTypes,
    &ett_x509ce_ScramblerCapabilities,
  };

  /* Register protocol */
  proto_x509ce = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_x509ce, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_x509ce -------------------------------------------*/
void proto_reg_handoff_x509ce(void) {
  register_ber_oid_dissector("2.5.29.3", dissect_CertificatePoliciesSyntax_PDU, proto_x509ce, "id-ce-certificatePolicies");
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
  register_ber_oid_dissector("2.5.29.58", dissect_ToBeRevokedSyntax_PDU, proto_x509ce, "id-ce-toBeRevoked");
  register_ber_oid_dissector("2.5.29.59", dissect_RevokedGroupsSyntax_PDU, proto_x509ce, "id-ce-RevokedGroups");
  register_ber_oid_dissector("2.5.29.60", dissect_ExpiredCertsOnCRL_PDU, proto_x509ce, "id-ce-expiredCertsOnCRL");
  register_ber_oid_dissector("2.5.29.61", dissect_AAIssuingDistPointSyntax_PDU, proto_x509ce, "id-ce-aAissuingDistributionPoint");
  register_ber_oid_dissector("1.3.6.1.5.5.7.1.34", dissect_NFTypes_PDU, proto_x509ce, "id-pe-nftype");
  register_ber_oid_dissector("2.5.13.35", dissect_CertificateAssertion_PDU, proto_x509ce, "id-mr-certificateMatch");
  register_ber_oid_dissector("2.5.13.36", dissect_CertificatePairExactAssertion_PDU, proto_x509ce, "id-mr-certificatePairExactMatch");
  register_ber_oid_dissector("2.5.13.37", dissect_CertificatePairAssertion_PDU, proto_x509ce, "id-mr-certificatePairMatch");
  register_ber_oid_dissector("2.5.13.38", dissect_CertificateListExactAssertion_PDU, proto_x509ce, "id-mr-certificateListExactMatch");
  register_ber_oid_dissector("2.5.13.39", dissect_CertificateListAssertion_PDU, proto_x509ce, "id-mr-certificateListMatch");
  register_ber_oid_dissector("2.5.13.62", dissect_PkiPathMatchSyntax_PDU, proto_x509ce, "id-mr-pkiPathMatch");
  register_ber_oid_dissector("2.5.13.65", dissect_EnhancedCertificateAssertion_PDU, proto_x509ce, "id-mr-enhancedCertificateMatch");
  register_ber_oid_dissector("1.3.6.1.4.1.311.21.7", dissect_CertificateTemplate_PDU, proto_x509ce, "id-ms-certificate-template");
  register_ber_oid_dissector("1.3.6.1.4.1.311.21.10", dissect_CertificatePoliciesSyntax_PDU, proto_x509ce, "id-ms-application-certificate-policies");
  register_ber_oid_dissector("1.3.6.1.4.1.311.25.2", dissect_NtdsCaSecurity_PDU, proto_x509ce, "id-ms-ntds-ca-security");
  register_ber_oid_dissector("1.3.6.1.4.1.311.25.2.1", dissect_NtdsObjectSid_PDU, proto_x509ce, "id-ms-ntds-object-sid");
  register_ber_oid_dissector("1.2.840.113533.7.65.0", dissect_EntrustVersionInfo_PDU, proto_x509ce, "id-ce-entrustVersionInfo");

  register_ber_oid_dissector("2.5.29.24", dissect_x509ce_invalidityDate_callback, proto_x509ce, "id-ce-invalidityDate");
  register_ber_oid_dissector("2.5.29.51", dissect_x509ce_baseUpdateTime_callback, proto_x509ce, "id-ce-baseUpdateTime");
  oid_add_from_string("anyPolicy","2.5.29.32.0");
}


/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
