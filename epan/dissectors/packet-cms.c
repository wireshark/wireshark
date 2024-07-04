/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-cms.c                                                               */
/* asn2wrs.py -b -C -q -L -p cms -c ./cms.cnf -s ./packet-cms-template -D . -O ../.. CryptographicMessageSyntax.asn AttributeCertificateVersion1.asn CMSFirmwareWrapper.asn */

/* packet-cms.c
 * Routines for RFC5652 Cryptographic Message Syntax packet dissection
 *   Ronnie Sahlberg 2004
 *   Stig Bjorlykke 2010
 *   Uwe Heuert 2022
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
#include <epan/proto_data.h>
#include <wsutil/wsgcrypt.h>

#include "packet-ber.h"
#include "packet-cms.h"
#include "packet-x509af.h"
#include "packet-x509ce.h"
#include "packet-x509if.h"
#include "packet-x509sat.h"
#include "packet-pkcs12.h"

#define PNAME  "Cryptographic Message Syntax"
#define PSNAME "CMS"
#define PFNAME "cms"

void proto_register_cms(void);
void proto_reg_handoff_cms(void);

/* Initialize the protocol and registered fields */
static int proto_cms;
static int hf_cms_ci_contentType;
static int hf_cms_ContentInfo_PDU;                /* ContentInfo */
static int hf_cms_ContentType_PDU;                /* ContentType */
static int hf_cms_SignedData_PDU;                 /* SignedData */
static int hf_cms_EnvelopedData_PDU;              /* EnvelopedData */
static int hf_cms_EncryptedContentInfo_PDU;       /* EncryptedContentInfo */
static int hf_cms_DigestedData_PDU;               /* DigestedData */
static int hf_cms_EncryptedData_PDU;              /* EncryptedData */
static int hf_cms_AuthenticatedData_PDU;          /* AuthenticatedData */
static int hf_cms_KeyEncryptionAlgorithmIdentifier_PDU;  /* KeyEncryptionAlgorithmIdentifier */
static int hf_cms_IssuerAndSerialNumber_PDU;      /* IssuerAndSerialNumber */
static int hf_cms_MessageDigest_PDU;              /* MessageDigest */
static int hf_cms_SigningTime_PDU;                /* SigningTime */
static int hf_cms_Countersignature_PDU;           /* Countersignature */
static int hf_cms_KeyWrapAlgorithm_PDU;           /* KeyWrapAlgorithm */
static int hf_cms_RC2WrapParameter_PDU;           /* RC2WrapParameter */
static int hf_cms_IV_PDU;                         /* IV */
static int hf_cms_SMIMECapabilities_PDU;          /* SMIMECapabilities */
static int hf_cms_SMIMEEncryptionKeyPreference_PDU;  /* SMIMEEncryptionKeyPreference */
static int hf_cms_RC2CBCParameters_PDU;           /* RC2CBCParameters */
static int hf_cms_AuthEnvelopedData_PDU;          /* AuthEnvelopedData */
static int hf_cms_CCMParameters_PDU;              /* CCMParameters */
static int hf_cms_GCMParameters_PDU;              /* GCMParameters */
static int hf_cms_FirmwarePkgData_PDU;            /* FirmwarePkgData */
static int hf_cms_FirmwarePackageIdentifier_PDU;  /* FirmwarePackageIdentifier */
static int hf_cms_TargetHardwareIdentifiers_PDU;  /* TargetHardwareIdentifiers */
static int hf_cms_DecryptKeyIdentifier_PDU;       /* DecryptKeyIdentifier */
static int hf_cms_ImplementedCryptoAlgorithms_PDU;  /* ImplementedCryptoAlgorithms */
static int hf_cms_ImplementedCompressAlgorithms_PDU;  /* ImplementedCompressAlgorithms */
static int hf_cms_CommunityIdentifiers_PDU;       /* CommunityIdentifiers */
static int hf_cms_FirmwarePackageInfo_PDU;        /* FirmwarePackageInfo */
static int hf_cms_WrappedFirmwareKey_PDU;         /* WrappedFirmwareKey */
static int hf_cms_FirmwarePackageLoadReceipt_PDU;  /* FirmwarePackageLoadReceipt */
static int hf_cms_FirmwarePackageLoadError_PDU;   /* FirmwarePackageLoadError */
static int hf_cms_HardwareModuleName_PDU;         /* HardwareModuleName */
static int hf_cms_FirmwarePackageMessageDigest_PDU;  /* FirmwarePackageMessageDigest */
static int hf_cms_contentType;                    /* ContentType */
static int hf_cms_content;                        /* T_content */
static int hf_cms_version;                        /* CMSVersion */
static int hf_cms_digestAlgorithms;               /* DigestAlgorithmIdentifiers */
static int hf_cms_encapContentInfo;               /* EncapsulatedContentInfo */
static int hf_cms_certificates;                   /* CertificateSet */
static int hf_cms_crls;                           /* RevocationInfoChoices */
static int hf_cms_signerInfos;                    /* SignerInfos */
static int hf_cms_DigestAlgorithmIdentifiers_item;  /* DigestAlgorithmIdentifier */
static int hf_cms_SignerInfos_item;               /* SignerInfo */
static int hf_cms_eContentType;                   /* ContentType */
static int hf_cms_eContent;                       /* T_eContent */
static int hf_cms_sid;                            /* SignerIdentifier */
static int hf_cms_digestAlgorithm;                /* DigestAlgorithmIdentifier */
static int hf_cms_signedAttrs;                    /* SignedAttributes */
static int hf_cms_signatureAlgorithm;             /* SignatureAlgorithmIdentifier */
static int hf_cms_signatureValue;                 /* SignatureValue */
static int hf_cms_unsignedAttrs;                  /* UnsignedAttributes */
static int hf_cms_issuerAndSerialNumber;          /* IssuerAndSerialNumber */
static int hf_cms_subjectKeyIdentifier;           /* SubjectKeyIdentifier */
static int hf_cms_SignedAttributes_item;          /* Attribute */
static int hf_cms_UnsignedAttributes_item;        /* Attribute */
static int hf_cms_attrType;                       /* T_attrType */
static int hf_cms_attrValues;                     /* SET_OF_AttributeValue */
static int hf_cms_attrValues_item;                /* AttributeValue */
static int hf_cms_originatorInfo;                 /* OriginatorInfo */
static int hf_cms_recipientInfos;                 /* RecipientInfos */
static int hf_cms_encryptedContentInfo;           /* EncryptedContentInfo */
static int hf_cms_unprotectedAttrs;               /* UnprotectedAttributes */
static int hf_cms_certs;                          /* CertificateSet */
static int hf_cms_RecipientInfos_item;            /* RecipientInfo */
static int hf_cms_encryptedContentType;           /* ContentType */
static int hf_cms_contentEncryptionAlgorithm;     /* ContentEncryptionAlgorithmIdentifier */
static int hf_cms_encryptedContent;               /* EncryptedContent */
static int hf_cms_UnprotectedAttributes_item;     /* Attribute */
static int hf_cms_ktri;                           /* KeyTransRecipientInfo */
static int hf_cms_kari;                           /* KeyAgreeRecipientInfo */
static int hf_cms_kekri;                          /* KEKRecipientInfo */
static int hf_cms_pwri;                           /* PasswordRecipientInfo */
static int hf_cms_ori;                            /* OtherRecipientInfo */
static int hf_cms_rid;                            /* RecipientIdentifier */
static int hf_cms_keyEncryptionAlgorithm;         /* KeyEncryptionAlgorithmIdentifier */
static int hf_cms_encryptedKey;                   /* EncryptedKey */
static int hf_cms_originator;                     /* OriginatorIdentifierOrKey */
static int hf_cms_ukm;                            /* UserKeyingMaterial */
static int hf_cms_recipientEncryptedKeys;         /* RecipientEncryptedKeys */
static int hf_cms_originatorKey;                  /* OriginatorPublicKey */
static int hf_cms_algorithm;                      /* AlgorithmIdentifier */
static int hf_cms_publicKey;                      /* BIT_STRING */
static int hf_cms_RecipientEncryptedKeys_item;    /* RecipientEncryptedKey */
static int hf_cms_rekRid;                         /* KeyAgreeRecipientIdentifier */
static int hf_cms_rKeyId;                         /* RecipientKeyIdentifier */
static int hf_cms_date;                           /* GeneralizedTime */
static int hf_cms_other;                          /* OtherKeyAttribute */
static int hf_cms_kekid;                          /* KEKIdentifier */
static int hf_cms_keyIdentifier;                  /* OCTET_STRING */
static int hf_cms_keyDerivationAlgorithm;         /* KeyDerivationAlgorithmIdentifier */
static int hf_cms_oriType;                        /* T_oriType */
static int hf_cms_oriValue;                       /* T_oriValue */
static int hf_cms_digest;                         /* Digest */
static int hf_cms_macAlgorithm;                   /* MessageAuthenticationCodeAlgorithm */
static int hf_cms_authAttrs;                      /* AuthAttributes */
static int hf_cms_mac;                            /* MessageAuthenticationCode */
static int hf_cms_unauthAttrs;                    /* UnauthAttributes */
static int hf_cms_AuthAttributes_item;            /* Attribute */
static int hf_cms_UnauthAttributes_item;          /* Attribute */
static int hf_cms_RevocationInfoChoices_item;     /* RevocationInfoChoice */
static int hf_cms_crl;                            /* CertificateList */
static int hf_cms_otherRIC;                       /* OtherRevocationInfoFormat */
static int hf_cms_otherRevInfoFormat;             /* T_otherRevInfoFormat */
static int hf_cms_otherRevInfo;                   /* T_otherRevInfo */
static int hf_cms_certificate;                    /* Certificate */
static int hf_cms_extendedCertificate;            /* ExtendedCertificate */
static int hf_cms_v1AttrCert;                     /* AttributeCertificateV1 */
static int hf_cms_v2AttrCert;                     /* AttributeCertificateV2 */
static int hf_cms_CertificateSet_item;            /* CertificateChoices */
static int hf_cms_issuer;                         /* Name */
static int hf_cms_serialNumber;                   /* CertificateSerialNumber */
static int hf_cms_keyAttrId;                      /* T_keyAttrId */
static int hf_cms_keyAttr;                        /* T_keyAttr */
static int hf_cms_utcTime;                        /* UTCTime */
static int hf_cms_generalTime;                    /* GeneralizedTime */
static int hf_cms_rc2ParameterVersion;            /* INTEGER */
static int hf_cms_iv;                             /* OCTET_STRING */
static int hf_cms_extendedCertificateInfo;        /* ExtendedCertificateInfo */
static int hf_cms_signature;                      /* Signature */
static int hf_cms_attributes;                     /* UnauthAttributes */
static int hf_cms_SMIMECapabilities_item;         /* SMIMECapability */
static int hf_cms_capability;                     /* T_capability */
static int hf_cms_parameters;                     /* T_parameters */
static int hf_cms_recipientKeyId;                 /* RecipientKeyIdentifier */
static int hf_cms_subjectAltKeyIdentifier;        /* SubjectKeyIdentifier */
static int hf_cms_rc2WrapParameter;               /* RC2WrapParameter */
static int hf_cms_rc2CBCParameter;                /* RC2CBCParameter */
static int hf_cms_authEncryptedContentInfo;       /* EncryptedContentInfo */
static int hf_cms_aes_nonce;                      /* OCTET_STRING_SIZE_7_13 */
static int hf_cms_aes_ICVlen;                     /* AES_CCM_ICVlen */
static int hf_cms_aes_nonce_01;                   /* OCTET_STRING */
static int hf_cms_aes_ICVlen_01;                  /* AES_GCM_ICVlen */
static int hf_cms_acInfo;                         /* AttributeCertificateInfoV1 */
static int hf_cms_signatureAlgorithm_v1;          /* AlgorithmIdentifier */
static int hf_cms_signatureValue_v1;              /* BIT_STRING */
static int hf_cms_version_v1;                     /* AttCertVersionV1 */
static int hf_cms_subject;                        /* T_subject */
static int hf_cms_baseCertificateID;              /* IssuerSerial */
static int hf_cms_subjectName;                    /* GeneralNames */
static int hf_cms_issuer_v1;                      /* GeneralNames */
static int hf_cms_signature_v1;                   /* AlgorithmIdentifier */
static int hf_cms_attCertValidityPeriod;          /* AttCertValidityPeriod */
static int hf_cms_attributes_v1;                  /* SEQUENCE_OF_Attribute */
static int hf_cms_attributes_v1_item;             /* Attribute */
static int hf_cms_issuerUniqueID;                 /* UniqueIdentifier */
static int hf_cms_extensions;                     /* Extensions */
static int hf_cms_name;                           /* PreferredOrLegacyPackageIdentifier */
static int hf_cms_stale;                          /* PreferredOrLegacyStalePackageIdentifier */
static int hf_cms_preferred;                      /* PreferredPackageIdentifier */
static int hf_cms_legacy;                         /* OCTET_STRING */
static int hf_cms_fwPkgID;                        /* OBJECT_IDENTIFIER */
static int hf_cms_verNum;                         /* INTEGER_0_MAX */
static int hf_cms_preferredStaleVerNum;           /* INTEGER_0_MAX */
static int hf_cms_legacyStaleVersion;             /* OCTET_STRING */
static int hf_cms_TargetHardwareIdentifiers_item;  /* OBJECT_IDENTIFIER */
static int hf_cms_ImplementedCryptoAlgorithms_item;  /* OBJECT_IDENTIFIER */
static int hf_cms_ImplementedCompressAlgorithms_item;  /* OBJECT_IDENTIFIER */
static int hf_cms_CommunityIdentifiers_item;      /* CommunityIdentifier */
static int hf_cms_communityOID;                   /* OBJECT_IDENTIFIER */
static int hf_cms_hwModuleList;                   /* HardwareModules */
static int hf_cms_hwType;                         /* OBJECT_IDENTIFIER */
static int hf_cms_hwSerialEntries;                /* SEQUENCE_OF_HardwareSerialEntry */
static int hf_cms_hwSerialEntries_item;           /* HardwareSerialEntry */
static int hf_cms_all;                            /* NULL */
static int hf_cms_single;                         /* OCTET_STRING */
static int hf_cms_block;                          /* T_block */
static int hf_cms_low;                            /* OCTET_STRING */
static int hf_cms_high;                           /* OCTET_STRING */
static int hf_cms_fwPkgType;                      /* INTEGER */
static int hf_cms_dependencies;                   /* SEQUENCE_OF_PreferredOrLegacyPackageIdentifier */
static int hf_cms_dependencies_item;              /* PreferredOrLegacyPackageIdentifier */
static int hf_cms_fwReceiptVersion;               /* FWReceiptVersion */
static int hf_cms_hwSerialNum;                    /* OCTET_STRING */
static int hf_cms_fwPkgName;                      /* PreferredOrLegacyPackageIdentifier */
static int hf_cms_trustAnchorKeyID;               /* OCTET_STRING */
static int hf_cms_decryptKeyID;                   /* OCTET_STRING */
static int hf_cms_fwErrorVersion;                 /* FWErrorVersion */
static int hf_cms_errorCode;                      /* FirmwarePackageLoadErrorCode */
static int hf_cms_vendorErrorCode;                /* VendorLoadErrorCode */
static int hf_cms_config;                         /* SEQUENCE_OF_CurrentFWConfig */
static int hf_cms_config_item;                    /* CurrentFWConfig */
static int hf_cms_msgDigest;                      /* OCTET_STRING */

/* Initialize the subtree pointers */
static int ett_cms;
static int ett_cms_ContentInfo;
static int ett_cms_SignedData;
static int ett_cms_DigestAlgorithmIdentifiers;
static int ett_cms_SignerInfos;
static int ett_cms_EncapsulatedContentInfo;
static int ett_cms_SignerInfo;
static int ett_cms_SignerIdentifier;
static int ett_cms_SignedAttributes;
static int ett_cms_UnsignedAttributes;
static int ett_cms_Attribute;
static int ett_cms_SET_OF_AttributeValue;
static int ett_cms_EnvelopedData;
static int ett_cms_OriginatorInfo;
static int ett_cms_RecipientInfos;
static int ett_cms_EncryptedContentInfo;
static int ett_cms_UnprotectedAttributes;
static int ett_cms_RecipientInfo;
static int ett_cms_KeyTransRecipientInfo;
static int ett_cms_RecipientIdentifier;
static int ett_cms_KeyAgreeRecipientInfo;
static int ett_cms_OriginatorIdentifierOrKey;
static int ett_cms_OriginatorPublicKey;
static int ett_cms_RecipientEncryptedKeys;
static int ett_cms_RecipientEncryptedKey;
static int ett_cms_KeyAgreeRecipientIdentifier;
static int ett_cms_RecipientKeyIdentifier;
static int ett_cms_KEKRecipientInfo;
static int ett_cms_KEKIdentifier;
static int ett_cms_PasswordRecipientInfo;
static int ett_cms_OtherRecipientInfo;
static int ett_cms_DigestedData;
static int ett_cms_EncryptedData;
static int ett_cms_AuthenticatedData;
static int ett_cms_AuthAttributes;
static int ett_cms_UnauthAttributes;
static int ett_cms_RevocationInfoChoices;
static int ett_cms_RevocationInfoChoice;
static int ett_cms_OtherRevocationInfoFormat;
static int ett_cms_CertificateChoices;
static int ett_cms_CertificateSet;
static int ett_cms_IssuerAndSerialNumber;
static int ett_cms_OtherKeyAttribute;
static int ett_cms_Time;
static int ett_cms_RC2CBCParameter;
static int ett_cms_ExtendedCertificate;
static int ett_cms_ExtendedCertificateInfo;
static int ett_cms_DigestInfo;
static int ett_cms_SMIMECapabilities;
static int ett_cms_SMIMECapability;
static int ett_cms_SMIMEEncryptionKeyPreference;
static int ett_cms_RC2CBCParameters;
static int ett_cms_AuthEnvelopedData;
static int ett_cms_CCMParameters;
static int ett_cms_GCMParameters;
static int ett_cms_AttributeCertificateV1;
static int ett_cms_AttributeCertificateInfoV1;
static int ett_cms_T_subject;
static int ett_cms_SEQUENCE_OF_Attribute;
static int ett_cms_FirmwarePackageIdentifier;
static int ett_cms_PreferredOrLegacyPackageIdentifier;
static int ett_cms_PreferredPackageIdentifier;
static int ett_cms_PreferredOrLegacyStalePackageIdentifier;
static int ett_cms_TargetHardwareIdentifiers;
static int ett_cms_ImplementedCryptoAlgorithms;
static int ett_cms_ImplementedCompressAlgorithms;
static int ett_cms_CommunityIdentifiers;
static int ett_cms_CommunityIdentifier;
static int ett_cms_HardwareModules;
static int ett_cms_SEQUENCE_OF_HardwareSerialEntry;
static int ett_cms_HardwareSerialEntry;
static int ett_cms_T_block;
static int ett_cms_FirmwarePackageInfo;
static int ett_cms_SEQUENCE_OF_PreferredOrLegacyPackageIdentifier;
static int ett_cms_FirmwarePackageLoadReceipt;
static int ett_cms_FirmwarePackageLoadError;
static int ett_cms_SEQUENCE_OF_CurrentFWConfig;
static int ett_cms_CurrentFWConfig;
static int ett_cms_HardwareModuleName;
static int ett_cms_FirmwarePackageMessageDigest;

static dissector_handle_t cms_handle;

static int dissect_cms_OCTET_STRING(bool implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_) ; /* XXX kill a compiler warning until asn2wrs stops generating these silly wrappers */

struct cms_private_data {
  const char *object_identifier_id;
  tvbuff_t *content_tvb;
};

static proto_tree *top_tree;
static proto_tree *cap_tree;

#define HASH_SHA1 "1.3.14.3.2.26"

#define HASH_MD5 "1.2.840.113549.2.5"


/* SHA-2 variants */
#define HASH_SHA224 "2.16.840.1.101.3.4.2.4"
#define SHA224_BUFFER_SIZE  32 /* actually 28 */
#define HASH_SHA256 "2.16.840.1.101.3.4.2.1"
#define SHA256_BUFFER_SIZE  32

unsigned char digest_buf[MAX(HASH_SHA1_LENGTH, HASH_MD5_LENGTH)];

/*
* Dissect CMS PDUs inside a PPDU.
*/
static int
dissect_cms(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
	int offset = 0;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_cms, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_cms);
	}
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CMS");
	col_clear(pinfo->cinfo, COL_INFO);

	while (tvb_reported_length_remaining(tvb, offset) > 0){
		offset=dissect_cms_ContentInfo(false, tvb, offset, &asn1_ctx , tree, -1);
	}
	return tvb_captured_length(tvb);
}

static struct cms_private_data*
cms_get_private_data(packet_info *pinfo)
{
  struct cms_private_data *cms_data = (struct cms_private_data*)p_get_proto_data(pinfo->pool, pinfo, proto_cms, 0);
  if (!cms_data) {
    cms_data = wmem_new0(pinfo->pool, struct cms_private_data);
    p_add_proto_data(pinfo->pool, pinfo, proto_cms, 0, cms_data);
  }
  return cms_data;
}

static void
cms_verify_msg_digest(proto_item *pi, tvbuff_t *content, const char *alg, tvbuff_t *tvb, int offset)
{
  int i= 0, buffer_size = 0;

  /* we only support two algorithms at the moment  - if we do add SHA2
     we should add a registration process to use a registration process */

  if(strcmp(alg, HASH_SHA1) == 0) {
    gcry_md_hash_buffer(GCRY_MD_SHA1, digest_buf, tvb_get_ptr(content, 0, tvb_captured_length(content)), tvb_captured_length(content));
    buffer_size = HASH_SHA1_LENGTH;

  } else if(strcmp(alg, HASH_MD5) == 0) {
    gcry_md_hash_buffer(GCRY_MD_MD5, digest_buf, tvb_get_ptr(content, 0, tvb_captured_length(content)), tvb_captured_length(content));
    buffer_size = HASH_MD5_LENGTH;
  }

  if(buffer_size) {
    /* compare our computed hash with what we have received */

    if(tvb_bytes_exist(tvb, offset, buffer_size) &&
       (tvb_memeql(tvb, offset, digest_buf, buffer_size) != 0)) {
      proto_item_append_text(pi, " [incorrect, should be ");
      for(i = 0; i < buffer_size; i++)
	proto_item_append_text(pi, "%02X", digest_buf[i]);

      proto_item_append_text(pi, "]");
    }
    else
      proto_item_append_text(pi, " [correct]");
  } else {
    proto_item_append_text(pi, " [unable to verify]");
  }

}



int
dissect_cms_ContentType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  struct cms_private_data *cms_data = cms_get_private_data(actx->pinfo);
  cms_data->object_identifier_id = NULL;
  const char *name = NULL;

    offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &cms_data->object_identifier_id);


  if(cms_data->object_identifier_id) {
    name = oid_resolved_from_string(actx->pinfo->pool, cms_data->object_identifier_id);
    proto_item_append_text(tree, " (%s)", name ? name : cms_data->object_identifier_id);
  }


  return offset;
}



static int
dissect_cms_T_content(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  struct cms_private_data *cms_data = cms_get_private_data(actx->pinfo);
  offset=call_ber_oid_callback(cms_data->object_identifier_id, tvb, offset, actx->pinfo, tree, NULL);



  return offset;
}


static const ber_sequence_t ContentInfo_sequence[] = {
  { &hf_cms_contentType     , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cms_ContentType },
  { &hf_cms_content         , BER_CLASS_CON, 0, 0, dissect_cms_T_content },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cms_ContentInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  top_tree = tree;
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ContentInfo_sequence, hf_index, ett_cms_ContentInfo);

  top_tree = NULL;


  return offset;
}


static const value_string cms_CMSVersion_vals[] = {
  {   0, "v0" },
  {   1, "v1" },
  {   2, "v2" },
  {   3, "v3" },
  {   4, "v4" },
  {   5, "v5" },
  { 0, NULL }
};


static int
dissect_cms_CMSVersion(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



int
dissect_cms_DigestAlgorithmIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t DigestAlgorithmIdentifiers_set_of[1] = {
  { &hf_cms_DigestAlgorithmIdentifiers_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_DigestAlgorithmIdentifier },
};

int
dissect_cms_DigestAlgorithmIdentifiers(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 DigestAlgorithmIdentifiers_set_of, hf_index, ett_cms_DigestAlgorithmIdentifiers);

  return offset;
}



static int
dissect_cms_T_eContent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  struct cms_private_data *cms_data = cms_get_private_data(actx->pinfo);
  cms_data->content_tvb = NULL;
  offset = dissect_ber_octet_string(false, actx, tree, tvb, offset, hf_index, &cms_data->content_tvb);

  if(cms_data->content_tvb) {
    proto_item_set_text(actx->created_item, "eContent (%u bytes)", tvb_reported_length(cms_data->content_tvb));

    call_ber_oid_callback(cms_data->object_identifier_id, cms_data->content_tvb, 0, actx->pinfo, top_tree ? top_tree : tree, NULL);
  }


  return offset;
}


static const ber_sequence_t EncapsulatedContentInfo_sequence[] = {
  { &hf_cms_eContentType    , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cms_ContentType },
  { &hf_cms_eContent        , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_cms_T_eContent },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cms_EncapsulatedContentInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EncapsulatedContentInfo_sequence, hf_index, ett_cms_EncapsulatedContentInfo);

  return offset;
}



static int
dissect_cms_T_attrType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  struct cms_private_data *cms_data = cms_get_private_data(actx->pinfo);
  cms_data->object_identifier_id = NULL;
  const char *name = NULL;

    offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_cms_attrType, &cms_data->object_identifier_id);


  if(cms_data->object_identifier_id) {
    name = oid_resolved_from_string(actx->pinfo->pool, cms_data->object_identifier_id);
    proto_item_append_text(tree, " (%s)", name ? name : cms_data->object_identifier_id);
  }


  return offset;
}



static int
dissect_cms_AttributeValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  struct cms_private_data *cms_data = cms_get_private_data(actx->pinfo);

  offset=call_ber_oid_callback(cms_data->object_identifier_id, tvb, offset, actx->pinfo, tree, NULL);


  return offset;
}


static const ber_sequence_t SET_OF_AttributeValue_set_of[1] = {
  { &hf_cms_attrValues_item , BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_cms_AttributeValue },
};

static int
dissect_cms_SET_OF_AttributeValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_AttributeValue_set_of, hf_index, ett_cms_SET_OF_AttributeValue);

  return offset;
}


static const ber_sequence_t Attribute_sequence[] = {
  { &hf_cms_attrType        , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cms_T_attrType },
  { &hf_cms_attrValues      , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_cms_SET_OF_AttributeValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_Attribute(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Attribute_sequence, hf_index, ett_cms_Attribute);

  return offset;
}


static const ber_sequence_t UnauthAttributes_set_of[1] = {
  { &hf_cms_UnauthAttributes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_Attribute },
};

static int
dissect_cms_UnauthAttributes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_set_of(implicit_tag, actx, tree, tvb, offset,
                                             1, NO_BOUND, UnauthAttributes_set_of, hf_index, ett_cms_UnauthAttributes);

  return offset;
}


static const ber_sequence_t ExtendedCertificateInfo_sequence[] = {
  { &hf_cms_version         , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cms_CMSVersion },
  { &hf_cms_certificate     , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_Certificate },
  { &hf_cms_attributes      , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_cms_UnauthAttributes },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_ExtendedCertificateInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ExtendedCertificateInfo_sequence, hf_index, ett_cms_ExtendedCertificateInfo);

  return offset;
}



static int
dissect_cms_SignatureAlgorithmIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_cms_Signature(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
                                    NULL);

  return offset;
}


static const ber_sequence_t ExtendedCertificate_sequence[] = {
  { &hf_cms_extendedCertificateInfo, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_ExtendedCertificateInfo },
  { &hf_cms_signatureAlgorithm, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_SignatureAlgorithmIdentifier },
  { &hf_cms_signature       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_cms_Signature },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_ExtendedCertificate(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ExtendedCertificate_sequence, hf_index, ett_cms_ExtendedCertificate);

  return offset;
}


static const value_string cms_AttCertVersionV1_vals[] = {
  {   0, "v1" },
  { 0, NULL }
};


static int
dissect_cms_AttCertVersionV1(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string cms_T_subject_vals[] = {
  {   0, "baseCertificateID" },
  {   1, "subjectName" },
  { 0, NULL }
};

static const ber_choice_t T_subject_choice[] = {
  {   0, &hf_cms_baseCertificateID, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_x509af_IssuerSerial },
  {   1, &hf_cms_subjectName     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_x509ce_GeneralNames },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_T_subject(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_subject_choice, hf_index, ett_cms_T_subject,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Attribute_sequence_of[1] = {
  { &hf_cms_attributes_v1_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_Attribute },
};

static int
dissect_cms_SEQUENCE_OF_Attribute(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Attribute_sequence_of, hf_index, ett_cms_SEQUENCE_OF_Attribute);

  return offset;
}


static const ber_sequence_t AttributeCertificateInfoV1_sequence[] = {
  { &hf_cms_version_v1      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cms_AttCertVersionV1 },
  { &hf_cms_subject         , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cms_T_subject },
  { &hf_cms_issuer_v1       , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509ce_GeneralNames },
  { &hf_cms_signature_v1    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_cms_serialNumber    , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_x509af_CertificateSerialNumber },
  { &hf_cms_attCertValidityPeriod, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AttCertValidityPeriod },
  { &hf_cms_attributes_v1   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_SEQUENCE_OF_Attribute },
  { &hf_cms_issuerUniqueID  , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509sat_UniqueIdentifier },
  { &hf_cms_extensions      , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509af_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_AttributeCertificateInfoV1(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttributeCertificateInfoV1_sequence, hf_index, ett_cms_AttributeCertificateInfoV1);

  return offset;
}



static int
dissect_cms_BIT_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
                                    NULL);

  return offset;
}


static const ber_sequence_t AttributeCertificateV1_sequence[] = {
  { &hf_cms_acInfo          , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_AttributeCertificateInfoV1 },
  { &hf_cms_signatureAlgorithm_v1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_cms_signatureValue_v1, BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_cms_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_AttributeCertificateV1(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttributeCertificateV1_sequence, hf_index, ett_cms_AttributeCertificateV1);

  return offset;
}



static int
dissect_cms_AttributeCertificateV2(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509af_AttributeCertificate(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string cms_CertificateChoices_vals[] = {
  {   0, "certificate" },
  {   1, "extendedCertificate" },
  {   2, "v1AttrCert" },
  {   3, "v2AttrCert" },
  { 0, NULL }
};

static const ber_choice_t CertificateChoices_choice[] = {
  {   0, &hf_cms_certificate     , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_Certificate },
  {   1, &hf_cms_extendedCertificate, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_cms_ExtendedCertificate },
  {   2, &hf_cms_v1AttrCert      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_cms_AttributeCertificateV1 },
  {   3, &hf_cms_v2AttrCert      , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_cms_AttributeCertificateV2 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_CertificateChoices(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CertificateChoices_choice, hf_index, ett_cms_CertificateChoices,
                                 NULL);

  return offset;
}


static const ber_sequence_t CertificateSet_set_of[1] = {
  { &hf_cms_CertificateSet_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cms_CertificateChoices },
};

static int
dissect_cms_CertificateSet(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 CertificateSet_set_of, hf_index, ett_cms_CertificateSet);

  return offset;
}



static int
dissect_cms_T_otherRevInfoFormat(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  struct cms_private_data *cms_data = cms_get_private_data(actx->pinfo);
  cms_data->object_identifier_id = NULL;

  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &cms_data->object_identifier_id);

  return offset;
}



static int
dissect_cms_T_otherRevInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  struct cms_private_data *cms_data = cms_get_private_data(actx->pinfo);
  offset=call_ber_oid_callback(cms_data->object_identifier_id, tvb, offset, actx->pinfo, tree, NULL);


  return offset;
}


static const ber_sequence_t OtherRevocationInfoFormat_sequence[] = {
  { &hf_cms_otherRevInfoFormat, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cms_T_otherRevInfoFormat },
  { &hf_cms_otherRevInfo    , BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_cms_T_otherRevInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_OtherRevocationInfoFormat(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OtherRevocationInfoFormat_sequence, hf_index, ett_cms_OtherRevocationInfoFormat);

  return offset;
}


static const value_string cms_RevocationInfoChoice_vals[] = {
  {   0, "crl" },
  {   1, "other" },
  { 0, NULL }
};

static const ber_choice_t RevocationInfoChoice_choice[] = {
  {   0, &hf_cms_crl             , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_CertificateList },
  {   1, &hf_cms_otherRIC        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_cms_OtherRevocationInfoFormat },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_RevocationInfoChoice(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RevocationInfoChoice_choice, hf_index, ett_cms_RevocationInfoChoice,
                                 NULL);

  return offset;
}


static const ber_sequence_t RevocationInfoChoices_set_of[1] = {
  { &hf_cms_RevocationInfoChoices_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cms_RevocationInfoChoice },
};

static int
dissect_cms_RevocationInfoChoices(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 RevocationInfoChoices_set_of, hf_index, ett_cms_RevocationInfoChoices);

  return offset;
}


static const ber_sequence_t IssuerAndSerialNumber_sequence[] = {
  { &hf_cms_issuer          , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_x509if_Name },
  { &hf_cms_serialNumber    , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_x509af_CertificateSerialNumber },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cms_IssuerAndSerialNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IssuerAndSerialNumber_sequence, hf_index, ett_cms_IssuerAndSerialNumber);

  return offset;
}



static int
dissect_cms_SubjectKeyIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


const value_string cms_SignerIdentifier_vals[] = {
  {   0, "issuerAndSerialNumber" },
  {   1, "subjectKeyIdentifier" },
  { 0, NULL }
};

static const ber_choice_t SignerIdentifier_choice[] = {
  {   0, &hf_cms_issuerAndSerialNumber, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_IssuerAndSerialNumber },
  {   1, &hf_cms_subjectKeyIdentifier, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_cms_SubjectKeyIdentifier },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_cms_SignerIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SignerIdentifier_choice, hf_index, ett_cms_SignerIdentifier,
                                 NULL);

  return offset;
}


static const ber_sequence_t SignedAttributes_set_of[1] = {
  { &hf_cms_SignedAttributes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_Attribute },
};

int
dissect_cms_SignedAttributes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_set_of(implicit_tag, actx, tree, tvb, offset,
                                             1, NO_BOUND, SignedAttributes_set_of, hf_index, ett_cms_SignedAttributes);

  return offset;
}



int
dissect_cms_SignatureValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t UnsignedAttributes_set_of[1] = {
  { &hf_cms_UnsignedAttributes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_Attribute },
};

int
dissect_cms_UnsignedAttributes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_set_of(implicit_tag, actx, tree, tvb, offset,
                                             1, NO_BOUND, UnsignedAttributes_set_of, hf_index, ett_cms_UnsignedAttributes);

  return offset;
}


static const ber_sequence_t SignerInfo_sequence[] = {
  { &hf_cms_version         , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cms_CMSVersion },
  { &hf_cms_sid             , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cms_SignerIdentifier },
  { &hf_cms_digestAlgorithm , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_DigestAlgorithmIdentifier },
  { &hf_cms_signedAttrs     , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cms_SignedAttributes },
  { &hf_cms_signatureAlgorithm, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_SignatureAlgorithmIdentifier },
  { &hf_cms_signatureValue  , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cms_SignatureValue },
  { &hf_cms_unsignedAttrs   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cms_UnsignedAttributes },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cms_SignerInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SignerInfo_sequence, hf_index, ett_cms_SignerInfo);

  return offset;
}


static const ber_sequence_t SignerInfos_set_of[1] = {
  { &hf_cms_SignerInfos_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_SignerInfo },
};

int
dissect_cms_SignerInfos(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SignerInfos_set_of, hf_index, ett_cms_SignerInfos);

  return offset;
}


static const ber_sequence_t SignedData_sequence[] = {
  { &hf_cms_version         , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cms_CMSVersion },
  { &hf_cms_digestAlgorithms, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_cms_DigestAlgorithmIdentifiers },
  { &hf_cms_encapContentInfo, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_EncapsulatedContentInfo },
  { &hf_cms_certificates    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cms_CertificateSet },
  { &hf_cms_crls            , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cms_RevocationInfoChoices },
  { &hf_cms_signerInfos     , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_cms_SignerInfos },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cms_SignedData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SignedData_sequence, hf_index, ett_cms_SignedData);

  return offset;
}


static const ber_sequence_t OriginatorInfo_sequence[] = {
  { &hf_cms_certs           , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cms_CertificateSet },
  { &hf_cms_crls            , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cms_RevocationInfoChoices },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_OriginatorInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OriginatorInfo_sequence, hf_index, ett_cms_OriginatorInfo);

  return offset;
}


static const value_string cms_RecipientIdentifier_vals[] = {
  {   0, "issuerAndSerialNumber" },
  {   1, "subjectKeyIdentifier" },
  { 0, NULL }
};

static const ber_choice_t RecipientIdentifier_choice[] = {
  {   0, &hf_cms_issuerAndSerialNumber, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_IssuerAndSerialNumber },
  {   1, &hf_cms_subjectKeyIdentifier, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_cms_SubjectKeyIdentifier },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_RecipientIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RecipientIdentifier_choice, hf_index, ett_cms_RecipientIdentifier,
                                 NULL);

  return offset;
}



static int
dissect_cms_KeyEncryptionAlgorithmIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_cms_EncryptedKey(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t KeyTransRecipientInfo_sequence[] = {
  { &hf_cms_version         , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cms_CMSVersion },
  { &hf_cms_rid             , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cms_RecipientIdentifier },
  { &hf_cms_keyEncryptionAlgorithm, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_KeyEncryptionAlgorithmIdentifier },
  { &hf_cms_encryptedKey    , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cms_EncryptedKey },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_KeyTransRecipientInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   KeyTransRecipientInfo_sequence, hf_index, ett_cms_KeyTransRecipientInfo);

  return offset;
}


static const ber_sequence_t OriginatorPublicKey_sequence[] = {
  { &hf_cms_algorithm       , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_cms_publicKey       , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_cms_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_OriginatorPublicKey(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OriginatorPublicKey_sequence, hf_index, ett_cms_OriginatorPublicKey);

  return offset;
}


static const value_string cms_OriginatorIdentifierOrKey_vals[] = {
  {   0, "issuerAndSerialNumber" },
  {   1, "subjectKeyIdentifier" },
  {   2, "originatorKey" },
  { 0, NULL }
};

static const ber_choice_t OriginatorIdentifierOrKey_choice[] = {
  {   0, &hf_cms_issuerAndSerialNumber, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_IssuerAndSerialNumber },
  {   1, &hf_cms_subjectKeyIdentifier, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_cms_SubjectKeyIdentifier },
  {   2, &hf_cms_originatorKey   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_cms_OriginatorPublicKey },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_OriginatorIdentifierOrKey(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 OriginatorIdentifierOrKey_choice, hf_index, ett_cms_OriginatorIdentifierOrKey,
                                 NULL);

  return offset;
}



static int
dissect_cms_UserKeyingMaterial(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_cms_GeneralizedTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_cms_T_keyAttrId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  struct cms_private_data *cms_data = cms_get_private_data(actx->pinfo);
  cms_data->object_identifier_id = NULL;

  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_cms_ci_contentType, &cms_data->object_identifier_id);

  return offset;
}



static int
dissect_cms_T_keyAttr(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  struct cms_private_data *cms_data = cms_get_private_data(actx->pinfo);
  offset=call_ber_oid_callback(cms_data->object_identifier_id, tvb, offset, actx->pinfo, tree, NULL);


  return offset;
}


static const ber_sequence_t OtherKeyAttribute_sequence[] = {
  { &hf_cms_keyAttrId       , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cms_T_keyAttrId },
  { &hf_cms_keyAttr         , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cms_T_keyAttr },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_OtherKeyAttribute(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OtherKeyAttribute_sequence, hf_index, ett_cms_OtherKeyAttribute);

  return offset;
}


static const ber_sequence_t RecipientKeyIdentifier_sequence[] = {
  { &hf_cms_subjectKeyIdentifier, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cms_SubjectKeyIdentifier },
  { &hf_cms_date            , BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cms_GeneralizedTime },
  { &hf_cms_other           , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cms_OtherKeyAttribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_RecipientKeyIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RecipientKeyIdentifier_sequence, hf_index, ett_cms_RecipientKeyIdentifier);

  return offset;
}


static const value_string cms_KeyAgreeRecipientIdentifier_vals[] = {
  {   0, "issuerAndSerialNumber" },
  {   1, "rKeyId" },
  { 0, NULL }
};

static const ber_choice_t KeyAgreeRecipientIdentifier_choice[] = {
  {   0, &hf_cms_issuerAndSerialNumber, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_IssuerAndSerialNumber },
  {   1, &hf_cms_rKeyId          , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_cms_RecipientKeyIdentifier },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_KeyAgreeRecipientIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 KeyAgreeRecipientIdentifier_choice, hf_index, ett_cms_KeyAgreeRecipientIdentifier,
                                 NULL);

  return offset;
}


static const ber_sequence_t RecipientEncryptedKey_sequence[] = {
  { &hf_cms_rekRid          , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cms_KeyAgreeRecipientIdentifier },
  { &hf_cms_encryptedKey    , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cms_EncryptedKey },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_RecipientEncryptedKey(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RecipientEncryptedKey_sequence, hf_index, ett_cms_RecipientEncryptedKey);

  return offset;
}


static const ber_sequence_t RecipientEncryptedKeys_sequence_of[1] = {
  { &hf_cms_RecipientEncryptedKeys_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_RecipientEncryptedKey },
};

static int
dissect_cms_RecipientEncryptedKeys(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      RecipientEncryptedKeys_sequence_of, hf_index, ett_cms_RecipientEncryptedKeys);

  return offset;
}


static const ber_sequence_t KeyAgreeRecipientInfo_sequence[] = {
  { &hf_cms_version         , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cms_CMSVersion },
  { &hf_cms_originator      , BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_cms_OriginatorIdentifierOrKey },
  { &hf_cms_ukm             , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_cms_UserKeyingMaterial },
  { &hf_cms_keyEncryptionAlgorithm, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_KeyEncryptionAlgorithmIdentifier },
  { &hf_cms_recipientEncryptedKeys, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_RecipientEncryptedKeys },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_KeyAgreeRecipientInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   KeyAgreeRecipientInfo_sequence, hf_index, ett_cms_KeyAgreeRecipientInfo);

  return offset;
}



static int
dissect_cms_OCTET_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t KEKIdentifier_sequence[] = {
  { &hf_cms_keyIdentifier   , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cms_OCTET_STRING },
  { &hf_cms_date            , BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cms_GeneralizedTime },
  { &hf_cms_other           , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cms_OtherKeyAttribute },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_KEKIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   KEKIdentifier_sequence, hf_index, ett_cms_KEKIdentifier);

  return offset;
}


static const ber_sequence_t KEKRecipientInfo_sequence[] = {
  { &hf_cms_version         , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cms_CMSVersion },
  { &hf_cms_kekid           , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_KEKIdentifier },
  { &hf_cms_keyEncryptionAlgorithm, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_KeyEncryptionAlgorithmIdentifier },
  { &hf_cms_encryptedKey    , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cms_EncryptedKey },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_KEKRecipientInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   KEKRecipientInfo_sequence, hf_index, ett_cms_KEKRecipientInfo);

  return offset;
}



static int
dissect_cms_KeyDerivationAlgorithmIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t PasswordRecipientInfo_sequence[] = {
  { &hf_cms_version         , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cms_CMSVersion },
  { &hf_cms_keyDerivationAlgorithm, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cms_KeyDerivationAlgorithmIdentifier },
  { &hf_cms_keyEncryptionAlgorithm, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_KeyEncryptionAlgorithmIdentifier },
  { &hf_cms_encryptedKey    , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cms_EncryptedKey },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_PasswordRecipientInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PasswordRecipientInfo_sequence, hf_index, ett_cms_PasswordRecipientInfo);

  return offset;
}



static int
dissect_cms_T_oriType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  struct cms_private_data *cms_data = cms_get_private_data(actx->pinfo);
  cms_data->object_identifier_id = NULL;

  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &cms_data->object_identifier_id);

  return offset;
}



static int
dissect_cms_T_oriValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  struct cms_private_data *cms_data = cms_get_private_data(actx->pinfo);
  offset=call_ber_oid_callback(cms_data->object_identifier_id, tvb, offset, actx->pinfo, tree, NULL);


  return offset;
}


static const ber_sequence_t OtherRecipientInfo_sequence[] = {
  { &hf_cms_oriType         , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cms_T_oriType },
  { &hf_cms_oriValue        , BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_cms_T_oriValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_OtherRecipientInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OtherRecipientInfo_sequence, hf_index, ett_cms_OtherRecipientInfo);

  return offset;
}


static const value_string cms_RecipientInfo_vals[] = {
  {   0, "ktri" },
  {   1, "kari" },
  {   2, "kekri" },
  {   3, "pwri" },
  {   4, "ori" },
  { 0, NULL }
};

static const ber_choice_t RecipientInfo_choice[] = {
  {   0, &hf_cms_ktri            , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_KeyTransRecipientInfo },
  {   1, &hf_cms_kari            , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_cms_KeyAgreeRecipientInfo },
  {   2, &hf_cms_kekri           , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_cms_KEKRecipientInfo },
  {   3, &hf_cms_pwri            , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_cms_PasswordRecipientInfo },
  {   4, &hf_cms_ori             , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_cms_OtherRecipientInfo },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_RecipientInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RecipientInfo_choice, hf_index, ett_cms_RecipientInfo,
                                 NULL);

  return offset;
}


static const ber_sequence_t RecipientInfos_set_of[1] = {
  { &hf_cms_RecipientInfos_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cms_RecipientInfo },
};

static int
dissect_cms_RecipientInfos(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_set_of(implicit_tag, actx, tree, tvb, offset,
                                             1, NO_BOUND, RecipientInfos_set_of, hf_index, ett_cms_RecipientInfos);

  return offset;
}



static int
dissect_cms_ContentEncryptionAlgorithmIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_cms_EncryptedContent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	tvbuff_t *encrypted_tvb;
	proto_item *item;
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &encrypted_tvb);

  struct cms_private_data *cms_data = cms_get_private_data(actx->pinfo);

  item = actx->created_item;

  PBE_decrypt_data(cms_data->object_identifier_id, encrypted_tvb, actx->pinfo, actx, item);

  return offset;
}


static const ber_sequence_t EncryptedContentInfo_sequence[] = {
  { &hf_cms_encryptedContentType, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cms_ContentType },
  { &hf_cms_contentEncryptionAlgorithm, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_ContentEncryptionAlgorithmIdentifier },
  { &hf_cms_encryptedContent, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cms_EncryptedContent },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_EncryptedContentInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EncryptedContentInfo_sequence, hf_index, ett_cms_EncryptedContentInfo);

  return offset;
}


static const ber_sequence_t UnprotectedAttributes_set_of[1] = {
  { &hf_cms_UnprotectedAttributes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_Attribute },
};

static int
dissect_cms_UnprotectedAttributes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_set_of(implicit_tag, actx, tree, tvb, offset,
                                             1, NO_BOUND, UnprotectedAttributes_set_of, hf_index, ett_cms_UnprotectedAttributes);

  return offset;
}


static const ber_sequence_t EnvelopedData_sequence[] = {
  { &hf_cms_version         , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cms_CMSVersion },
  { &hf_cms_originatorInfo  , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cms_OriginatorInfo },
  { &hf_cms_recipientInfos  , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_cms_RecipientInfos },
  { &hf_cms_encryptedContentInfo, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_EncryptedContentInfo },
  { &hf_cms_unprotectedAttrs, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cms_UnprotectedAttributes },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cms_EnvelopedData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EnvelopedData_sequence, hf_index, ett_cms_EnvelopedData);

  return offset;
}



int
dissect_cms_Digest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t DigestedData_sequence[] = {
  { &hf_cms_version         , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cms_CMSVersion },
  { &hf_cms_digestAlgorithm , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_DigestAlgorithmIdentifier },
  { &hf_cms_encapContentInfo, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_EncapsulatedContentInfo },
  { &hf_cms_digest          , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cms_Digest },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_DigestedData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DigestedData_sequence, hf_index, ett_cms_DigestedData);

  return offset;
}


static const ber_sequence_t EncryptedData_sequence[] = {
  { &hf_cms_version         , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cms_CMSVersion },
  { &hf_cms_encryptedContentInfo, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_EncryptedContentInfo },
  { &hf_cms_unprotectedAttrs, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cms_UnprotectedAttributes },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_EncryptedData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EncryptedData_sequence, hf_index, ett_cms_EncryptedData);

  return offset;
}



static int
dissect_cms_MessageAuthenticationCodeAlgorithm(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t AuthAttributes_set_of[1] = {
  { &hf_cms_AuthAttributes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_Attribute },
};

static int
dissect_cms_AuthAttributes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_set_of(implicit_tag, actx, tree, tvb, offset,
                                             1, NO_BOUND, AuthAttributes_set_of, hf_index, ett_cms_AuthAttributes);

  return offset;
}



static int
dissect_cms_MessageAuthenticationCode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t AuthenticatedData_sequence[] = {
  { &hf_cms_version         , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cms_CMSVersion },
  { &hf_cms_originatorInfo  , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cms_OriginatorInfo },
  { &hf_cms_recipientInfos  , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_cms_RecipientInfos },
  { &hf_cms_macAlgorithm    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_MessageAuthenticationCodeAlgorithm },
  { &hf_cms_digestAlgorithm , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cms_DigestAlgorithmIdentifier },
  { &hf_cms_encapContentInfo, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_EncapsulatedContentInfo },
  { &hf_cms_authAttrs       , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cms_AuthAttributes },
  { &hf_cms_mac             , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cms_MessageAuthenticationCode },
  { &hf_cms_unauthAttrs     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cms_UnauthAttributes },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_AuthenticatedData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AuthenticatedData_sequence, hf_index, ett_cms_AuthenticatedData);

  return offset;
}



static int
dissect_cms_MessageDigest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  struct cms_private_data *cms_data = cms_get_private_data(actx->pinfo);
  proto_item *pi;
  int old_offset = offset;

    offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);


  pi = actx->created_item;

  /* move past TLV */
  old_offset = get_ber_identifier(tvb, old_offset, NULL, NULL, NULL);
  old_offset = get_ber_length(tvb, old_offset, NULL, NULL);

  if(cms_data->content_tvb)
    cms_verify_msg_digest(pi, cms_data->content_tvb, x509af_get_last_algorithm_id(), tvb, old_offset);


  return offset;
}



static int
dissect_cms_UTCTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_UTCTime(implicit_tag, actx, tree, tvb, offset, hf_index, NULL, NULL);

  return offset;
}


static const value_string cms_Time_vals[] = {
  {   0, "utcTime" },
  {   1, "generalTime" },
  { 0, NULL }
};

static const ber_choice_t Time_choice[] = {
  {   0, &hf_cms_utcTime         , BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_NOOWNTAG, dissect_cms_UTCTime },
  {   1, &hf_cms_generalTime     , BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_cms_GeneralizedTime },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_Time(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Time_choice, hf_index, ett_cms_Time,
                                 NULL);

  return offset;
}



static int
dissect_cms_SigningTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cms_Time(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



int
dissect_cms_Countersignature(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cms_SignerInfo(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_cms_KeyWrapAlgorithm(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_cms_RC2ParameterVersion(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  uint32_t length = 0;

    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &length);


  if(cap_tree != NULL)
    proto_item_append_text(cap_tree, " (%d bits)", length);


  return offset;
}



static int
dissect_cms_RC2WrapParameter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cms_RC2ParameterVersion(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_cms_IV(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_cms_INTEGER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t RC2CBCParameter_sequence[] = {
  { &hf_cms_rc2ParameterVersion, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cms_INTEGER },
  { &hf_cms_iv              , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cms_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_RC2CBCParameter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RC2CBCParameter_sequence, hf_index, ett_cms_RC2CBCParameter);

  return offset;
}


static const ber_sequence_t DigestInfo_sequence[] = {
  { &hf_cms_digestAlgorithm , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_DigestAlgorithmIdentifier },
  { &hf_cms_digest          , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cms_Digest },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cms_DigestInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DigestInfo_sequence, hf_index, ett_cms_DigestInfo);

  return offset;
}



static int
dissect_cms_T_capability(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  struct cms_private_data *cms_data = cms_get_private_data(actx->pinfo);
  cms_data->object_identifier_id = NULL;
  const char *name = NULL;

    offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_cms_attrType, &cms_data->object_identifier_id);


  if(cms_data->object_identifier_id) {
    name = oid_resolved_from_string(actx->pinfo->pool, cms_data->object_identifier_id);
    proto_item_append_text(tree, " %s", name ? name : cms_data->object_identifier_id);
    cap_tree = tree;
  }


  return offset;
}



static int
dissect_cms_T_parameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  struct cms_private_data *cms_data = cms_get_private_data(actx->pinfo);

  offset=call_ber_oid_callback(cms_data->object_identifier_id, tvb, offset, actx->pinfo, tree, NULL);


  return offset;
}


static const ber_sequence_t SMIMECapability_sequence[] = {
  { &hf_cms_capability      , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cms_T_capability },
  { &hf_cms_parameters      , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cms_T_parameters },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_SMIMECapability(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SMIMECapability_sequence, hf_index, ett_cms_SMIMECapability);

  return offset;
}


static const ber_sequence_t SMIMECapabilities_sequence_of[1] = {
  { &hf_cms_SMIMECapabilities_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_SMIMECapability },
};

static int
dissect_cms_SMIMECapabilities(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SMIMECapabilities_sequence_of, hf_index, ett_cms_SMIMECapabilities);

  return offset;
}


static const value_string cms_SMIMEEncryptionKeyPreference_vals[] = {
  {   0, "issuerAndSerialNumber" },
  {   1, "recipientKeyId" },
  {   2, "subjectAltKeyIdentifier" },
  { 0, NULL }
};

static const ber_choice_t SMIMEEncryptionKeyPreference_choice[] = {
  {   0, &hf_cms_issuerAndSerialNumber, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_cms_IssuerAndSerialNumber },
  {   1, &hf_cms_recipientKeyId  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_cms_RecipientKeyIdentifier },
  {   2, &hf_cms_subjectAltKeyIdentifier, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_cms_SubjectKeyIdentifier },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_SMIMEEncryptionKeyPreference(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SMIMEEncryptionKeyPreference_choice, hf_index, ett_cms_SMIMEEncryptionKeyPreference,
                                 NULL);

  return offset;
}


static const value_string cms_RC2CBCParameters_vals[] = {
  {   0, "rc2WrapParameter" },
  {   1, "rc2CBCParameter" },
  { 0, NULL }
};

static const ber_choice_t RC2CBCParameters_choice[] = {
  {   0, &hf_cms_rc2WrapParameter, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cms_RC2WrapParameter },
  {   1, &hf_cms_rc2CBCParameter , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_RC2CBCParameter },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_RC2CBCParameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RC2CBCParameters_choice, hf_index, ett_cms_RC2CBCParameters,
                                 NULL);

  return offset;
}


static const ber_sequence_t AuthEnvelopedData_sequence[] = {
  { &hf_cms_version         , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cms_CMSVersion },
  { &hf_cms_originatorInfo  , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cms_OriginatorInfo },
  { &hf_cms_recipientInfos  , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_cms_RecipientInfos },
  { &hf_cms_authEncryptedContentInfo, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_EncryptedContentInfo },
  { &hf_cms_authAttrs       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cms_AuthAttributes },
  { &hf_cms_mac             , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cms_MessageAuthenticationCode },
  { &hf_cms_unauthAttrs     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cms_UnauthAttributes },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cms_AuthEnvelopedData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AuthEnvelopedData_sequence, hf_index, ett_cms_AuthEnvelopedData);

  return offset;
}



static int
dissect_cms_OCTET_STRING_SIZE_7_13(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   7, 13, hf_index, NULL);

  return offset;
}



static int
dissect_cms_AES_CCM_ICVlen(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_integer(implicit_tag, actx, tree, tvb, offset,
                                                            4U, 16U, hf_index, NULL);

  return offset;
}


static const ber_sequence_t CCMParameters_sequence[] = {
  { &hf_cms_aes_nonce       , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cms_OCTET_STRING_SIZE_7_13 },
  { &hf_cms_aes_ICVlen      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cms_AES_CCM_ICVlen },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_CCMParameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CCMParameters_sequence, hf_index, ett_cms_CCMParameters);

  return offset;
}



static int
dissect_cms_AES_GCM_ICVlen(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_integer(implicit_tag, actx, tree, tvb, offset,
                                                            12U, 16U, hf_index, NULL);

  return offset;
}


static const ber_sequence_t GCMParameters_sequence[] = {
  { &hf_cms_aes_nonce_01    , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cms_OCTET_STRING },
  { &hf_cms_aes_ICVlen_01   , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cms_AES_GCM_ICVlen },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_GCMParameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GCMParameters_sequence, hf_index, ett_cms_GCMParameters);

  return offset;
}



static int
dissect_cms_FirmwarePkgData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_cms_OBJECT_IDENTIFIER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_cms_INTEGER_0_MAX(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_integer64(implicit_tag, actx, tree, tvb, offset,
                                                            0U, NO_BOUND, hf_index, NULL);

  return offset;
}


static const ber_sequence_t PreferredPackageIdentifier_sequence[] = {
  { &hf_cms_fwPkgID         , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cms_OBJECT_IDENTIFIER },
  { &hf_cms_verNum          , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cms_INTEGER_0_MAX },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_PreferredPackageIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PreferredPackageIdentifier_sequence, hf_index, ett_cms_PreferredPackageIdentifier);

  return offset;
}


static const value_string cms_PreferredOrLegacyPackageIdentifier_vals[] = {
  {   0, "preferred" },
  {   1, "legacy" },
  { 0, NULL }
};

static const ber_choice_t PreferredOrLegacyPackageIdentifier_choice[] = {
  {   0, &hf_cms_preferred       , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_PreferredPackageIdentifier },
  {   1, &hf_cms_legacy          , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cms_OCTET_STRING },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_PreferredOrLegacyPackageIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PreferredOrLegacyPackageIdentifier_choice, hf_index, ett_cms_PreferredOrLegacyPackageIdentifier,
                                 NULL);

  return offset;
}


static const value_string cms_PreferredOrLegacyStalePackageIdentifier_vals[] = {
  {   0, "preferredStaleVerNum" },
  {   1, "legacyStaleVersion" },
  { 0, NULL }
};

static const ber_choice_t PreferredOrLegacyStalePackageIdentifier_choice[] = {
  {   0, &hf_cms_preferredStaleVerNum, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cms_INTEGER_0_MAX },
  {   1, &hf_cms_legacyStaleVersion, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cms_OCTET_STRING },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_PreferredOrLegacyStalePackageIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PreferredOrLegacyStalePackageIdentifier_choice, hf_index, ett_cms_PreferredOrLegacyStalePackageIdentifier,
                                 NULL);

  return offset;
}


static const ber_sequence_t FirmwarePackageIdentifier_sequence[] = {
  { &hf_cms_name            , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cms_PreferredOrLegacyPackageIdentifier },
  { &hf_cms_stale           , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cms_PreferredOrLegacyStalePackageIdentifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_FirmwarePackageIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   FirmwarePackageIdentifier_sequence, hf_index, ett_cms_FirmwarePackageIdentifier);

  return offset;
}


static const ber_sequence_t TargetHardwareIdentifiers_sequence_of[1] = {
  { &hf_cms_TargetHardwareIdentifiers_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cms_OBJECT_IDENTIFIER },
};

static int
dissect_cms_TargetHardwareIdentifiers(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      TargetHardwareIdentifiers_sequence_of, hf_index, ett_cms_TargetHardwareIdentifiers);

  return offset;
}



static int
dissect_cms_DecryptKeyIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t ImplementedCryptoAlgorithms_sequence_of[1] = {
  { &hf_cms_ImplementedCryptoAlgorithms_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cms_OBJECT_IDENTIFIER },
};

static int
dissect_cms_ImplementedCryptoAlgorithms(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      ImplementedCryptoAlgorithms_sequence_of, hf_index, ett_cms_ImplementedCryptoAlgorithms);

  return offset;
}


static const ber_sequence_t ImplementedCompressAlgorithms_sequence_of[1] = {
  { &hf_cms_ImplementedCompressAlgorithms_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cms_OBJECT_IDENTIFIER },
};

static int
dissect_cms_ImplementedCompressAlgorithms(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      ImplementedCompressAlgorithms_sequence_of, hf_index, ett_cms_ImplementedCompressAlgorithms);

  return offset;
}



static int
dissect_cms_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t T_block_sequence[] = {
  { &hf_cms_low             , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cms_OCTET_STRING },
  { &hf_cms_high            , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cms_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_T_block(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_block_sequence, hf_index, ett_cms_T_block);

  return offset;
}


static const value_string cms_HardwareSerialEntry_vals[] = {
  {   0, "all" },
  {   1, "single" },
  {   2, "block" },
  { 0, NULL }
};

static const ber_choice_t HardwareSerialEntry_choice[] = {
  {   0, &hf_cms_all             , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_cms_NULL },
  {   1, &hf_cms_single          , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cms_OCTET_STRING },
  {   2, &hf_cms_block           , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_T_block },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_HardwareSerialEntry(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 HardwareSerialEntry_choice, hf_index, ett_cms_HardwareSerialEntry,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_HardwareSerialEntry_sequence_of[1] = {
  { &hf_cms_hwSerialEntries_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cms_HardwareSerialEntry },
};

static int
dissect_cms_SEQUENCE_OF_HardwareSerialEntry(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_HardwareSerialEntry_sequence_of, hf_index, ett_cms_SEQUENCE_OF_HardwareSerialEntry);

  return offset;
}


static const ber_sequence_t HardwareModules_sequence[] = {
  { &hf_cms_hwType          , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cms_OBJECT_IDENTIFIER },
  { &hf_cms_hwSerialEntries , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_SEQUENCE_OF_HardwareSerialEntry },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_HardwareModules(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   HardwareModules_sequence, hf_index, ett_cms_HardwareModules);

  return offset;
}


static const value_string cms_CommunityIdentifier_vals[] = {
  {   0, "communityOID" },
  {   1, "hwModuleList" },
  { 0, NULL }
};

static const ber_choice_t CommunityIdentifier_choice[] = {
  {   0, &hf_cms_communityOID    , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cms_OBJECT_IDENTIFIER },
  {   1, &hf_cms_hwModuleList    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_HardwareModules },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_CommunityIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CommunityIdentifier_choice, hf_index, ett_cms_CommunityIdentifier,
                                 NULL);

  return offset;
}


static const ber_sequence_t CommunityIdentifiers_sequence_of[1] = {
  { &hf_cms_CommunityIdentifiers_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cms_CommunityIdentifier },
};

static int
dissect_cms_CommunityIdentifiers(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      CommunityIdentifiers_sequence_of, hf_index, ett_cms_CommunityIdentifiers);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_PreferredOrLegacyPackageIdentifier_sequence_of[1] = {
  { &hf_cms_dependencies_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cms_PreferredOrLegacyPackageIdentifier },
};

static int
dissect_cms_SEQUENCE_OF_PreferredOrLegacyPackageIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_PreferredOrLegacyPackageIdentifier_sequence_of, hf_index, ett_cms_SEQUENCE_OF_PreferredOrLegacyPackageIdentifier);

  return offset;
}


static const ber_sequence_t FirmwarePackageInfo_sequence[] = {
  { &hf_cms_fwPkgType       , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cms_INTEGER },
  { &hf_cms_dependencies    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cms_SEQUENCE_OF_PreferredOrLegacyPackageIdentifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_FirmwarePackageInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   FirmwarePackageInfo_sequence, hf_index, ett_cms_FirmwarePackageInfo);

  return offset;
}



static int
dissect_cms_WrappedFirmwareKey(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cms_EnvelopedData(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string cms_FWReceiptVersion_vals[] = {
  {   1, "v1" },
  { 0, NULL }
};


static int
dissect_cms_FWReceiptVersion(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t FirmwarePackageLoadReceipt_sequence[] = {
  { &hf_cms_fwReceiptVersion, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cms_FWReceiptVersion },
  { &hf_cms_hwType          , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cms_OBJECT_IDENTIFIER },
  { &hf_cms_hwSerialNum     , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cms_OCTET_STRING },
  { &hf_cms_fwPkgName       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cms_PreferredOrLegacyPackageIdentifier },
  { &hf_cms_trustAnchorKeyID, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cms_OCTET_STRING },
  { &hf_cms_decryptKeyID    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cms_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_FirmwarePackageLoadReceipt(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   FirmwarePackageLoadReceipt_sequence, hf_index, ett_cms_FirmwarePackageLoadReceipt);

  return offset;
}


static const value_string cms_FWErrorVersion_vals[] = {
  {   1, "v1" },
  { 0, NULL }
};


static int
dissect_cms_FWErrorVersion(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string cms_FirmwarePackageLoadErrorCode_vals[] = {
  {   1, "decodeFailure" },
  {   2, "badContentInfo" },
  {   3, "badSignedData" },
  {   4, "badEncapContent" },
  {   5, "badCertificate" },
  {   6, "badSignerInfo" },
  {   7, "badSignedAttrs" },
  {   8, "badUnsignedAttrs" },
  {   9, "missingContent" },
  {  10, "noTrustAnchor" },
  {  11, "notAuthorized" },
  {  12, "badDigestAlgorithm" },
  {  13, "badSignatureAlgorithm" },
  {  14, "unsupportedKeySize" },
  {  15, "signatureFailure" },
  {  16, "contentTypeMismatch" },
  {  17, "badEncryptedData" },
  {  18, "unprotectedAttrsPresent" },
  {  19, "badEncryptContent" },
  {  20, "badEncryptAlgorithm" },
  {  21, "missingCiphertext" },
  {  22, "noDecryptKey" },
  {  23, "decryptFailure" },
  {  24, "badCompressAlgorithm" },
  {  25, "missingCompressedContent" },
  {  26, "decompressFailure" },
  {  27, "wrongHardware" },
  {  28, "stalePackage" },
  {  29, "notInCommunity" },
  {  30, "unsupportedPackageType" },
  {  31, "missingDependency" },
  {  32, "wrongDependencyVersion" },
  {  33, "insufficientMemory" },
  {  34, "badFirmware" },
  {  35, "unsupportedParameters" },
  {  36, "breaksDependency" },
  {  99, "otherError" },
  { 0, NULL }
};


static int
dissect_cms_FirmwarePackageLoadErrorCode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_cms_VendorLoadErrorCode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t CurrentFWConfig_sequence[] = {
  { &hf_cms_fwPkgType       , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cms_INTEGER },
  { &hf_cms_fwPkgName       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cms_PreferredOrLegacyPackageIdentifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_CurrentFWConfig(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CurrentFWConfig_sequence, hf_index, ett_cms_CurrentFWConfig);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_CurrentFWConfig_sequence_of[1] = {
  { &hf_cms_config_item     , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_CurrentFWConfig },
};

static int
dissect_cms_SEQUENCE_OF_CurrentFWConfig(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_CurrentFWConfig_sequence_of, hf_index, ett_cms_SEQUENCE_OF_CurrentFWConfig);

  return offset;
}


static const ber_sequence_t FirmwarePackageLoadError_sequence[] = {
  { &hf_cms_fwErrorVersion  , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cms_FWErrorVersion },
  { &hf_cms_hwType          , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cms_OBJECT_IDENTIFIER },
  { &hf_cms_hwSerialNum     , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cms_OCTET_STRING },
  { &hf_cms_errorCode       , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_cms_FirmwarePackageLoadErrorCode },
  { &hf_cms_vendorErrorCode , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cms_VendorLoadErrorCode },
  { &hf_cms_fwPkgName       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cms_PreferredOrLegacyPackageIdentifier },
  { &hf_cms_config          , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cms_SEQUENCE_OF_CurrentFWConfig },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_FirmwarePackageLoadError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   FirmwarePackageLoadError_sequence, hf_index, ett_cms_FirmwarePackageLoadError);

  return offset;
}


static const ber_sequence_t HardwareModuleName_sequence[] = {
  { &hf_cms_hwType          , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cms_OBJECT_IDENTIFIER },
  { &hf_cms_hwSerialNum     , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cms_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_HardwareModuleName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   HardwareModuleName_sequence, hf_index, ett_cms_HardwareModuleName);

  return offset;
}


static const ber_sequence_t FirmwarePackageMessageDigest_sequence[] = {
  { &hf_cms_algorithm       , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_cms_msgDigest       , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cms_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_FirmwarePackageMessageDigest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   FirmwarePackageMessageDigest_sequence, hf_index, ett_cms_FirmwarePackageMessageDigest);

  return offset;
}

/*--- PDUs ---*/

static int dissect_ContentInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cms_ContentInfo(false, tvb, offset, &asn1_ctx, tree, hf_cms_ContentInfo_PDU);
  return offset;
}
static int dissect_ContentType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cms_ContentType(false, tvb, offset, &asn1_ctx, tree, hf_cms_ContentType_PDU);
  return offset;
}
static int dissect_SignedData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cms_SignedData(false, tvb, offset, &asn1_ctx, tree, hf_cms_SignedData_PDU);
  return offset;
}
static int dissect_EnvelopedData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cms_EnvelopedData(false, tvb, offset, &asn1_ctx, tree, hf_cms_EnvelopedData_PDU);
  return offset;
}
static int dissect_EncryptedContentInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cms_EncryptedContentInfo(false, tvb, offset, &asn1_ctx, tree, hf_cms_EncryptedContentInfo_PDU);
  return offset;
}
static int dissect_DigestedData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cms_DigestedData(false, tvb, offset, &asn1_ctx, tree, hf_cms_DigestedData_PDU);
  return offset;
}
static int dissect_EncryptedData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cms_EncryptedData(false, tvb, offset, &asn1_ctx, tree, hf_cms_EncryptedData_PDU);
  return offset;
}
static int dissect_AuthenticatedData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cms_AuthenticatedData(false, tvb, offset, &asn1_ctx, tree, hf_cms_AuthenticatedData_PDU);
  return offset;
}
static int dissect_KeyEncryptionAlgorithmIdentifier_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cms_KeyEncryptionAlgorithmIdentifier(false, tvb, offset, &asn1_ctx, tree, hf_cms_KeyEncryptionAlgorithmIdentifier_PDU);
  return offset;
}
static int dissect_IssuerAndSerialNumber_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cms_IssuerAndSerialNumber(false, tvb, offset, &asn1_ctx, tree, hf_cms_IssuerAndSerialNumber_PDU);
  return offset;
}
static int dissect_MessageDigest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cms_MessageDigest(false, tvb, offset, &asn1_ctx, tree, hf_cms_MessageDigest_PDU);
  return offset;
}
static int dissect_SigningTime_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cms_SigningTime(false, tvb, offset, &asn1_ctx, tree, hf_cms_SigningTime_PDU);
  return offset;
}
static int dissect_Countersignature_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cms_Countersignature(false, tvb, offset, &asn1_ctx, tree, hf_cms_Countersignature_PDU);
  return offset;
}
static int dissect_KeyWrapAlgorithm_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cms_KeyWrapAlgorithm(false, tvb, offset, &asn1_ctx, tree, hf_cms_KeyWrapAlgorithm_PDU);
  return offset;
}
static int dissect_RC2WrapParameter_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cms_RC2WrapParameter(false, tvb, offset, &asn1_ctx, tree, hf_cms_RC2WrapParameter_PDU);
  return offset;
}
static int dissect_IV_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cms_IV(false, tvb, offset, &asn1_ctx, tree, hf_cms_IV_PDU);
  return offset;
}
static int dissect_SMIMECapabilities_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cms_SMIMECapabilities(false, tvb, offset, &asn1_ctx, tree, hf_cms_SMIMECapabilities_PDU);
  return offset;
}
static int dissect_SMIMEEncryptionKeyPreference_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cms_SMIMEEncryptionKeyPreference(false, tvb, offset, &asn1_ctx, tree, hf_cms_SMIMEEncryptionKeyPreference_PDU);
  return offset;
}
static int dissect_RC2CBCParameters_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cms_RC2CBCParameters(false, tvb, offset, &asn1_ctx, tree, hf_cms_RC2CBCParameters_PDU);
  return offset;
}
static int dissect_AuthEnvelopedData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cms_AuthEnvelopedData(false, tvb, offset, &asn1_ctx, tree, hf_cms_AuthEnvelopedData_PDU);
  return offset;
}
static int dissect_CCMParameters_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cms_CCMParameters(false, tvb, offset, &asn1_ctx, tree, hf_cms_CCMParameters_PDU);
  return offset;
}
static int dissect_GCMParameters_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cms_GCMParameters(false, tvb, offset, &asn1_ctx, tree, hf_cms_GCMParameters_PDU);
  return offset;
}
static int dissect_FirmwarePkgData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cms_FirmwarePkgData(false, tvb, offset, &asn1_ctx, tree, hf_cms_FirmwarePkgData_PDU);
  return offset;
}
static int dissect_FirmwarePackageIdentifier_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cms_FirmwarePackageIdentifier(false, tvb, offset, &asn1_ctx, tree, hf_cms_FirmwarePackageIdentifier_PDU);
  return offset;
}
static int dissect_TargetHardwareIdentifiers_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cms_TargetHardwareIdentifiers(false, tvb, offset, &asn1_ctx, tree, hf_cms_TargetHardwareIdentifiers_PDU);
  return offset;
}
static int dissect_DecryptKeyIdentifier_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cms_DecryptKeyIdentifier(false, tvb, offset, &asn1_ctx, tree, hf_cms_DecryptKeyIdentifier_PDU);
  return offset;
}
static int dissect_ImplementedCryptoAlgorithms_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cms_ImplementedCryptoAlgorithms(false, tvb, offset, &asn1_ctx, tree, hf_cms_ImplementedCryptoAlgorithms_PDU);
  return offset;
}
static int dissect_ImplementedCompressAlgorithms_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cms_ImplementedCompressAlgorithms(false, tvb, offset, &asn1_ctx, tree, hf_cms_ImplementedCompressAlgorithms_PDU);
  return offset;
}
static int dissect_CommunityIdentifiers_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cms_CommunityIdentifiers(false, tvb, offset, &asn1_ctx, tree, hf_cms_CommunityIdentifiers_PDU);
  return offset;
}
static int dissect_FirmwarePackageInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cms_FirmwarePackageInfo(false, tvb, offset, &asn1_ctx, tree, hf_cms_FirmwarePackageInfo_PDU);
  return offset;
}
static int dissect_WrappedFirmwareKey_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cms_WrappedFirmwareKey(false, tvb, offset, &asn1_ctx, tree, hf_cms_WrappedFirmwareKey_PDU);
  return offset;
}
static int dissect_FirmwarePackageLoadReceipt_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cms_FirmwarePackageLoadReceipt(false, tvb, offset, &asn1_ctx, tree, hf_cms_FirmwarePackageLoadReceipt_PDU);
  return offset;
}
static int dissect_FirmwarePackageLoadError_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cms_FirmwarePackageLoadError(false, tvb, offset, &asn1_ctx, tree, hf_cms_FirmwarePackageLoadError_PDU);
  return offset;
}
static int dissect_HardwareModuleName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cms_HardwareModuleName(false, tvb, offset, &asn1_ctx, tree, hf_cms_HardwareModuleName_PDU);
  return offset;
}
static int dissect_FirmwarePackageMessageDigest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_cms_FirmwarePackageMessageDigest(false, tvb, offset, &asn1_ctx, tree, hf_cms_FirmwarePackageMessageDigest_PDU);
  return offset;
}


/*--- proto_register_cms ----------------------------------------------*/
void proto_register_cms(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_cms_ci_contentType,
      { "contentType", "cms.contentInfo.contentType",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_ContentInfo_PDU,
      { "ContentInfo", "cms.ContentInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_ContentType_PDU,
      { "ContentType", "cms.ContentType",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_SignedData_PDU,
      { "SignedData", "cms.SignedData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_EnvelopedData_PDU,
      { "EnvelopedData", "cms.EnvelopedData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_EncryptedContentInfo_PDU,
      { "EncryptedContentInfo", "cms.EncryptedContentInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_DigestedData_PDU,
      { "DigestedData", "cms.DigestedData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_EncryptedData_PDU,
      { "EncryptedData", "cms.EncryptedData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_AuthenticatedData_PDU,
      { "AuthenticatedData", "cms.AuthenticatedData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_KeyEncryptionAlgorithmIdentifier_PDU,
      { "KeyEncryptionAlgorithmIdentifier", "cms.KeyEncryptionAlgorithmIdentifier_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_IssuerAndSerialNumber_PDU,
      { "IssuerAndSerialNumber", "cms.IssuerAndSerialNumber_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_MessageDigest_PDU,
      { "MessageDigest", "cms.MessageDigest",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_SigningTime_PDU,
      { "SigningTime", "cms.SigningTime",
        FT_UINT32, BASE_DEC, VALS(cms_Time_vals), 0,
        NULL, HFILL }},
    { &hf_cms_Countersignature_PDU,
      { "Countersignature", "cms.Countersignature_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_KeyWrapAlgorithm_PDU,
      { "KeyWrapAlgorithm", "cms.KeyWrapAlgorithm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_RC2WrapParameter_PDU,
      { "RC2WrapParameter", "cms.RC2WrapParameter",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_IV_PDU,
      { "IV", "cms.IV",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_SMIMECapabilities_PDU,
      { "SMIMECapabilities", "cms.SMIMECapabilities",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_SMIMEEncryptionKeyPreference_PDU,
      { "SMIMEEncryptionKeyPreference", "cms.SMIMEEncryptionKeyPreference",
        FT_UINT32, BASE_DEC, VALS(cms_SMIMEEncryptionKeyPreference_vals), 0,
        NULL, HFILL }},
    { &hf_cms_RC2CBCParameters_PDU,
      { "RC2CBCParameters", "cms.RC2CBCParameters",
        FT_UINT32, BASE_DEC, VALS(cms_RC2CBCParameters_vals), 0,
        NULL, HFILL }},
    { &hf_cms_AuthEnvelopedData_PDU,
      { "AuthEnvelopedData", "cms.AuthEnvelopedData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_CCMParameters_PDU,
      { "CCMParameters", "cms.CCMParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_GCMParameters_PDU,
      { "GCMParameters", "cms.GCMParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_FirmwarePkgData_PDU,
      { "FirmwarePkgData", "cms.FirmwarePkgData",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_FirmwarePackageIdentifier_PDU,
      { "FirmwarePackageIdentifier", "cms.FirmwarePackageIdentifier_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_TargetHardwareIdentifiers_PDU,
      { "TargetHardwareIdentifiers", "cms.TargetHardwareIdentifiers",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_DecryptKeyIdentifier_PDU,
      { "DecryptKeyIdentifier", "cms.DecryptKeyIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_ImplementedCryptoAlgorithms_PDU,
      { "ImplementedCryptoAlgorithms", "cms.ImplementedCryptoAlgorithms",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_ImplementedCompressAlgorithms_PDU,
      { "ImplementedCompressAlgorithms", "cms.ImplementedCompressAlgorithms",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_CommunityIdentifiers_PDU,
      { "CommunityIdentifiers", "cms.CommunityIdentifiers",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_FirmwarePackageInfo_PDU,
      { "FirmwarePackageInfo", "cms.FirmwarePackageInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_WrappedFirmwareKey_PDU,
      { "WrappedFirmwareKey", "cms.WrappedFirmwareKey_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_FirmwarePackageLoadReceipt_PDU,
      { "FirmwarePackageLoadReceipt", "cms.FirmwarePackageLoadReceipt_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_FirmwarePackageLoadError_PDU,
      { "FirmwarePackageLoadError", "cms.FirmwarePackageLoadError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_HardwareModuleName_PDU,
      { "HardwareModuleName", "cms.HardwareModuleName_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_FirmwarePackageMessageDigest_PDU,
      { "FirmwarePackageMessageDigest", "cms.FirmwarePackageMessageDigest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_contentType,
      { "contentType", "cms.contentType",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_content,
      { "content", "cms.content_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_version,
      { "version", "cms.version",
        FT_INT32, BASE_DEC, VALS(cms_CMSVersion_vals), 0,
        "CMSVersion", HFILL }},
    { &hf_cms_digestAlgorithms,
      { "digestAlgorithms", "cms.digestAlgorithms",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DigestAlgorithmIdentifiers", HFILL }},
    { &hf_cms_encapContentInfo,
      { "encapContentInfo", "cms.encapContentInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EncapsulatedContentInfo", HFILL }},
    { &hf_cms_certificates,
      { "certificates", "cms.certificates",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CertificateSet", HFILL }},
    { &hf_cms_crls,
      { "crls", "cms.crls",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RevocationInfoChoices", HFILL }},
    { &hf_cms_signerInfos,
      { "signerInfos", "cms.signerInfos",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_DigestAlgorithmIdentifiers_item,
      { "DigestAlgorithmIdentifier", "cms.DigestAlgorithmIdentifier_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_SignerInfos_item,
      { "SignerInfo", "cms.SignerInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_eContentType,
      { "eContentType", "cms.eContentType",
        FT_OID, BASE_NONE, NULL, 0,
        "ContentType", HFILL }},
    { &hf_cms_eContent,
      { "eContent", "cms.eContent",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_sid,
      { "sid", "cms.sid",
        FT_UINT32, BASE_DEC, VALS(cms_SignerIdentifier_vals), 0,
        "SignerIdentifier", HFILL }},
    { &hf_cms_digestAlgorithm,
      { "digestAlgorithm", "cms.digestAlgorithm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DigestAlgorithmIdentifier", HFILL }},
    { &hf_cms_signedAttrs,
      { "signedAttrs", "cms.signedAttrs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SignedAttributes", HFILL }},
    { &hf_cms_signatureAlgorithm,
      { "signatureAlgorithm", "cms.signatureAlgorithm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SignatureAlgorithmIdentifier", HFILL }},
    { &hf_cms_signatureValue,
      { "signature", "cms.signature",
        FT_BYTES, BASE_NONE, NULL, 0,
        "SignatureValue", HFILL }},
    { &hf_cms_unsignedAttrs,
      { "unsignedAttrs", "cms.unsignedAttrs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UnsignedAttributes", HFILL }},
    { &hf_cms_issuerAndSerialNumber,
      { "issuerAndSerialNumber", "cms.issuerAndSerialNumber_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_subjectKeyIdentifier,
      { "subjectKeyIdentifier", "cms.subjectKeyIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_SignedAttributes_item,
      { "Attribute", "cms.Attribute_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_UnsignedAttributes_item,
      { "Attribute", "cms.Attribute_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_attrType,
      { "attrType", "cms.attrType",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_attrValues,
      { "attrValues", "cms.attrValues",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_AttributeValue", HFILL }},
    { &hf_cms_attrValues_item,
      { "AttributeValue", "cms.AttributeValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_originatorInfo,
      { "originatorInfo", "cms.originatorInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_recipientInfos,
      { "recipientInfos", "cms.recipientInfos",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_encryptedContentInfo,
      { "encryptedContentInfo", "cms.encryptedContentInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_unprotectedAttrs,
      { "unprotectedAttrs", "cms.unprotectedAttrs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UnprotectedAttributes", HFILL }},
    { &hf_cms_certs,
      { "certs", "cms.certs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CertificateSet", HFILL }},
    { &hf_cms_RecipientInfos_item,
      { "RecipientInfo", "cms.RecipientInfo",
        FT_UINT32, BASE_DEC, VALS(cms_RecipientInfo_vals), 0,
        NULL, HFILL }},
    { &hf_cms_encryptedContentType,
      { "contentType", "cms.contentType",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_contentEncryptionAlgorithm,
      { "contentEncryptionAlgorithm", "cms.contentEncryptionAlgorithm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ContentEncryptionAlgorithmIdentifier", HFILL }},
    { &hf_cms_encryptedContent,
      { "encryptedContent", "cms.encryptedContent",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_UnprotectedAttributes_item,
      { "Attribute", "cms.Attribute_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_ktri,
      { "ktri", "cms.ktri_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "KeyTransRecipientInfo", HFILL }},
    { &hf_cms_kari,
      { "kari", "cms.kari_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "KeyAgreeRecipientInfo", HFILL }},
    { &hf_cms_kekri,
      { "kekri", "cms.kekri_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "KEKRecipientInfo", HFILL }},
    { &hf_cms_pwri,
      { "pwri", "cms.pwri_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PasswordRecipientInfo", HFILL }},
    { &hf_cms_ori,
      { "ori", "cms.ori_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "OtherRecipientInfo", HFILL }},
    { &hf_cms_rid,
      { "rid", "cms.rid",
        FT_UINT32, BASE_DEC, VALS(cms_RecipientIdentifier_vals), 0,
        "RecipientIdentifier", HFILL }},
    { &hf_cms_keyEncryptionAlgorithm,
      { "keyEncryptionAlgorithm", "cms.keyEncryptionAlgorithm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "KeyEncryptionAlgorithmIdentifier", HFILL }},
    { &hf_cms_encryptedKey,
      { "encryptedKey", "cms.encryptedKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_originator,
      { "originator", "cms.originator",
        FT_UINT32, BASE_DEC, VALS(cms_OriginatorIdentifierOrKey_vals), 0,
        "OriginatorIdentifierOrKey", HFILL }},
    { &hf_cms_ukm,
      { "ukm", "cms.ukm",
        FT_BYTES, BASE_NONE, NULL, 0,
        "UserKeyingMaterial", HFILL }},
    { &hf_cms_recipientEncryptedKeys,
      { "recipientEncryptedKeys", "cms.recipientEncryptedKeys",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_originatorKey,
      { "originatorKey", "cms.originatorKey_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "OriginatorPublicKey", HFILL }},
    { &hf_cms_algorithm,
      { "algorithm", "cms.algorithm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_cms_publicKey,
      { "publicKey", "cms.publicKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_cms_RecipientEncryptedKeys_item,
      { "RecipientEncryptedKey", "cms.RecipientEncryptedKey_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_rekRid,
      { "rid", "cms.rid",
        FT_UINT32, BASE_DEC, VALS(cms_KeyAgreeRecipientIdentifier_vals), 0,
        "KeyAgreeRecipientIdentifier", HFILL }},
    { &hf_cms_rKeyId,
      { "rKeyId", "cms.rKeyId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RecipientKeyIdentifier", HFILL }},
    { &hf_cms_date,
      { "date", "cms.date",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_cms_other,
      { "other", "cms.other_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "OtherKeyAttribute", HFILL }},
    { &hf_cms_kekid,
      { "kekid", "cms.kekid_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "KEKIdentifier", HFILL }},
    { &hf_cms_keyIdentifier,
      { "keyIdentifier", "cms.keyIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_cms_keyDerivationAlgorithm,
      { "keyDerivationAlgorithm", "cms.keyDerivationAlgorithm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "KeyDerivationAlgorithmIdentifier", HFILL }},
    { &hf_cms_oriType,
      { "oriType", "cms.oriType",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_oriValue,
      { "oriValue", "cms.oriValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_digest,
      { "digest", "cms.digest",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_macAlgorithm,
      { "macAlgorithm", "cms.macAlgorithm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MessageAuthenticationCodeAlgorithm", HFILL }},
    { &hf_cms_authAttrs,
      { "authAttrs", "cms.authAttrs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AuthAttributes", HFILL }},
    { &hf_cms_mac,
      { "mac", "cms.mac",
        FT_BYTES, BASE_NONE, NULL, 0,
        "MessageAuthenticationCode", HFILL }},
    { &hf_cms_unauthAttrs,
      { "unauthAttrs", "cms.unauthAttrs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UnauthAttributes", HFILL }},
    { &hf_cms_AuthAttributes_item,
      { "Attribute", "cms.Attribute_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_UnauthAttributes_item,
      { "Attribute", "cms.Attribute_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_RevocationInfoChoices_item,
      { "RevocationInfoChoice", "cms.RevocationInfoChoice",
        FT_UINT32, BASE_DEC, VALS(cms_RevocationInfoChoice_vals), 0,
        NULL, HFILL }},
    { &hf_cms_crl,
      { "crl", "cms.crl_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertificateList", HFILL }},
    { &hf_cms_otherRIC,
      { "other", "cms.other_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "OtherRevocationInfoFormat", HFILL }},
    { &hf_cms_otherRevInfoFormat,
      { "otherRevInfoFormat", "cms.otherRevInfoFormat",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_otherRevInfo,
      { "otherRevInfo", "cms.otherRevInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_certificate,
      { "certificate", "cms.certificate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_extendedCertificate,
      { "extendedCertificate", "cms.extendedCertificate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_v1AttrCert,
      { "v1AttrCert", "cms.v1AttrCert_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeCertificateV1", HFILL }},
    { &hf_cms_v2AttrCert,
      { "v2AttrCert", "cms.v2AttrCert_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeCertificateV2", HFILL }},
    { &hf_cms_CertificateSet_item,
      { "CertificateChoices", "cms.CertificateChoices",
        FT_UINT32, BASE_DEC, VALS(cms_CertificateChoices_vals), 0,
        NULL, HFILL }},
    { &hf_cms_issuer,
      { "issuer", "cms.issuer",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "Name", HFILL }},
    { &hf_cms_serialNumber,
      { "serialNumber", "cms.serialNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        "CertificateSerialNumber", HFILL }},
    { &hf_cms_keyAttrId,
      { "keyAttrId", "cms.keyAttrId",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_keyAttr,
      { "keyAttr", "cms.keyAttr_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_utcTime,
      { "utcTime", "cms.utcTime",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_generalTime,
      { "generalTime", "cms.generalTime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_cms_rc2ParameterVersion,
      { "rc2ParameterVersion", "cms.rc2ParameterVersion",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_cms_iv,
      { "iv", "cms.iv",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_cms_extendedCertificateInfo,
      { "extendedCertificateInfo", "cms.extendedCertificateInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_signature,
      { "signature", "cms.signature",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_attributes,
      { "attributes", "cms.attributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UnauthAttributes", HFILL }},
    { &hf_cms_SMIMECapabilities_item,
      { "SMIMECapability", "cms.SMIMECapability_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_capability,
      { "capability", "cms.capability",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_parameters,
      { "parameters", "cms.parameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_recipientKeyId,
      { "recipientKeyId", "cms.recipientKeyId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RecipientKeyIdentifier", HFILL }},
    { &hf_cms_subjectAltKeyIdentifier,
      { "subjectAltKeyIdentifier", "cms.subjectAltKeyIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "SubjectKeyIdentifier", HFILL }},
    { &hf_cms_rc2WrapParameter,
      { "rc2WrapParameter", "cms.rc2WrapParameter",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_rc2CBCParameter,
      { "rc2CBCParameter", "cms.rc2CBCParameter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_authEncryptedContentInfo,
      { "authEncryptedContentInfo", "cms.authEncryptedContentInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EncryptedContentInfo", HFILL }},
    { &hf_cms_aes_nonce,
      { "aes-nonce", "cms.aes_nonce",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_7_13", HFILL }},
    { &hf_cms_aes_ICVlen,
      { "aes-ICVlen", "cms.aes_ICVlen",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AES_CCM_ICVlen", HFILL }},
    { &hf_cms_aes_nonce_01,
      { "aes-nonce", "cms.aes_nonce",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_cms_aes_ICVlen_01,
      { "aes-ICVlen", "cms.aes_ICVlen",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AES_GCM_ICVlen", HFILL }},
    { &hf_cms_acInfo,
      { "acInfo", "cms.acInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeCertificateInfoV1", HFILL }},
    { &hf_cms_signatureAlgorithm_v1,
      { "signatureAlgorithm", "cms.signatureAlgorithm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_cms_signatureValue_v1,
      { "signature", "cms.signature",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_cms_version_v1,
      { "version", "cms.version",
        FT_INT32, BASE_DEC, VALS(cms_AttCertVersionV1_vals), 0,
        "AttCertVersionV1", HFILL }},
    { &hf_cms_subject,
      { "subject", "cms.subject",
        FT_UINT32, BASE_DEC, VALS(cms_T_subject_vals), 0,
        NULL, HFILL }},
    { &hf_cms_baseCertificateID,
      { "baseCertificateID", "cms.baseCertificateID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IssuerSerial", HFILL }},
    { &hf_cms_subjectName,
      { "subjectName", "cms.subjectName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GeneralNames", HFILL }},
    { &hf_cms_issuer_v1,
      { "issuer", "cms.issuer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GeneralNames", HFILL }},
    { &hf_cms_signature_v1,
      { "signature", "cms.signature_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_cms_attCertValidityPeriod,
      { "attCertValidityPeriod", "cms.attCertValidityPeriod_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_attributes_v1,
      { "attributes", "cms.attributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Attribute", HFILL }},
    { &hf_cms_attributes_v1_item,
      { "Attribute", "cms.Attribute_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_issuerUniqueID,
      { "issuerUniqueID", "cms.issuerUniqueID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "UniqueIdentifier", HFILL }},
    { &hf_cms_extensions,
      { "extensions", "cms.extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_name,
      { "name", "cms.name",
        FT_UINT32, BASE_DEC, VALS(cms_PreferredOrLegacyPackageIdentifier_vals), 0,
        "PreferredOrLegacyPackageIdentifier", HFILL }},
    { &hf_cms_stale,
      { "stale", "cms.stale",
        FT_UINT32, BASE_DEC, VALS(cms_PreferredOrLegacyStalePackageIdentifier_vals), 0,
        "PreferredOrLegacyStalePackageIdentifier", HFILL }},
    { &hf_cms_preferred,
      { "preferred", "cms.preferred_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PreferredPackageIdentifier", HFILL }},
    { &hf_cms_legacy,
      { "legacy", "cms.legacy",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_cms_fwPkgID,
      { "fwPkgID", "cms.fwPkgID",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_cms_verNum,
      { "verNum", "cms.verNum",
        FT_UINT64, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_cms_preferredStaleVerNum,
      { "preferredStaleVerNum", "cms.preferredStaleVerNum",
        FT_UINT64, BASE_DEC, NULL, 0,
        "INTEGER_0_MAX", HFILL }},
    { &hf_cms_legacyStaleVersion,
      { "legacyStaleVersion", "cms.legacyStaleVersion",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_cms_TargetHardwareIdentifiers_item,
      { "TargetHardwareIdentifiers item", "cms.TargetHardwareIdentifiers_item",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_cms_ImplementedCryptoAlgorithms_item,
      { "ImplementedCryptoAlgorithms item", "cms.ImplementedCryptoAlgorithms_item",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_cms_ImplementedCompressAlgorithms_item,
      { "ImplementedCompressAlgorithms item", "cms.ImplementedCompressAlgorithms_item",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_cms_CommunityIdentifiers_item,
      { "CommunityIdentifier", "cms.CommunityIdentifier",
        FT_UINT32, BASE_DEC, VALS(cms_CommunityIdentifier_vals), 0,
        NULL, HFILL }},
    { &hf_cms_communityOID,
      { "communityOID", "cms.communityOID",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_cms_hwModuleList,
      { "hwModuleList", "cms.hwModuleList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "HardwareModules", HFILL }},
    { &hf_cms_hwType,
      { "hwType", "cms.hwType",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_cms_hwSerialEntries,
      { "hwSerialEntries", "cms.hwSerialEntries",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_HardwareSerialEntry", HFILL }},
    { &hf_cms_hwSerialEntries_item,
      { "HardwareSerialEntry", "cms.HardwareSerialEntry",
        FT_UINT32, BASE_DEC, VALS(cms_HardwareSerialEntry_vals), 0,
        NULL, HFILL }},
    { &hf_cms_all,
      { "all", "cms.all_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_single,
      { "single", "cms.single",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_cms_block,
      { "block", "cms.block_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_low,
      { "low", "cms.low",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_cms_high,
      { "high", "cms.high",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_cms_fwPkgType,
      { "fwPkgType", "cms.fwPkgType",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_cms_dependencies,
      { "dependencies", "cms.dependencies",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_PreferredOrLegacyPackageIdentifier", HFILL }},
    { &hf_cms_dependencies_item,
      { "PreferredOrLegacyPackageIdentifier", "cms.PreferredOrLegacyPackageIdentifier",
        FT_UINT32, BASE_DEC, VALS(cms_PreferredOrLegacyPackageIdentifier_vals), 0,
        NULL, HFILL }},
    { &hf_cms_fwReceiptVersion,
      { "version", "cms.version",
        FT_INT32, BASE_DEC, VALS(cms_FWReceiptVersion_vals), 0,
        "FWReceiptVersion", HFILL }},
    { &hf_cms_hwSerialNum,
      { "hwSerialNum", "cms.hwSerialNum",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_cms_fwPkgName,
      { "fwPkgName", "cms.fwPkgName",
        FT_UINT32, BASE_DEC, VALS(cms_PreferredOrLegacyPackageIdentifier_vals), 0,
        "PreferredOrLegacyPackageIdentifier", HFILL }},
    { &hf_cms_trustAnchorKeyID,
      { "trustAnchorKeyID", "cms.trustAnchorKeyID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_cms_decryptKeyID,
      { "decryptKeyID", "cms.decryptKeyID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_cms_fwErrorVersion,
      { "version", "cms.version",
        FT_INT32, BASE_DEC, VALS(cms_FWErrorVersion_vals), 0,
        "FWErrorVersion", HFILL }},
    { &hf_cms_errorCode,
      { "errorCode", "cms.errorCode",
        FT_UINT32, BASE_DEC, VALS(cms_FirmwarePackageLoadErrorCode_vals), 0,
        "FirmwarePackageLoadErrorCode", HFILL }},
    { &hf_cms_vendorErrorCode,
      { "vendorErrorCode", "cms.vendorErrorCode",
        FT_INT32, BASE_DEC, NULL, 0,
        "VendorLoadErrorCode", HFILL }},
    { &hf_cms_config,
      { "config", "cms.config",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_CurrentFWConfig", HFILL }},
    { &hf_cms_config_item,
      { "CurrentFWConfig", "cms.CurrentFWConfig_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_msgDigest,
      { "msgDigest", "cms.msgDigest",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
	  &ett_cms,
    &ett_cms_ContentInfo,
    &ett_cms_SignedData,
    &ett_cms_DigestAlgorithmIdentifiers,
    &ett_cms_SignerInfos,
    &ett_cms_EncapsulatedContentInfo,
    &ett_cms_SignerInfo,
    &ett_cms_SignerIdentifier,
    &ett_cms_SignedAttributes,
    &ett_cms_UnsignedAttributes,
    &ett_cms_Attribute,
    &ett_cms_SET_OF_AttributeValue,
    &ett_cms_EnvelopedData,
    &ett_cms_OriginatorInfo,
    &ett_cms_RecipientInfos,
    &ett_cms_EncryptedContentInfo,
    &ett_cms_UnprotectedAttributes,
    &ett_cms_RecipientInfo,
    &ett_cms_KeyTransRecipientInfo,
    &ett_cms_RecipientIdentifier,
    &ett_cms_KeyAgreeRecipientInfo,
    &ett_cms_OriginatorIdentifierOrKey,
    &ett_cms_OriginatorPublicKey,
    &ett_cms_RecipientEncryptedKeys,
    &ett_cms_RecipientEncryptedKey,
    &ett_cms_KeyAgreeRecipientIdentifier,
    &ett_cms_RecipientKeyIdentifier,
    &ett_cms_KEKRecipientInfo,
    &ett_cms_KEKIdentifier,
    &ett_cms_PasswordRecipientInfo,
    &ett_cms_OtherRecipientInfo,
    &ett_cms_DigestedData,
    &ett_cms_EncryptedData,
    &ett_cms_AuthenticatedData,
    &ett_cms_AuthAttributes,
    &ett_cms_UnauthAttributes,
    &ett_cms_RevocationInfoChoices,
    &ett_cms_RevocationInfoChoice,
    &ett_cms_OtherRevocationInfoFormat,
    &ett_cms_CertificateChoices,
    &ett_cms_CertificateSet,
    &ett_cms_IssuerAndSerialNumber,
    &ett_cms_OtherKeyAttribute,
    &ett_cms_Time,
    &ett_cms_RC2CBCParameter,
    &ett_cms_ExtendedCertificate,
    &ett_cms_ExtendedCertificateInfo,
    &ett_cms_DigestInfo,
    &ett_cms_SMIMECapabilities,
    &ett_cms_SMIMECapability,
    &ett_cms_SMIMEEncryptionKeyPreference,
    &ett_cms_RC2CBCParameters,
    &ett_cms_AuthEnvelopedData,
    &ett_cms_CCMParameters,
    &ett_cms_GCMParameters,
    &ett_cms_AttributeCertificateV1,
    &ett_cms_AttributeCertificateInfoV1,
    &ett_cms_T_subject,
    &ett_cms_SEQUENCE_OF_Attribute,
    &ett_cms_FirmwarePackageIdentifier,
    &ett_cms_PreferredOrLegacyPackageIdentifier,
    &ett_cms_PreferredPackageIdentifier,
    &ett_cms_PreferredOrLegacyStalePackageIdentifier,
    &ett_cms_TargetHardwareIdentifiers,
    &ett_cms_ImplementedCryptoAlgorithms,
    &ett_cms_ImplementedCompressAlgorithms,
    &ett_cms_CommunityIdentifiers,
    &ett_cms_CommunityIdentifier,
    &ett_cms_HardwareModules,
    &ett_cms_SEQUENCE_OF_HardwareSerialEntry,
    &ett_cms_HardwareSerialEntry,
    &ett_cms_T_block,
    &ett_cms_FirmwarePackageInfo,
    &ett_cms_SEQUENCE_OF_PreferredOrLegacyPackageIdentifier,
    &ett_cms_FirmwarePackageLoadReceipt,
    &ett_cms_FirmwarePackageLoadError,
    &ett_cms_SEQUENCE_OF_CurrentFWConfig,
    &ett_cms_CurrentFWConfig,
    &ett_cms_HardwareModuleName,
    &ett_cms_FirmwarePackageMessageDigest,
  };

  /* Register protocol */
  proto_cms = proto_register_protocol(PNAME, PSNAME, PFNAME);

  cms_handle = register_dissector(PFNAME, dissect_cms, proto_cms);

  /* Register fields and subtrees */
  proto_register_field_array(proto_cms, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_ber_syntax_dissector("ContentInfo", proto_cms, dissect_ContentInfo_PDU);
  register_ber_syntax_dissector("SignedData", proto_cms, dissect_SignedData_PDU);
  register_ber_oid_syntax(".p7s", NULL, "ContentInfo");
  register_ber_oid_syntax(".p7m", NULL, "ContentInfo");
  register_ber_oid_syntax(".p7c", NULL, "ContentInfo");


}


/*--- proto_reg_handoff_cms -------------------------------------------*/
void proto_reg_handoff_cms(void) {
  dissector_handle_t content_info_handle;
  register_ber_oid_dissector("1.2.840.113549.1.9.16.1.6", dissect_ContentInfo_PDU, proto_cms, "id-ct-contentInfo");
  register_ber_oid_dissector("1.2.840.113549.1.7.2", dissect_SignedData_PDU, proto_cms, "id-signedData");
  register_ber_oid_dissector("1.2.840.113549.1.7.3", dissect_EnvelopedData_PDU, proto_cms, "id-envelopedData");
  register_ber_oid_dissector("1.2.840.113549.1.7.5", dissect_DigestedData_PDU, proto_cms, "id-digestedData");
  register_ber_oid_dissector("1.2.840.113549.1.7.6", dissect_EncryptedData_PDU, proto_cms, "id-encryptedData");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.1.2", dissect_AuthenticatedData_PDU, proto_cms, "id-ct-authenticatedData");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.1.9", dissect_EncryptedContentInfo_PDU, proto_cms, "id-ct-compressedData");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.1.23", dissect_AuthEnvelopedData_PDU, proto_cms, "id-ct-authEnvelopedData");
  register_ber_oid_dissector("1.2.840.113549.1.9.3", dissect_ContentType_PDU, proto_cms, "id-contentType");
  register_ber_oid_dissector("1.2.840.113549.1.9.4", dissect_MessageDigest_PDU, proto_cms, "id-messageDigest");
  register_ber_oid_dissector("1.2.840.113549.1.9.5", dissect_SigningTime_PDU, proto_cms, "id-signingTime");
  register_ber_oid_dissector("1.2.840.113549.1.9.6", dissect_Countersignature_PDU, proto_cms, "id-counterSignature");
  register_ber_oid_dissector("2.6.1.4.18", dissect_ContentInfo_PDU, proto_cms, "id-et-pkcs7");
  register_ber_oid_dissector("1.3.6.1.4.1.311.16.4", dissect_IssuerAndSerialNumber_PDU, proto_cms, "ms-oe-encryption-key-preference");
  register_ber_oid_dissector("1.2.840.113549.1.9.15", dissect_SMIMECapabilities_PDU, proto_cms, "id-smime-capabilities");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.2.11", dissect_SMIMEEncryptionKeyPreference_PDU, proto_cms, "id-encryption-key-preference");
  register_ber_oid_dissector("1.2.840.113549.3.4", dissect_RC2CBCParameters_PDU, proto_cms, "id-alg-rc4");
  register_ber_oid_dissector("0.4.0.127.0.7.1.1.5.1.1.3", dissect_KeyEncryptionAlgorithmIdentifier_PDU, proto_cms, "ecka-eg-X963KDF-SHA256");
  register_ber_oid_dissector("0.4.0.127.0.7.1.1.5.1.1.4", dissect_KeyEncryptionAlgorithmIdentifier_PDU, proto_cms, "ecka-eg-X963KDF-SHA384");
  register_ber_oid_dissector("0.4.0.127.0.7.1.1.5.1.1.5", dissect_KeyEncryptionAlgorithmIdentifier_PDU, proto_cms, "ecka-eg-X963KDF-SHA512");
  register_ber_oid_dissector("2.16.840.1.101.3.4.1.5", dissect_KeyEncryptionAlgorithmIdentifier_PDU, proto_cms, "id-aes128-wrap");
  register_ber_oid_dissector("2.16.840.1.101.3.4.1.25", dissect_KeyEncryptionAlgorithmIdentifier_PDU, proto_cms, "id-aes192-wrap");
  register_ber_oid_dissector("2.16.840.1.101.3.4.1.45", dissect_KeyEncryptionAlgorithmIdentifier_PDU, proto_cms, "id-aes256-wrap");
  register_ber_oid_dissector("2.16.840.1.101.3.4.1.6", dissect_GCMParameters_PDU, proto_cms, "id-aes128-GCM");
  register_ber_oid_dissector("2.16.840.1.101.3.4.1.26", dissect_GCMParameters_PDU, proto_cms, "id-aes192-GCM");
  register_ber_oid_dissector("2.16.840.1.101.3.4.1.46", dissect_GCMParameters_PDU, proto_cms, "id-aes256-GCM");
  register_ber_oid_dissector("2.16.840.1.101.3.4.1.7", dissect_CCMParameters_PDU, proto_cms, "id-aes128-CCM");
  register_ber_oid_dissector("2.16.840.1.101.3.4.1.27", dissect_CCMParameters_PDU, proto_cms, "id-aes192-CCM");
  register_ber_oid_dissector("2.16.840.1.101.3.4.1.44", dissect_CCMParameters_PDU, proto_cms, "id-aes256-CCM");
  register_ber_oid_dissector("1.3.133.16.840.63.0.2", dissect_KeyWrapAlgorithm_PDU, proto_cms, "dhSinglePass-stdDH-sha1kdf-scheme");
  register_ber_oid_dissector("1.3.132.1.11.0", dissect_KeyWrapAlgorithm_PDU, proto_cms, "dhSinglePass-stdDH-sha224kdf-scheme");
  register_ber_oid_dissector("1.3.132.1.11.1", dissect_KeyWrapAlgorithm_PDU, proto_cms, "dhSinglePass-stdDH-sha256kdf-scheme");
  register_ber_oid_dissector("1.3.132.1.11.2", dissect_KeyWrapAlgorithm_PDU, proto_cms, "dhSinglePass-stdDH-sha384kdf-scheme");
  register_ber_oid_dissector("1.3.132.1.11.3", dissect_KeyWrapAlgorithm_PDU, proto_cms, "dhSinglePass-stdDH-sha512kdf-scheme");
  register_ber_oid_dissector("1.3.133.16.840.63.0.3", dissect_KeyWrapAlgorithm_PDU, proto_cms, "dhSinglePass-cofactorDH-sha1kdf-scheme");
  register_ber_oid_dissector("1.3.132.1.14.0", dissect_KeyWrapAlgorithm_PDU, proto_cms, "dhSinglePass-cofactorDH-sha224kdf-scheme");
  register_ber_oid_dissector("1.3.132.1.14.1", dissect_KeyWrapAlgorithm_PDU, proto_cms, "dhSinglePass-cofactorDH-sha256kdf-scheme");
  register_ber_oid_dissector("1.3.132.1.14.2", dissect_KeyWrapAlgorithm_PDU, proto_cms, "dhSinglePass-cofactorDH-sha384kdf-scheme");
  register_ber_oid_dissector("1.3.132.1.14.3", dissect_KeyWrapAlgorithm_PDU, proto_cms, "dhSinglePass-cofactorDH-sha512kdf-scheme");
  register_ber_oid_dissector("1.3.133.16.840.63.0.16", dissect_KeyWrapAlgorithm_PDU, proto_cms, "mqvSinglePass-sha1kdf-scheme");
  register_ber_oid_dissector("1.3.132.1.15.0", dissect_KeyWrapAlgorithm_PDU, proto_cms, "mqvSinglePass-sha224kdf-scheme");
  register_ber_oid_dissector("1.3.132.1.15.1", dissect_KeyWrapAlgorithm_PDU, proto_cms, "mqvSinglePass-sha256kdf-scheme");
  register_ber_oid_dissector("1.3.132.1.15.2", dissect_KeyWrapAlgorithm_PDU, proto_cms, "mqvSinglePass-sha384kdf-scheme");
  register_ber_oid_dissector("1.3.132.1.15.3", dissect_KeyWrapAlgorithm_PDU, proto_cms, "mqvSinglePass-sha512kdf-scheme");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.3.7", dissect_RC2WrapParameter_PDU, proto_cms, "id-alg-CMSRC2-wrap");
  register_ber_oid_dissector("1.2.840.113549.3.7", dissect_IV_PDU, proto_cms, "des-ede3-cbc");
  register_ber_oid_dissector("1.2.840.113549.3.2", dissect_RC2CBCParameters_PDU, proto_cms, "rc2-cbc");
  register_ber_oid_dissector("2.16.840.1.113730.3.1.40", dissect_SignedData_PDU, proto_cms, "userSMIMECertificate");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.1.16", dissect_FirmwarePkgData_PDU, proto_cms, "id-ct-firmwarePackage");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.2.35", dissect_FirmwarePackageIdentifier_PDU, proto_cms, "id-aa-firmwarePackageID");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.2.36", dissect_TargetHardwareIdentifiers_PDU, proto_cms, "id-aa-targetHardwareIDs");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.2.37", dissect_DecryptKeyIdentifier_PDU, proto_cms, "id-aa-decryptKeyID");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.2.38", dissect_ImplementedCryptoAlgorithms_PDU, proto_cms, "id-aa-implCryptoAlgs");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.2.43", dissect_ImplementedCompressAlgorithms_PDU, proto_cms, "id-aa-implCompressAlgs");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.2.40", dissect_CommunityIdentifiers_PDU, proto_cms, "id-aa-communityIdentifiers");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.2.42", dissect_FirmwarePackageInfo_PDU, proto_cms, "id-aa-firmwarePackageInfo");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.2.39", dissect_WrappedFirmwareKey_PDU, proto_cms, "id-aa-wrappedFirmwareKey");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.1.17", dissect_FirmwarePackageLoadReceipt_PDU, proto_cms, "id-ct-firmwareLoadReceipt");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.1.18", dissect_FirmwarePackageLoadError_PDU, proto_cms, "id-ct-firmwareLoadError");
  register_ber_oid_dissector("1.3.6.1.5.5.7.8.4", dissect_HardwareModuleName_PDU, proto_cms, "id-on-hardwareModuleName");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.2.41", dissect_FirmwarePackageMessageDigest_PDU, proto_cms, "id-aa-fwPkgMessageDigest");


  /* RFC 3370 [CMS-ASN} section 4.3.1 */
  register_ber_oid_dissector("1.2.840.113549.1.9.16.3.6", dissect_ber_oid_NULL_callback, proto_cms, "id-alg-CMS3DESwrap");

  oid_add_from_string("id-data","1.2.840.113549.1.7.1");
  oid_add_from_string("id-alg-des-ede3-cbc","1.2.840.113549.3.7");
  oid_add_from_string("id-alg-des-cbc","1.3.14.3.2.7");

  oid_add_from_string("id-ct-authEnvelopedData","1.2.840.113549.1.9.16.1.23");
  oid_add_from_string("id-aes-CBC-CMAC-128","0.4.0.127.0.7.1.3.1.1.2");
  oid_add_from_string("id-aes-CBC-CMAC-192","0.4.0.127.0.7.1.3.1.1.3");
  oid_add_from_string("id-aes-CBC-CMAC-256","0.4.0.127.0.7.1.3.1.1.4");
  oid_add_from_string("ecdsaWithSHA256","1.2.840.10045.4.3.2");
  oid_add_from_string("ecdsaWithSHA384","1.2.840.10045.4.3.3");
  oid_add_from_string("ecdsaWithSHA512","1.2.840.10045.4.3.4");

  content_info_handle = create_dissector_handle (dissect_ContentInfo_PDU, proto_cms);

  dissector_add_string("media_type", "application/pkcs7-mime", content_info_handle);
  dissector_add_string("media_type", "application/pkcs7-signature", content_info_handle);

  dissector_add_string("media_type", "application/vnd.de-dke-k461-ic1+xml", content_info_handle);
  dissector_add_string("media_type", "application/vnd.de-dke-k461-ic1+xml; encap=cms-tr03109", content_info_handle);
  dissector_add_string("media_type", "application/vnd.de-dke-k461-ic1+xml; encap=cms-tr03109-zlib", content_info_handle);
  dissector_add_string("media_type", "application/hgp;encap=cms", content_info_handle);
}
