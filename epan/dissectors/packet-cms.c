/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-cms.c                                                               */
/* ../../tools/asn2wrs.py -b -C -p cms -c ./cms.cnf -s ./packet-cms-template -D . -O ../../epan/dissectors CryptographicMessageSyntax.asn AttributeCertificateVersion1.asn */

/* Input file: packet-cms-template.c */

#line 1 "../../asn1/cms/packet-cms-template.c"
/* packet-cms.c
 * Routines for RFC5652 Cryptographic Message Syntax packet dissection
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
#include <epan/packet.h>
#include <epan/oids.h>
#include <epan/asn1.h>

#include <string.h>

#include "packet-ber.h"
#include "packet-cms.h"
#include "packet-x509af.h"
#include "packet-x509ce.h"
#include "packet-x509if.h"
#include "packet-x509sat.h"
#include "packet-pkcs12.h"

#include <epan/crypt/sha1.h>
#include <epan/crypt/md5.h>

#define PNAME  "Cryptographic Message Syntax"
#define PSNAME "CMS"
#define PFNAME "cms"

/* Initialize the protocol and registered fields */
static int proto_cms = -1;
static int hf_cms_ci_contentType = -1;

/*--- Included file: packet-cms-hf.c ---*/
#line 1 "../../asn1/cms/packet-cms-hf.c"
static int hf_cms_ContentInfo_PDU = -1;           /* ContentInfo */
static int hf_cms_ContentType_PDU = -1;           /* ContentType */
static int hf_cms_SignedData_PDU = -1;            /* SignedData */
static int hf_cms_EnvelopedData_PDU = -1;         /* EnvelopedData */
static int hf_cms_DigestedData_PDU = -1;          /* DigestedData */
static int hf_cms_EncryptedData_PDU = -1;         /* EncryptedData */
static int hf_cms_AuthenticatedData_PDU = -1;     /* AuthenticatedData */
static int hf_cms_IssuerAndSerialNumber_PDU = -1;  /* IssuerAndSerialNumber */
static int hf_cms_MessageDigest_PDU = -1;         /* MessageDigest */
static int hf_cms_SigningTime_PDU = -1;           /* SigningTime */
static int hf_cms_Countersignature_PDU = -1;      /* Countersignature */
static int hf_cms_RC2WrapParameter_PDU = -1;      /* RC2WrapParameter */
static int hf_cms_SMIMECapabilities_PDU = -1;     /* SMIMECapabilities */
static int hf_cms_SMIMEEncryptionKeyPreference_PDU = -1;  /* SMIMEEncryptionKeyPreference */
static int hf_cms_RC2CBCParameters_PDU = -1;      /* RC2CBCParameters */
static int hf_cms_contentType = -1;               /* ContentType */
static int hf_cms_content = -1;                   /* T_content */
static int hf_cms_version = -1;                   /* CMSVersion */
static int hf_cms_digestAlgorithms = -1;          /* DigestAlgorithmIdentifiers */
static int hf_cms_encapContentInfo = -1;          /* EncapsulatedContentInfo */
static int hf_cms_certificates = -1;              /* CertificateSet */
static int hf_cms_crls = -1;                      /* RevocationInfoChoices */
static int hf_cms_signerInfos = -1;               /* SignerInfos */
static int hf_cms_DigestAlgorithmIdentifiers_item = -1;  /* DigestAlgorithmIdentifier */
static int hf_cms_SignerInfos_item = -1;          /* SignerInfo */
static int hf_cms_eContentType = -1;              /* ContentType */
static int hf_cms_eContent = -1;                  /* T_eContent */
static int hf_cms_sid = -1;                       /* SignerIdentifier */
static int hf_cms_digestAlgorithm = -1;           /* DigestAlgorithmIdentifier */
static int hf_cms_signedAttrs = -1;               /* SignedAttributes */
static int hf_cms_signatureAlgorithm = -1;        /* SignatureAlgorithmIdentifier */
static int hf_cms_signatureValue = -1;            /* SignatureValue */
static int hf_cms_unsignedAttrs = -1;             /* UnsignedAttributes */
static int hf_cms_issuerAndSerialNumber = -1;     /* IssuerAndSerialNumber */
static int hf_cms_subjectKeyIdentifier = -1;      /* SubjectKeyIdentifier */
static int hf_cms_SignedAttributes_item = -1;     /* Attribute */
static int hf_cms_UnsignedAttributes_item = -1;   /* Attribute */
static int hf_cms_attrType = -1;                  /* T_attrType */
static int hf_cms_attrValues = -1;                /* SET_OF_AttributeValue */
static int hf_cms_attrValues_item = -1;           /* AttributeValue */
static int hf_cms_originatorInfo = -1;            /* OriginatorInfo */
static int hf_cms_recipientInfos = -1;            /* RecipientInfos */
static int hf_cms_encryptedContentInfo = -1;      /* EncryptedContentInfo */
static int hf_cms_unprotectedAttrs = -1;          /* UnprotectedAttributes */
static int hf_cms_certs = -1;                     /* CertificateSet */
static int hf_cms_RecipientInfos_item = -1;       /* RecipientInfo */
static int hf_cms_encryptedContentType = -1;      /* ContentType */
static int hf_cms_contentEncryptionAlgorithm = -1;  /* ContentEncryptionAlgorithmIdentifier */
static int hf_cms_encryptedContent = -1;          /* EncryptedContent */
static int hf_cms_UnprotectedAttributes_item = -1;  /* Attribute */
static int hf_cms_ktri = -1;                      /* KeyTransRecipientInfo */
static int hf_cms_kari = -1;                      /* KeyAgreeRecipientInfo */
static int hf_cms_kekri = -1;                     /* KEKRecipientInfo */
static int hf_cms_pwri = -1;                      /* PasswordRecipientInfo */
static int hf_cms_ori = -1;                       /* OtherRecipientInfo */
static int hf_cms_rid = -1;                       /* RecipientIdentifier */
static int hf_cms_keyEncryptionAlgorithm = -1;    /* KeyEncryptionAlgorithmIdentifier */
static int hf_cms_encryptedKey = -1;              /* EncryptedKey */
static int hf_cms_originator = -1;                /* OriginatorIdentifierOrKey */
static int hf_cms_ukm = -1;                       /* UserKeyingMaterial */
static int hf_cms_recipientEncryptedKeys = -1;    /* RecipientEncryptedKeys */
static int hf_cms_originatorKey = -1;             /* OriginatorPublicKey */
static int hf_cms_algorithm = -1;                 /* AlgorithmIdentifier */
static int hf_cms_publicKey = -1;                 /* BIT_STRING */
static int hf_cms_RecipientEncryptedKeys_item = -1;  /* RecipientEncryptedKey */
static int hf_cms_rekRid = -1;                    /* KeyAgreeRecipientIdentifier */
static int hf_cms_rKeyId = -1;                    /* RecipientKeyIdentifier */
static int hf_cms_date = -1;                      /* GeneralizedTime */
static int hf_cms_other = -1;                     /* OtherKeyAttribute */
static int hf_cms_kekid = -1;                     /* KEKIdentifier */
static int hf_cms_keyIdentifier = -1;             /* OCTET_STRING */
static int hf_cms_keyDerivationAlgorithm = -1;    /* KeyDerivationAlgorithmIdentifier */
static int hf_cms_oriType = -1;                   /* T_oriType */
static int hf_cms_oriValue = -1;                  /* T_oriValue */
static int hf_cms_digest = -1;                    /* Digest */
static int hf_cms_macAlgorithm = -1;              /* MessageAuthenticationCodeAlgorithm */
static int hf_cms_authAttrs = -1;                 /* AuthAttributes */
static int hf_cms_mac = -1;                       /* MessageAuthenticationCode */
static int hf_cms_unauthAttrs = -1;               /* UnauthAttributes */
static int hf_cms_AuthAttributes_item = -1;       /* Attribute */
static int hf_cms_UnauthAttributes_item = -1;     /* Attribute */
static int hf_cms_RevocationInfoChoices_item = -1;  /* RevocationInfoChoice */
static int hf_cms_crl = -1;                       /* CertificateList */
static int hf_cms_otherRIC = -1;                  /* OtherRevocationInfoFormat */
static int hf_cms_otherRevInfoFormat = -1;        /* T_otherRevInfoFormat */
static int hf_cms_otherRevInfo = -1;              /* T_otherRevInfo */
static int hf_cms_certificate = -1;               /* Certificate */
static int hf_cms_extendedCertificate = -1;       /* ExtendedCertificate */
static int hf_cms_v1AttrCert = -1;                /* AttributeCertificateV1 */
static int hf_cms_v2AttrCert = -1;                /* AttributeCertificateV2 */
static int hf_cms_CertificateSet_item = -1;       /* CertificateChoices */
static int hf_cms_issuer = -1;                    /* Name */
static int hf_cms_serialNumber = -1;              /* CertificateSerialNumber */
static int hf_cms_keyAttrId = -1;                 /* T_keyAttrId */
static int hf_cms_keyAttr = -1;                   /* T_keyAttr */
static int hf_cms_utcTime = -1;                   /* UTCTime */
static int hf_cms_generalTime = -1;               /* GeneralizedTime */
static int hf_cms_rc2ParameterVersion = -1;       /* INTEGER */
static int hf_cms_iv = -1;                        /* OCTET_STRING */
static int hf_cms_extendedCertificateInfo = -1;   /* ExtendedCertificateInfo */
static int hf_cms_signature = -1;                 /* Signature */
static int hf_cms_attributes = -1;                /* UnauthAttributes */
static int hf_cms_SMIMECapabilities_item = -1;    /* SMIMECapability */
static int hf_cms_capability = -1;                /* T_capability */
static int hf_cms_parameters = -1;                /* T_parameters */
static int hf_cms_recipientKeyId = -1;            /* RecipientKeyIdentifier */
static int hf_cms_subjectAltKeyIdentifier = -1;   /* SubjectKeyIdentifier */
static int hf_cms_rc2WrapParameter = -1;          /* RC2WrapParameter */
static int hf_cms_rc2CBCParameter = -1;           /* RC2CBCParameter */
static int hf_cms_acInfo = -1;                    /* AttributeCertificateInfoV1 */
static int hf_cms_signatureAlgorithm_v1 = -1;     /* AlgorithmIdentifier */
static int hf_cms_signatureValue_v1 = -1;         /* BIT_STRING */
static int hf_cms_version_v1 = -1;                /* AttCertVersionV1 */
static int hf_cms_subject = -1;                   /* T_subject */
static int hf_cms_baseCertificateID = -1;         /* IssuerSerial */
static int hf_cms_subjectName = -1;               /* GeneralNames */
static int hf_cms_issuer_v1 = -1;                 /* GeneralNames */
static int hf_cms_signature_v1 = -1;              /* AlgorithmIdentifier */
static int hf_cms_attCertValidityPeriod = -1;     /* AttCertValidityPeriod */
static int hf_cms_attributes_v1 = -1;             /* SEQUENCE_OF_Attribute */
static int hf_cms_attributes_v1_item = -1;        /* Attribute */
static int hf_cms_issuerUniqueID = -1;            /* UniqueIdentifier */
static int hf_cms_extensions = -1;                /* Extensions */

/*--- End of included file: packet-cms-hf.c ---*/
#line 55 "../../asn1/cms/packet-cms-template.c"

/* Initialize the subtree pointers */

/*--- Included file: packet-cms-ett.c ---*/
#line 1 "../../asn1/cms/packet-cms-ett.c"
static gint ett_cms_ContentInfo = -1;
static gint ett_cms_SignedData = -1;
static gint ett_cms_DigestAlgorithmIdentifiers = -1;
static gint ett_cms_SignerInfos = -1;
static gint ett_cms_EncapsulatedContentInfo = -1;
static gint ett_cms_SignerInfo = -1;
static gint ett_cms_SignerIdentifier = -1;
static gint ett_cms_SignedAttributes = -1;
static gint ett_cms_UnsignedAttributes = -1;
static gint ett_cms_Attribute = -1;
static gint ett_cms_SET_OF_AttributeValue = -1;
static gint ett_cms_EnvelopedData = -1;
static gint ett_cms_OriginatorInfo = -1;
static gint ett_cms_RecipientInfos = -1;
static gint ett_cms_EncryptedContentInfo = -1;
static gint ett_cms_UnprotectedAttributes = -1;
static gint ett_cms_RecipientInfo = -1;
static gint ett_cms_KeyTransRecipientInfo = -1;
static gint ett_cms_RecipientIdentifier = -1;
static gint ett_cms_KeyAgreeRecipientInfo = -1;
static gint ett_cms_OriginatorIdentifierOrKey = -1;
static gint ett_cms_OriginatorPublicKey = -1;
static gint ett_cms_RecipientEncryptedKeys = -1;
static gint ett_cms_RecipientEncryptedKey = -1;
static gint ett_cms_KeyAgreeRecipientIdentifier = -1;
static gint ett_cms_RecipientKeyIdentifier = -1;
static gint ett_cms_KEKRecipientInfo = -1;
static gint ett_cms_KEKIdentifier = -1;
static gint ett_cms_PasswordRecipientInfo = -1;
static gint ett_cms_OtherRecipientInfo = -1;
static gint ett_cms_DigestedData = -1;
static gint ett_cms_EncryptedData = -1;
static gint ett_cms_AuthenticatedData = -1;
static gint ett_cms_AuthAttributes = -1;
static gint ett_cms_UnauthAttributes = -1;
static gint ett_cms_RevocationInfoChoices = -1;
static gint ett_cms_RevocationInfoChoice = -1;
static gint ett_cms_OtherRevocationInfoFormat = -1;
static gint ett_cms_CertificateChoices = -1;
static gint ett_cms_CertificateSet = -1;
static gint ett_cms_IssuerAndSerialNumber = -1;
static gint ett_cms_OtherKeyAttribute = -1;
static gint ett_cms_Time = -1;
static gint ett_cms_RC2CBCParameter = -1;
static gint ett_cms_ExtendedCertificate = -1;
static gint ett_cms_ExtendedCertificateInfo = -1;
static gint ett_cms_SMIMECapabilities = -1;
static gint ett_cms_SMIMECapability = -1;
static gint ett_cms_SMIMEEncryptionKeyPreference = -1;
static gint ett_cms_RC2CBCParameters = -1;
static gint ett_cms_AttributeCertificateV1 = -1;
static gint ett_cms_AttributeCertificateInfoV1 = -1;
static gint ett_cms_T_subject = -1;
static gint ett_cms_SEQUENCE_OF_Attribute = -1;

/*--- End of included file: packet-cms-ett.c ---*/
#line 58 "../../asn1/cms/packet-cms-template.c"

static int dissect_cms_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_) ; /* XXX kill a compiler warning until asn2wrs stops generating these silly wrappers */


static const char *object_identifier_id;
static tvbuff_t *content_tvb = NULL;

static proto_tree *top_tree=NULL;
static proto_tree *cap_tree=NULL;

#define HASH_SHA1 "1.3.14.3.2.26"
#define SHA1_BUFFER_SIZE  20

#define HASH_MD5 "1.2.840.113549.2.5"
#define MD5_BUFFER_SIZE  16


/* SHA-2 variants */
#define HASH_SHA224 "2.16.840.1.101.3.4.2.4"
#define SHA224_BUFFER_SIZE  32 /* actually 28 */
#define HASH_SHA256 "2.16.840.1.101.3.4.2.1"
#define SHA256_BUFFER_SIZE  32

unsigned char digest_buf[MAX(SHA1_BUFFER_SIZE, MD5_BUFFER_SIZE)];

static void
cms_verify_msg_digest(proto_item *pi, tvbuff_t *content, const char *alg, tvbuff_t *tvb, int offset)
{
  sha1_context sha1_ctx;
  md5_state_t md5_ctx;
  int i= 0, buffer_size = 0;

  /* we only support two algorithms at the moment  - if we do add SHA2
     we should add a registration process to use a registration process */

  if(strcmp(alg, HASH_SHA1) == 0) {

    sha1_starts(&sha1_ctx);

    sha1_update(&sha1_ctx, tvb_get_ptr(content, 0, tvb_length(content)),
		tvb_length(content));

    sha1_finish(&sha1_ctx, digest_buf);

    buffer_size = SHA1_BUFFER_SIZE;

  } else if(strcmp(alg, HASH_MD5) == 0) {

    md5_init(&md5_ctx);

    md5_append(&md5_ctx, tvb_get_ptr(content, 0, tvb_length(content)),
	       tvb_length(content));

    md5_finish(&md5_ctx, digest_buf);

    buffer_size = MD5_BUFFER_SIZE;
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


/*--- Included file: packet-cms-fn.c ---*/
#line 1 "../../asn1/cms/packet-cms-fn.c"


int
dissect_cms_ContentType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 87 "../../asn1/cms/cms.cnf"
  	const char *name = NULL;

	  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &object_identifier_id);


	if(object_identifier_id) {
		name = oid_resolved_from_string(object_identifier_id);
		proto_item_append_text(tree, " (%s)", name ? name : object_identifier_id);
	}



  return offset;
}



static int
dissect_cms_T_content(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 97 "../../asn1/cms/cms.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);




  return offset;
}


static const ber_sequence_t ContentInfo_sequence[] = {
  { &hf_cms_contentType     , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cms_ContentType },
  { &hf_cms_content         , BER_CLASS_CON, 0, 0, dissect_cms_T_content },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cms_ContentInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 78 "../../asn1/cms/cms.cnf"
  top_tree = tree;
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ContentInfo_sequence, hf_index, ett_cms_ContentInfo);

  content_tvb = NULL;
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
dissect_cms_CMSVersion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



int
dissect_cms_DigestAlgorithmIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t DigestAlgorithmIdentifiers_set_of[1] = {
  { &hf_cms_DigestAlgorithmIdentifiers_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_DigestAlgorithmIdentifier },
};

int
dissect_cms_DigestAlgorithmIdentifiers(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 DigestAlgorithmIdentifiers_set_of, hf_index, ett_cms_DigestAlgorithmIdentifiers);

  return offset;
}



static int
dissect_cms_T_eContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 101 "../../asn1/cms/cms.cnf"

  offset = dissect_ber_octet_string(FALSE, actx, tree, tvb, offset, hf_index, &content_tvb);
  proto_item_set_text(actx->created_item, "eContent (%u bytes)", tvb_length (content_tvb));

  call_ber_oid_callback(object_identifier_id, content_tvb, 0, actx->pinfo, top_tree ? top_tree : tree);



  return offset;
}


static const ber_sequence_t EncapsulatedContentInfo_sequence[] = {
  { &hf_cms_eContentType    , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cms_ContentType },
  { &hf_cms_eContent        , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_cms_T_eContent },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_cms_EncapsulatedContentInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EncapsulatedContentInfo_sequence, hf_index, ett_cms_EncapsulatedContentInfo);

  return offset;
}



static int
dissect_cms_T_attrType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 128 "../../asn1/cms/cms.cnf"
  const char *name = NULL;

    offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_cms_attrType, &object_identifier_id);


  if(object_identifier_id) {
    name = oid_resolved_from_string(object_identifier_id);
    proto_item_append_text(tree, " (%s)", name ? name : object_identifier_id);
  }



  return offset;
}



static int
dissect_cms_AttributeValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 138 "../../asn1/cms/cms.cnf"

  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);



  return offset;
}


static const ber_sequence_t SET_OF_AttributeValue_set_of[1] = {
  { &hf_cms_attrValues_item , BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_cms_AttributeValue },
};

static int
dissect_cms_SET_OF_AttributeValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cms_Attribute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Attribute_sequence, hf_index, ett_cms_Attribute);

  return offset;
}


static const ber_sequence_t UnauthAttributes_set_of[1] = {
  { &hf_cms_UnauthAttributes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_Attribute },
};

static int
dissect_cms_UnauthAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cms_ExtendedCertificateInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ExtendedCertificateInfo_sequence, hf_index, ett_cms_ExtendedCertificateInfo);

  return offset;
}



static int
dissect_cms_SignatureAlgorithmIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_cms_Signature(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
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
dissect_cms_ExtendedCertificate(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ExtendedCertificate_sequence, hf_index, ett_cms_ExtendedCertificate);

  return offset;
}


static const value_string cms_AttCertVersionV1_vals[] = {
  {   0, "v1" },
  { 0, NULL }
};


static int
dissect_cms_AttCertVersionV1(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cms_T_subject(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_subject_choice, hf_index, ett_cms_T_subject,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Attribute_sequence_of[1] = {
  { &hf_cms_attributes_v1_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_Attribute },
};

static int
dissect_cms_SEQUENCE_OF_Attribute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cms_AttributeCertificateInfoV1(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttributeCertificateInfoV1_sequence, hf_index, ett_cms_AttributeCertificateInfoV1);

  return offset;
}



static int
dissect_cms_BIT_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
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
dissect_cms_AttributeCertificateV1(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AttributeCertificateV1_sequence, hf_index, ett_cms_AttributeCertificateV1);

  return offset;
}



static int
dissect_cms_AttributeCertificateV2(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cms_CertificateChoices(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CertificateChoices_choice, hf_index, ett_cms_CertificateChoices,
                                 NULL);

  return offset;
}


static const ber_sequence_t CertificateSet_set_of[1] = {
  { &hf_cms_CertificateSet_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cms_CertificateChoices },
};

static int
dissect_cms_CertificateSet(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 CertificateSet_set_of, hf_index, ett_cms_CertificateSet);

  return offset;
}



static int
dissect_cms_T_otherRevInfoFormat(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &object_identifier_id);

  return offset;
}



static int
dissect_cms_T_otherRevInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 122 "../../asn1/cms/cms.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);



  return offset;
}


static const ber_sequence_t OtherRevocationInfoFormat_sequence[] = {
  { &hf_cms_otherRevInfoFormat, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cms_T_otherRevInfoFormat },
  { &hf_cms_otherRevInfo    , BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_cms_T_otherRevInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_OtherRevocationInfoFormat(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cms_RevocationInfoChoice(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RevocationInfoChoice_choice, hf_index, ett_cms_RevocationInfoChoice,
                                 NULL);

  return offset;
}


static const ber_sequence_t RevocationInfoChoices_set_of[1] = {
  { &hf_cms_RevocationInfoChoices_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cms_RevocationInfoChoice },
};

static int
dissect_cms_RevocationInfoChoices(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cms_IssuerAndSerialNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IssuerAndSerialNumber_sequence, hf_index, ett_cms_IssuerAndSerialNumber);

  return offset;
}



static int
dissect_cms_SubjectKeyIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cms_SignerIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SignerIdentifier_choice, hf_index, ett_cms_SignerIdentifier,
                                 NULL);

  return offset;
}


static const ber_sequence_t SignedAttributes_set_of[1] = {
  { &hf_cms_SignedAttributes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_Attribute },
};

int
dissect_cms_SignedAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_set_of(implicit_tag, actx, tree, tvb, offset,
                                             1, NO_BOUND, SignedAttributes_set_of, hf_index, ett_cms_SignedAttributes);

  return offset;
}



int
dissect_cms_SignatureValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t UnsignedAttributes_set_of[1] = {
  { &hf_cms_UnsignedAttributes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_Attribute },
};

int
dissect_cms_UnsignedAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cms_SignerInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SignerInfo_sequence, hf_index, ett_cms_SignerInfo);

  return offset;
}


static const ber_sequence_t SignerInfos_set_of[1] = {
  { &hf_cms_SignerInfos_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_SignerInfo },
};

int
dissect_cms_SignerInfos(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cms_SignedData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cms_OriginatorInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cms_RecipientIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RecipientIdentifier_choice, hf_index, ett_cms_RecipientIdentifier,
                                 NULL);

  return offset;
}



static int
dissect_cms_KeyEncryptionAlgorithmIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_cms_EncryptedKey(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cms_KeyTransRecipientInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cms_OriginatorPublicKey(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cms_OriginatorIdentifierOrKey(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 OriginatorIdentifierOrKey_choice, hf_index, ett_cms_OriginatorIdentifierOrKey,
                                 NULL);

  return offset;
}



static int
dissect_cms_UserKeyingMaterial(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_cms_GeneralizedTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_cms_T_keyAttrId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_cms_ci_contentType, &object_identifier_id);

  return offset;
}



static int
dissect_cms_T_keyAttr(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 117 "../../asn1/cms/cms.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);


  return offset;
}


static const ber_sequence_t OtherKeyAttribute_sequence[] = {
  { &hf_cms_keyAttrId       , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cms_T_keyAttrId },
  { &hf_cms_keyAttr         , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cms_T_keyAttr },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_OtherKeyAttribute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cms_RecipientKeyIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cms_KeyAgreeRecipientIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cms_RecipientEncryptedKey(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RecipientEncryptedKey_sequence, hf_index, ett_cms_RecipientEncryptedKey);

  return offset;
}


static const ber_sequence_t RecipientEncryptedKeys_sequence_of[1] = {
  { &hf_cms_RecipientEncryptedKeys_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_RecipientEncryptedKey },
};

static int
dissect_cms_RecipientEncryptedKeys(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cms_KeyAgreeRecipientInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   KeyAgreeRecipientInfo_sequence, hf_index, ett_cms_KeyAgreeRecipientInfo);

  return offset;
}



static int
dissect_cms_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cms_KEKIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cms_KEKRecipientInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   KEKRecipientInfo_sequence, hf_index, ett_cms_KEKRecipientInfo);

  return offset;
}



static int
dissect_cms_KeyDerivationAlgorithmIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cms_PasswordRecipientInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PasswordRecipientInfo_sequence, hf_index, ett_cms_PasswordRecipientInfo);

  return offset;
}



static int
dissect_cms_T_oriType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &object_identifier_id);

  return offset;
}



static int
dissect_cms_T_oriValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 111 "../../asn1/cms/cms.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);



  return offset;
}


static const ber_sequence_t OtherRecipientInfo_sequence[] = {
  { &hf_cms_oriType         , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cms_T_oriType },
  { &hf_cms_oriValue        , BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_cms_T_oriValue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_OtherRecipientInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cms_RecipientInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RecipientInfo_choice, hf_index, ett_cms_RecipientInfo,
                                 NULL);

  return offset;
}


static const ber_sequence_t RecipientInfos_set_of[1] = {
  { &hf_cms_RecipientInfos_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_cms_RecipientInfo },
};

static int
dissect_cms_RecipientInfos(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_set_of(implicit_tag, actx, tree, tvb, offset,
                                             1, NO_BOUND, RecipientInfos_set_of, hf_index, ett_cms_RecipientInfos);

  return offset;
}



static int
dissect_cms_ContentEncryptionAlgorithmIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_cms_EncryptedContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 188 "../../asn1/cms/cms.cnf"
	tvbuff_t *encrypted_tvb;
	proto_item *item;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &encrypted_tvb);

#line 193 "../../asn1/cms/cms.cnf"

	item = actx->created_item;

	PBE_decrypt_data(object_identifier_id, encrypted_tvb, actx, item);


  return offset;
}


static const ber_sequence_t EncryptedContentInfo_sequence[] = {
  { &hf_cms_encryptedContentType, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cms_ContentType },
  { &hf_cms_contentEncryptionAlgorithm, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_ContentEncryptionAlgorithmIdentifier },
  { &hf_cms_encryptedContent, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cms_EncryptedContent },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_EncryptedContentInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EncryptedContentInfo_sequence, hf_index, ett_cms_EncryptedContentInfo);

  return offset;
}


static const ber_sequence_t UnprotectedAttributes_set_of[1] = {
  { &hf_cms_UnprotectedAttributes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_Attribute },
};

static int
dissect_cms_UnprotectedAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cms_EnvelopedData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EnvelopedData_sequence, hf_index, ett_cms_EnvelopedData);

  return offset;
}



int
dissect_cms_Digest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cms_DigestedData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cms_EncryptedData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EncryptedData_sequence, hf_index, ett_cms_EncryptedData);

  return offset;
}



static int
dissect_cms_MessageAuthenticationCodeAlgorithm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t AuthAttributes_set_of[1] = {
  { &hf_cms_AuthAttributes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_Attribute },
};

static int
dissect_cms_AuthAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_set_of(implicit_tag, actx, tree, tvb, offset,
                                             1, NO_BOUND, AuthAttributes_set_of, hf_index, ett_cms_AuthAttributes);

  return offset;
}



static int
dissect_cms_MessageAuthenticationCode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cms_AuthenticatedData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AuthenticatedData_sequence, hf_index, ett_cms_AuthenticatedData);

  return offset;
}



static int
dissect_cms_MessageDigest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 142 "../../asn1/cms/cms.cnf"
  proto_item *pi;
  int old_offset = offset;

    offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

 
  pi = actx->created_item;

  /* move past TLV */
  old_offset = get_ber_identifier(tvb, old_offset, NULL, NULL, NULL);
  old_offset = get_ber_length(tvb, old_offset, NULL, NULL);

  if(content_tvb)
    cms_verify_msg_digest(pi, content_tvb, x509af_get_last_algorithm_id(), tvb, old_offset);



  return offset;
}



static int
dissect_cms_UTCTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_UTCTime(implicit_tag, actx, tree, tvb, offset, hf_index);

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
dissect_cms_Time(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Time_choice, hf_index, ett_cms_Time,
                                 NULL);

  return offset;
}



static int
dissect_cms_SigningTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cms_Time(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



int
dissect_cms_Countersignature(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cms_SignerInfo(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_cms_RC2ParameterVersion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 178 "../../asn1/cms/cms.cnf"
  guint32 length = 0;

    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &length);


  if(cap_tree != NULL)
    proto_item_append_text(cap_tree, " (%d bits)", length);



  return offset;
}



static int
dissect_cms_RC2WrapParameter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_cms_RC2ParameterVersion(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_cms_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cms_RC2CBCParameter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RC2CBCParameter_sequence, hf_index, ett_cms_RC2CBCParameter);

  return offset;
}



static int
dissect_cms_T_capability(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 160 "../../asn1/cms/cms.cnf"
  const char *name = NULL;

    offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_cms_attrType, &object_identifier_id);


  if(object_identifier_id) {
    name = oid_resolved_from_string(object_identifier_id);
    proto_item_append_text(tree, " %s", name ? name : object_identifier_id);
    cap_tree = tree;
  }



  return offset;
}



static int
dissect_cms_T_parameters(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 171 "../../asn1/cms/cms.cnf"

  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree);



  return offset;
}


static const ber_sequence_t SMIMECapability_sequence[] = {
  { &hf_cms_capability      , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_cms_T_capability },
  { &hf_cms_parameters      , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cms_T_parameters },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_cms_SMIMECapability(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SMIMECapability_sequence, hf_index, ett_cms_SMIMECapability);

  return offset;
}


static const ber_sequence_t SMIMECapabilities_sequence_of[1] = {
  { &hf_cms_SMIMECapabilities_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cms_SMIMECapability },
};

static int
dissect_cms_SMIMECapabilities(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cms_SMIMEEncryptionKeyPreference(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_cms_RC2CBCParameters(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RC2CBCParameters_choice, hf_index, ett_cms_RC2CBCParameters,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static void dissect_ContentInfo_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cms_ContentInfo(FALSE, tvb, 0, &asn1_ctx, tree, hf_cms_ContentInfo_PDU);
}
static void dissect_ContentType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cms_ContentType(FALSE, tvb, 0, &asn1_ctx, tree, hf_cms_ContentType_PDU);
}
static void dissect_SignedData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cms_SignedData(FALSE, tvb, 0, &asn1_ctx, tree, hf_cms_SignedData_PDU);
}
static void dissect_EnvelopedData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cms_EnvelopedData(FALSE, tvb, 0, &asn1_ctx, tree, hf_cms_EnvelopedData_PDU);
}
static void dissect_DigestedData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cms_DigestedData(FALSE, tvb, 0, &asn1_ctx, tree, hf_cms_DigestedData_PDU);
}
static void dissect_EncryptedData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cms_EncryptedData(FALSE, tvb, 0, &asn1_ctx, tree, hf_cms_EncryptedData_PDU);
}
static void dissect_AuthenticatedData_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cms_AuthenticatedData(FALSE, tvb, 0, &asn1_ctx, tree, hf_cms_AuthenticatedData_PDU);
}
static void dissect_IssuerAndSerialNumber_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cms_IssuerAndSerialNumber(FALSE, tvb, 0, &asn1_ctx, tree, hf_cms_IssuerAndSerialNumber_PDU);
}
static void dissect_MessageDigest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cms_MessageDigest(FALSE, tvb, 0, &asn1_ctx, tree, hf_cms_MessageDigest_PDU);
}
static void dissect_SigningTime_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cms_SigningTime(FALSE, tvb, 0, &asn1_ctx, tree, hf_cms_SigningTime_PDU);
}
static void dissect_Countersignature_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cms_Countersignature(FALSE, tvb, 0, &asn1_ctx, tree, hf_cms_Countersignature_PDU);
}
static void dissect_RC2WrapParameter_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cms_RC2WrapParameter(FALSE, tvb, 0, &asn1_ctx, tree, hf_cms_RC2WrapParameter_PDU);
}
static void dissect_SMIMECapabilities_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cms_SMIMECapabilities(FALSE, tvb, 0, &asn1_ctx, tree, hf_cms_SMIMECapabilities_PDU);
}
static void dissect_SMIMEEncryptionKeyPreference_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cms_SMIMEEncryptionKeyPreference(FALSE, tvb, 0, &asn1_ctx, tree, hf_cms_SMIMEEncryptionKeyPreference_PDU);
}
static void dissect_RC2CBCParameters_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_cms_RC2CBCParameters(FALSE, tvb, 0, &asn1_ctx, tree, hf_cms_RC2CBCParameters_PDU);
}


/*--- End of included file: packet-cms-fn.c ---*/
#line 136 "../../asn1/cms/packet-cms-template.c"

/*--- proto_register_cms ----------------------------------------------*/
void proto_register_cms(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_cms_ci_contentType,
      { "contentType", "cms.contentInfo.contentType",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/*--- Included file: packet-cms-hfarr.c ---*/
#line 1 "../../asn1/cms/packet-cms-hfarr.c"
    { &hf_cms_ContentInfo_PDU,
      { "ContentInfo", "cms.ContentInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_ContentType_PDU,
      { "ContentType", "cms.ContentType",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_SignedData_PDU,
      { "SignedData", "cms.SignedData",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_EnvelopedData_PDU,
      { "EnvelopedData", "cms.EnvelopedData",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_DigestedData_PDU,
      { "DigestedData", "cms.DigestedData",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_EncryptedData_PDU,
      { "EncryptedData", "cms.EncryptedData",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_AuthenticatedData_PDU,
      { "AuthenticatedData", "cms.AuthenticatedData",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_IssuerAndSerialNumber_PDU,
      { "IssuerAndSerialNumber", "cms.IssuerAndSerialNumber",
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
      { "Countersignature", "cms.Countersignature",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_RC2WrapParameter_PDU,
      { "RC2WrapParameter", "cms.RC2WrapParameter",
        FT_INT32, BASE_DEC, NULL, 0,
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
    { &hf_cms_contentType,
      { "contentType", "cms.contentType",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_content,
      { "content", "cms.content",
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
      { "encapContentInfo", "cms.encapContentInfo",
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
      { "DigestAlgorithmIdentifier", "cms.DigestAlgorithmIdentifier",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_SignerInfos_item,
      { "SignerInfo", "cms.SignerInfo",
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
      { "digestAlgorithm", "cms.digestAlgorithm",
        FT_NONE, BASE_NONE, NULL, 0,
        "DigestAlgorithmIdentifier", HFILL }},
    { &hf_cms_signedAttrs,
      { "signedAttrs", "cms.signedAttrs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SignedAttributes", HFILL }},
    { &hf_cms_signatureAlgorithm,
      { "signatureAlgorithm", "cms.signatureAlgorithm",
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
      { "issuerAndSerialNumber", "cms.issuerAndSerialNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_subjectKeyIdentifier,
      { "subjectKeyIdentifier", "cms.subjectKeyIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_SignedAttributes_item,
      { "Attribute", "cms.Attribute",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_UnsignedAttributes_item,
      { "Attribute", "cms.Attribute",
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
      { "AttributeValue", "cms.AttributeValue",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_originatorInfo,
      { "originatorInfo", "cms.originatorInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_recipientInfos,
      { "recipientInfos", "cms.recipientInfos",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_encryptedContentInfo,
      { "encryptedContentInfo", "cms.encryptedContentInfo",
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
      { "contentEncryptionAlgorithm", "cms.contentEncryptionAlgorithm",
        FT_NONE, BASE_NONE, NULL, 0,
        "ContentEncryptionAlgorithmIdentifier", HFILL }},
    { &hf_cms_encryptedContent,
      { "encryptedContent", "cms.encryptedContent",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_UnprotectedAttributes_item,
      { "Attribute", "cms.Attribute",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_ktri,
      { "ktri", "cms.ktri",
        FT_NONE, BASE_NONE, NULL, 0,
        "KeyTransRecipientInfo", HFILL }},
    { &hf_cms_kari,
      { "kari", "cms.kari",
        FT_NONE, BASE_NONE, NULL, 0,
        "KeyAgreeRecipientInfo", HFILL }},
    { &hf_cms_kekri,
      { "kekri", "cms.kekri",
        FT_NONE, BASE_NONE, NULL, 0,
        "KEKRecipientInfo", HFILL }},
    { &hf_cms_pwri,
      { "pwri", "cms.pwri",
        FT_NONE, BASE_NONE, NULL, 0,
        "PasswordRecipientInfo", HFILL }},
    { &hf_cms_ori,
      { "ori", "cms.ori",
        FT_NONE, BASE_NONE, NULL, 0,
        "OtherRecipientInfo", HFILL }},
    { &hf_cms_rid,
      { "rid", "cms.rid",
        FT_UINT32, BASE_DEC, VALS(cms_RecipientIdentifier_vals), 0,
        "RecipientIdentifier", HFILL }},
    { &hf_cms_keyEncryptionAlgorithm,
      { "keyEncryptionAlgorithm", "cms.keyEncryptionAlgorithm",
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
      { "originatorKey", "cms.originatorKey",
        FT_NONE, BASE_NONE, NULL, 0,
        "OriginatorPublicKey", HFILL }},
    { &hf_cms_algorithm,
      { "algorithm", "cms.algorithm",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_cms_publicKey,
      { "publicKey", "cms.publicKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_cms_RecipientEncryptedKeys_item,
      { "RecipientEncryptedKey", "cms.RecipientEncryptedKey",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_rekRid,
      { "rid", "cms.rid",
        FT_UINT32, BASE_DEC, VALS(cms_KeyAgreeRecipientIdentifier_vals), 0,
        "KeyAgreeRecipientIdentifier", HFILL }},
    { &hf_cms_rKeyId,
      { "rKeyId", "cms.rKeyId",
        FT_NONE, BASE_NONE, NULL, 0,
        "RecipientKeyIdentifier", HFILL }},
    { &hf_cms_date,
      { "date", "cms.date",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_cms_other,
      { "other", "cms.other",
        FT_NONE, BASE_NONE, NULL, 0,
        "OtherKeyAttribute", HFILL }},
    { &hf_cms_kekid,
      { "kekid", "cms.kekid",
        FT_NONE, BASE_NONE, NULL, 0,
        "KEKIdentifier", HFILL }},
    { &hf_cms_keyIdentifier,
      { "keyIdentifier", "cms.keyIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_cms_keyDerivationAlgorithm,
      { "keyDerivationAlgorithm", "cms.keyDerivationAlgorithm",
        FT_NONE, BASE_NONE, NULL, 0,
        "KeyDerivationAlgorithmIdentifier", HFILL }},
    { &hf_cms_oriType,
      { "oriType", "cms.oriType",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_oriValue,
      { "oriValue", "cms.oriValue",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_digest,
      { "digest", "cms.digest",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_macAlgorithm,
      { "macAlgorithm", "cms.macAlgorithm",
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
      { "Attribute", "cms.Attribute",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_UnauthAttributes_item,
      { "Attribute", "cms.Attribute",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_RevocationInfoChoices_item,
      { "RevocationInfoChoice", "cms.RevocationInfoChoice",
        FT_UINT32, BASE_DEC, VALS(cms_RevocationInfoChoice_vals), 0,
        NULL, HFILL }},
    { &hf_cms_crl,
      { "crl", "cms.crl",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertificateList", HFILL }},
    { &hf_cms_otherRIC,
      { "other", "cms.other",
        FT_NONE, BASE_NONE, NULL, 0,
        "OtherRevocationInfoFormat", HFILL }},
    { &hf_cms_otherRevInfoFormat,
      { "otherRevInfoFormat", "cms.otherRevInfoFormat",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_otherRevInfo,
      { "otherRevInfo", "cms.otherRevInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_certificate,
      { "certificate", "cms.certificate",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_extendedCertificate,
      { "extendedCertificate", "cms.extendedCertificate",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_v1AttrCert,
      { "v1AttrCert", "cms.v1AttrCert",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeCertificateV1", HFILL }},
    { &hf_cms_v2AttrCert,
      { "v2AttrCert", "cms.v2AttrCert",
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
        FT_INT32, BASE_DEC, NULL, 0,
        "CertificateSerialNumber", HFILL }},
    { &hf_cms_keyAttrId,
      { "keyAttrId", "cms.keyAttrId",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_keyAttr,
      { "keyAttr", "cms.keyAttr",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_utcTime,
      { "utcTime", "cms.utcTime",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_generalTime,
      { "generalTime", "cms.generalTime",
        FT_STRING, BASE_NONE, NULL, 0,
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
      { "extendedCertificateInfo", "cms.extendedCertificateInfo",
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
      { "SMIMECapability", "cms.SMIMECapability",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_capability,
      { "capability", "cms.capability",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_parameters,
      { "parameters", "cms.parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_recipientKeyId,
      { "recipientKeyId", "cms.recipientKeyId",
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
      { "rc2CBCParameter", "cms.rc2CBCParameter",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_acInfo,
      { "acInfo", "cms.acInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeCertificateInfoV1", HFILL }},
    { &hf_cms_signatureAlgorithm_v1,
      { "signatureAlgorithm", "cms.signatureAlgorithm",
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
      { "baseCertificateID", "cms.baseCertificateID",
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
      { "signature", "cms.signature",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_cms_attCertValidityPeriod,
      { "attCertValidityPeriod", "cms.attCertValidityPeriod",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_cms_attributes_v1,
      { "attributes", "cms.attributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Attribute", HFILL }},
    { &hf_cms_attributes_v1_item,
      { "Attribute", "cms.Attribute",
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

/*--- End of included file: packet-cms-hfarr.c ---*/
#line 147 "../../asn1/cms/packet-cms-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-cms-ettarr.c ---*/
#line 1 "../../asn1/cms/packet-cms-ettarr.c"
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
    &ett_cms_SMIMECapabilities,
    &ett_cms_SMIMECapability,
    &ett_cms_SMIMEEncryptionKeyPreference,
    &ett_cms_RC2CBCParameters,
    &ett_cms_AttributeCertificateV1,
    &ett_cms_AttributeCertificateInfoV1,
    &ett_cms_T_subject,
    &ett_cms_SEQUENCE_OF_Attribute,

/*--- End of included file: packet-cms-ettarr.c ---*/
#line 152 "../../asn1/cms/packet-cms-template.c"
  };

  /* Register protocol */
  proto_cms = proto_register_protocol(PNAME, PSNAME, PFNAME);

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

/*--- Included file: packet-cms-dis-tab.c ---*/
#line 1 "../../asn1/cms/packet-cms-dis-tab.c"
  register_ber_oid_dissector("1.2.840.113549.1.9.16.1.6", dissect_ContentInfo_PDU, proto_cms, "id-ct-contentInfo");
  register_ber_oid_dissector("1.2.840.113549.1.7.2", dissect_SignedData_PDU, proto_cms, "id-signedData");
  register_ber_oid_dissector("1.2.840.113549.1.7.3", dissect_EnvelopedData_PDU, proto_cms, "id-envelopedData");
  register_ber_oid_dissector("1.2.840.113549.1.7.5", dissect_DigestedData_PDU, proto_cms, "id-digestedData");
  register_ber_oid_dissector("1.2.840.113549.1.7.6", dissect_EncryptedData_PDU, proto_cms, "id-encryptedData");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.1.2", dissect_AuthenticatedData_PDU, proto_cms, "id-ct-authenticatedData");
  register_ber_oid_dissector("1.2.840.113549.1.9.3", dissect_ContentType_PDU, proto_cms, "id-contentType");
  register_ber_oid_dissector("1.2.840.113549.1.9.4", dissect_MessageDigest_PDU, proto_cms, "id-messageDigest");
  register_ber_oid_dissector("1.2.840.113549.1.9.5", dissect_SigningTime_PDU, proto_cms, "id-signingTime");
  register_ber_oid_dissector("1.2.840.113549.1.9.6", dissect_Countersignature_PDU, proto_cms, "id-counterSignature");
  register_ber_oid_dissector("2.6.1.4.18", dissect_ContentInfo_PDU, proto_cms, "id-et-pkcs7");
  register_ber_oid_dissector("1.3.6.1.4.1.311.16.4", dissect_IssuerAndSerialNumber_PDU, proto_cms, "ms-oe-encryption-key-preference");
  register_ber_oid_dissector("1.2.840.113549.1.9.15", dissect_SMIMECapabilities_PDU, proto_cms, "id-smime-capabilities");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.2.11", dissect_SMIMEEncryptionKeyPreference_PDU, proto_cms, "id-encryption-key-preference");
  register_ber_oid_dissector("1.2.840.113549.3.2", dissect_RC2CBCParameters_PDU, proto_cms, "id-alg-rc2-cbc");
  register_ber_oid_dissector("1.2.840.113549.3.4", dissect_RC2CBCParameters_PDU, proto_cms, "id-alg-rc4");
  register_ber_oid_dissector("1.2.840.113549.1.9.16.3.7", dissect_RC2WrapParameter_PDU, proto_cms, "id-alg-cmsrc2-wrap");


/*--- End of included file: packet-cms-dis-tab.c ---*/
#line 174 "../../asn1/cms/packet-cms-template.c"

  oid_add_from_string("id-data","1.2.840.113549.1.7.1");
  oid_add_from_string("id-alg-des-ede3-cbc","1.2.840.113549.3.7");
  oid_add_from_string("id-alg-des-cbc","1.3.14.3.2.7");

}

