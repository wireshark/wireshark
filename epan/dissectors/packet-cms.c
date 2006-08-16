/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* .\packet-cms.c                                                             */
/* ../../tools/asn2wrs.py -b -e -p cms -c cms.cnf -s packet-cms-template CryptographicMessageSyntax.asn */

/* Input file: packet-cms-template.c */

#line 1 "packet-cms-template.c"
/* packet-cms.c
 * Routines for RFC2630 Cryptographic Message Syntax packet dissection
 *   Ronnie Sahlberg 2004
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
#include <epan/conversation.h>
#include <epan/oid_resolv.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-cms.h"
#include "packet-x509af.h"
#include "packet-x509if.h"

#include <epan/sha1.h>
#include <epan/crypt-md5.h>

#define PNAME  "Cryptographic Message Syntax"
#define PSNAME "CMS"
#define PFNAME "cms"

/* Initialize the protocol and registered fields */
int proto_cms = -1;
static int hf_cms_ci_contentType = -1;

/*--- Included file: packet-cms-hf.c ---*/
#line 1 "packet-cms-hf.c"
static int hf_cms_ContentInfo_PDU = -1;           /* ContentInfo */
static int hf_cms_ContentType_PDU = -1;           /* ContentType */
static int hf_cms_SignedData_PDU = -1;            /* SignedData */
static int hf_cms_EnvelopedData_PDU = -1;         /* EnvelopedData */
static int hf_cms_DigestedData_PDU = -1;          /* DigestedData */
static int hf_cms_EncryptedData_PDU = -1;         /* EncryptedData */
static int hf_cms_AuthenticatedData_PDU = -1;     /* AuthenticatedData */
static int hf_cms_MessageDigest_PDU = -1;         /* MessageDigest */
static int hf_cms_SigningTime_PDU = -1;           /* SigningTime */
static int hf_cms_Countersignature_PDU = -1;      /* Countersignature */
static int hf_cms_contentType = -1;               /* T_contentType */
static int hf_cms_content = -1;                   /* T_content */
static int hf_cms_version = -1;                   /* CMSVersion */
static int hf_cms_digestAlgorithms = -1;          /* DigestAlgorithmIdentifiers */
static int hf_cms_encapContentInfo = -1;          /* EncapsulatedContentInfo */
static int hf_cms_certificates = -1;              /* CertificateSet */
static int hf_cms_crls = -1;                      /* CertificateRevocationLists */
static int hf_cms_signerInfos = -1;               /* SignerInfos */
static int hf_cms_DigestAlgorithmIdentifiers_item = -1;  /* DigestAlgorithmIdentifier */
static int hf_cms_SignerInfos_item = -1;          /* SignerInfo */
static int hf_cms_eContentType = -1;              /* T_eContentType */
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
static int hf_cms_digest = -1;                    /* Digest */
static int hf_cms_macAlgorithm = -1;              /* MessageAuthenticationCodeAlgorithm */
static int hf_cms_authenticatedAttributes = -1;   /* AuthAttributes */
static int hf_cms_mac = -1;                       /* MessageAuthenticationCode */
static int hf_cms_unauthenticatedAttributes = -1;  /* UnauthAttributes */
static int hf_cms_AuthAttributes_item = -1;       /* Attribute */
static int hf_cms_UnauthAttributes_item = -1;     /* Attribute */
static int hf_cms_CertificateRevocationLists_item = -1;  /* CertificateList */
static int hf_cms_certificate = -1;               /* Certificate */
static int hf_cms_extendedCertificate = -1;       /* ExtendedCertificate */
static int hf_cms_attrCert = -1;                  /* AttributeCertificate */
static int hf_cms_CertificateSet_item = -1;       /* CertificateChoices */
static int hf_cms_issuer = -1;                    /* Name */
static int hf_cms_serialNumber = -1;              /* CertificateSerialNumber */
static int hf_cms_keyAttrId = -1;                 /* T_keyAttrId */
static int hf_cms_keyAttr = -1;                   /* T_keyAttr */
static int hf_cms_utcTime = -1;                   /* UTCTime */
static int hf_cms_generalTime = -1;               /* GeneralizedTime */
static int hf_cms_extendedCertificateInfo = -1;   /* ExtendedCertificateInfo */
static int hf_cms_signature = -1;                 /* Signature */
static int hf_cms_attributes = -1;                /* UnauthAttributes */

/*--- End of included file: packet-cms-hf.c ---*/
#line 54 "packet-cms-template.c"

/* Initialize the subtree pointers */

/*--- Included file: packet-cms-ett.c ---*/
#line 1 "packet-cms-ett.c"
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
static gint ett_cms_DigestedData = -1;
static gint ett_cms_EncryptedData = -1;
static gint ett_cms_AuthenticatedData = -1;
static gint ett_cms_AuthAttributes = -1;
static gint ett_cms_UnauthAttributes = -1;
static gint ett_cms_CertificateRevocationLists = -1;
static gint ett_cms_CertificateChoices = -1;
static gint ett_cms_CertificateSet = -1;
static gint ett_cms_IssuerAndSerialNumber = -1;
static gint ett_cms_OtherKeyAttribute = -1;
static gint ett_cms_Time = -1;
static gint ett_cms_ExtendedCertificate = -1;
static gint ett_cms_ExtendedCertificateInfo = -1;

/*--- End of included file: packet-cms-ett.c ---*/
#line 57 "packet-cms-template.c"

static int dissect_cms_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) ; /* XXX kill a compiler warning until asn2wrs stops generating these silly wrappers */


static const char *object_identifier_id;
static tvbuff_t *content_tvb = NULL;

static proto_tree *top_tree=NULL;

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
       (memcmp(tvb_get_ptr(tvb, offset, buffer_size), digest_buf, buffer_size) != 0)) { 
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
#line 1 "packet-cms-fn.c"
/*--- Fields for imported types ---*/

static int dissect_algorithm(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_AlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_cms_algorithm);
}
static int dissect_CertificateRevocationLists_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_CertificateList(FALSE, tvb, offset, pinfo, tree, hf_cms_CertificateRevocationLists_item);
}
static int dissect_certificate(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_Certificate(FALSE, tvb, offset, pinfo, tree, hf_cms_certificate);
}
static int dissect_attrCert_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_AttributeCertificate(TRUE, tvb, offset, pinfo, tree, hf_cms_attrCert);
}
static int dissect_issuer(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Name(FALSE, tvb, offset, pinfo, tree, hf_cms_issuer);
}
static int dissect_serialNumber(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_CertificateSerialNumber(FALSE, tvb, offset, pinfo, tree, hf_cms_serialNumber);
}



int
dissect_cms_ContentType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_encryptedContentType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_ContentType(FALSE, tvb, offset, pinfo, tree, hf_cms_encryptedContentType);
}



static int
dissect_cms_T_contentType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 56 "cms.cnf"
  offset = dissect_ber_object_identifier_str(FALSE, pinfo, tree, tvb, offset,
                                         hf_cms_ci_contentType, &object_identifier_id);



  return offset;
}
static int dissect_contentType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_T_contentType(FALSE, tvb, offset, pinfo, tree, hf_cms_contentType);
}



static int
dissect_cms_T_content(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 60 "cms.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, pinfo, tree);



  return offset;
}
static int dissect_content(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_T_content(FALSE, tvb, offset, pinfo, tree, hf_cms_content);
}


static const ber_sequence_t ContentInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_contentType },
  { BER_CLASS_CON, 0, 0, dissect_content },
  { 0, 0, 0, NULL }
};

int
dissect_cms_ContentInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 50 "cms.cnf"
  top_tree = tree;
    offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
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
  { 0, NULL }
};


static int
dissect_cms_CMSVersion(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_version(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_CMSVersion(FALSE, tvb, offset, pinfo, tree, hf_cms_version);
}



static int
dissect_cms_DigestAlgorithmIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_DigestAlgorithmIdentifiers_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_DigestAlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_cms_DigestAlgorithmIdentifiers_item);
}
static int dissect_digestAlgorithm(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_DigestAlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_cms_digestAlgorithm);
}
static int dissect_digestAlgorithm_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_DigestAlgorithmIdentifier(TRUE, tvb, offset, pinfo, tree, hf_cms_digestAlgorithm);
}


static const ber_sequence_t DigestAlgorithmIdentifiers_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_DigestAlgorithmIdentifiers_item },
};

int
dissect_cms_DigestAlgorithmIdentifiers(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 DigestAlgorithmIdentifiers_set_of, hf_index, ett_cms_DigestAlgorithmIdentifiers);

  return offset;
}
static int dissect_digestAlgorithms(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_DigestAlgorithmIdentifiers(FALSE, tvb, offset, pinfo, tree, hf_cms_digestAlgorithms);
}



static int
dissect_cms_T_eContentType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 63 "cms.cnf"
  offset = dissect_ber_object_identifier_str(FALSE, pinfo, tree, tvb, offset,
                                         hf_cms_ci_contentType, &object_identifier_id);



  return offset;
}
static int dissect_eContentType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_T_eContentType(FALSE, tvb, offset, pinfo, tree, hf_cms_eContentType);
}



static int
dissect_cms_T_eContent(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 67 "cms.cnf"
  gint8 class;
  gboolean pc, ind;
  gint32 tag;
  guint32 len;
  int pdu_offset = offset;
  int content_offset;

  /* XXX Do we care about printing out the octet string? */
  offset = dissect_cms_OCTET_STRING(FALSE, tvb, offset, pinfo, NULL, hf_cms_eContent);

  pdu_offset = get_ber_identifier(tvb, pdu_offset, &class, &pc, &tag);
  content_offset = pdu_offset = get_ber_length(tree, tvb, pdu_offset, &len, &ind);
  pdu_offset = call_ber_oid_callback(object_identifier_id, tvb, pdu_offset, pinfo, top_tree ? top_tree : tree);
  
  content_tvb = tvb_new_subset(tvb, content_offset, len, -1);



  return offset;
}
static int dissect_eContent(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_T_eContent(FALSE, tvb, offset, pinfo, tree, hf_cms_eContent);
}


static const ber_sequence_t EncapsulatedContentInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_eContentType },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_eContent },
  { 0, 0, 0, NULL }
};

int
dissect_cms_EncapsulatedContentInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   EncapsulatedContentInfo_sequence, hf_index, ett_cms_EncapsulatedContentInfo);

  return offset;
}
static int dissect_encapContentInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_EncapsulatedContentInfo(FALSE, tvb, offset, pinfo, tree, hf_cms_encapContentInfo);
}



static int
dissect_cms_T_attrType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 94 "cms.cnf"
  const char *name = NULL;

    offset = dissect_ber_object_identifier_str(implicit_tag, pinfo, tree, tvb, offset, hf_cms_attrType, &object_identifier_id);


  if(object_identifier_id) {
    name = get_oid_str_name(object_identifier_id);
    proto_item_append_text(tree, " (%s)", name ? name : object_identifier_id); 
  }



  return offset;
}
static int dissect_attrType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_T_attrType(FALSE, tvb, offset, pinfo, tree, hf_cms_attrType);
}



static int
dissect_cms_AttributeValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 104 "cms.cnf"

  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, pinfo, tree);



  return offset;
}
static int dissect_attrValues_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_AttributeValue(FALSE, tvb, offset, pinfo, tree, hf_cms_attrValues_item);
}


static const ber_sequence_t SET_OF_AttributeValue_set_of[1] = {
  { BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_attrValues_item },
};

static int
dissect_cms_SET_OF_AttributeValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_AttributeValue_set_of, hf_index, ett_cms_SET_OF_AttributeValue);

  return offset;
}
static int dissect_attrValues(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_SET_OF_AttributeValue(FALSE, tvb, offset, pinfo, tree, hf_cms_attrValues);
}


static const ber_sequence_t Attribute_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_attrType },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_attrValues },
  { 0, 0, 0, NULL }
};

static int
dissect_cms_Attribute(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
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
static int dissect_UnprotectedAttributes_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_Attribute(FALSE, tvb, offset, pinfo, tree, hf_cms_UnprotectedAttributes_item);
}
static int dissect_AuthAttributes_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_Attribute(FALSE, tvb, offset, pinfo, tree, hf_cms_AuthAttributes_item);
}
static int dissect_UnauthAttributes_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_Attribute(FALSE, tvb, offset, pinfo, tree, hf_cms_UnauthAttributes_item);
}


static const ber_sequence_t UnauthAttributes_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_UnauthAttributes_item },
};

static int
dissect_cms_UnauthAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 UnauthAttributes_set_of, hf_index, ett_cms_UnauthAttributes);

  return offset;
}
static int dissect_unauthenticatedAttributes_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_UnauthAttributes(TRUE, tvb, offset, pinfo, tree, hf_cms_unauthenticatedAttributes);
}
static int dissect_attributes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_UnauthAttributes(FALSE, tvb, offset, pinfo, tree, hf_cms_attributes);
}


static const ber_sequence_t ExtendedCertificateInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_version },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_certificate },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_attributes },
  { 0, 0, 0, NULL }
};

static int
dissect_cms_ExtendedCertificateInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ExtendedCertificateInfo_sequence, hf_index, ett_cms_ExtendedCertificateInfo);

  return offset;
}
static int dissect_extendedCertificateInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_ExtendedCertificateInfo(FALSE, tvb, offset, pinfo, tree, hf_cms_extendedCertificateInfo);
}



static int
dissect_cms_SignatureAlgorithmIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_signatureAlgorithm(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_SignatureAlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_cms_signatureAlgorithm);
}



static int
dissect_cms_Signature(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}
static int dissect_signature(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_Signature(FALSE, tvb, offset, pinfo, tree, hf_cms_signature);
}


static const ber_sequence_t ExtendedCertificate_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_extendedCertificateInfo },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signatureAlgorithm },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_signature },
  { 0, 0, 0, NULL }
};

static int
dissect_cms_ExtendedCertificate(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ExtendedCertificate_sequence, hf_index, ett_cms_ExtendedCertificate);

  return offset;
}
static int dissect_extendedCertificate_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_ExtendedCertificate(TRUE, tvb, offset, pinfo, tree, hf_cms_extendedCertificate);
}


static const value_string cms_CertificateChoices_vals[] = {
  {   0, "certificate" },
  {   1, "extendedCertificate" },
  {   2, "attrCert" },
  { 0, NULL }
};

static const ber_choice_t CertificateChoices_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_certificate },
  {   1, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_extendedCertificate_impl },
  {   2, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_attrCert_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_cms_CertificateChoices(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 CertificateChoices_choice, hf_index, ett_cms_CertificateChoices,
                                 NULL);

  return offset;
}
static int dissect_CertificateSet_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_CertificateChoices(FALSE, tvb, offset, pinfo, tree, hf_cms_CertificateSet_item);
}


static const ber_sequence_t CertificateSet_set_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_CertificateSet_item },
};

static int
dissect_cms_CertificateSet(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 CertificateSet_set_of, hf_index, ett_cms_CertificateSet);

  return offset;
}
static int dissect_certificates_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_CertificateSet(TRUE, tvb, offset, pinfo, tree, hf_cms_certificates);
}
static int dissect_certs_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_CertificateSet(TRUE, tvb, offset, pinfo, tree, hf_cms_certs);
}


static const ber_sequence_t CertificateRevocationLists_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_CertificateRevocationLists_item },
};

static int
dissect_cms_CertificateRevocationLists(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 CertificateRevocationLists_set_of, hf_index, ett_cms_CertificateRevocationLists);

  return offset;
}
static int dissect_crls_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_CertificateRevocationLists(TRUE, tvb, offset, pinfo, tree, hf_cms_crls);
}


static const ber_sequence_t IssuerAndSerialNumber_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_issuer },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_serialNumber },
  { 0, 0, 0, NULL }
};

int
dissect_cms_IssuerAndSerialNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   IssuerAndSerialNumber_sequence, hf_index, ett_cms_IssuerAndSerialNumber);

  return offset;
}
static int dissect_issuerAndSerialNumber(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_IssuerAndSerialNumber(FALSE, tvb, offset, pinfo, tree, hf_cms_issuerAndSerialNumber);
}



static int
dissect_cms_SubjectKeyIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_subjectKeyIdentifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_SubjectKeyIdentifier(FALSE, tvb, offset, pinfo, tree, hf_cms_subjectKeyIdentifier);
}
static int dissect_subjectKeyIdentifier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_SubjectKeyIdentifier(TRUE, tvb, offset, pinfo, tree, hf_cms_subjectKeyIdentifier);
}


const value_string cms_SignerIdentifier_vals[] = {
  {   0, "issuerAndSerialNumber" },
  {   1, "subjectKeyIdentifier" },
  { 0, NULL }
};

static const ber_choice_t SignerIdentifier_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_issuerAndSerialNumber },
  {   1, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_subjectKeyIdentifier_impl },
  { 0, 0, 0, 0, NULL }
};

int
dissect_cms_SignerIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 SignerIdentifier_choice, hf_index, ett_cms_SignerIdentifier,
                                 NULL);

  return offset;
}
static int dissect_sid(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_SignerIdentifier(FALSE, tvb, offset, pinfo, tree, hf_cms_sid);
}


static const ber_sequence_t SignedAttributes_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_SignedAttributes_item },
};

int
dissect_cms_SignedAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SignedAttributes_set_of, hf_index, ett_cms_SignedAttributes);

  return offset;
}
static int dissect_signedAttrs_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_SignedAttributes(TRUE, tvb, offset, pinfo, tree, hf_cms_signedAttrs);
}



int
dissect_cms_SignatureValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_signatureValue(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_SignatureValue(FALSE, tvb, offset, pinfo, tree, hf_cms_signatureValue);
}


static const ber_sequence_t UnsignedAttributes_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_UnsignedAttributes_item },
};

int
dissect_cms_UnsignedAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 UnsignedAttributes_set_of, hf_index, ett_cms_UnsignedAttributes);

  return offset;
}
static int dissect_unsignedAttrs_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_UnsignedAttributes(TRUE, tvb, offset, pinfo, tree, hf_cms_unsignedAttrs);
}


static const ber_sequence_t SignerInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_version },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_sid },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_digestAlgorithm },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_signedAttrs_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signatureAlgorithm },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_signatureValue },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_unsignedAttrs_impl },
  { 0, 0, 0, NULL }
};

int
dissect_cms_SignerInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SignerInfo_sequence, hf_index, ett_cms_SignerInfo);

  return offset;
}
static int dissect_SignerInfos_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_SignerInfo(FALSE, tvb, offset, pinfo, tree, hf_cms_SignerInfos_item);
}


static const ber_sequence_t SignerInfos_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_SignerInfos_item },
};

int
dissect_cms_SignerInfos(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SignerInfos_set_of, hf_index, ett_cms_SignerInfos);

  return offset;
}
static int dissect_signerInfos(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_SignerInfos(FALSE, tvb, offset, pinfo, tree, hf_cms_signerInfos);
}


static const ber_sequence_t SignedData_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_version },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_digestAlgorithms },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_encapContentInfo },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_certificates_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_crls_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_signerInfos },
  { 0, 0, 0, NULL }
};

int
dissect_cms_SignedData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SignedData_sequence, hf_index, ett_cms_SignedData);

  return offset;
}


static const ber_sequence_t OriginatorInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_certs_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_crls_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_cms_OriginatorInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   OriginatorInfo_sequence, hf_index, ett_cms_OriginatorInfo);

  return offset;
}
static int dissect_originatorInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_OriginatorInfo(TRUE, tvb, offset, pinfo, tree, hf_cms_originatorInfo);
}


static const value_string cms_RecipientIdentifier_vals[] = {
  {   0, "issuerAndSerialNumber" },
  {   1, "subjectKeyIdentifier" },
  { 0, NULL }
};

static const ber_choice_t RecipientIdentifier_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_issuerAndSerialNumber },
  {   1, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_subjectKeyIdentifier_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_cms_RecipientIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 RecipientIdentifier_choice, hf_index, ett_cms_RecipientIdentifier,
                                 NULL);

  return offset;
}
static int dissect_rid(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_RecipientIdentifier(FALSE, tvb, offset, pinfo, tree, hf_cms_rid);
}



static int
dissect_cms_KeyEncryptionAlgorithmIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_keyEncryptionAlgorithm(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_KeyEncryptionAlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_cms_keyEncryptionAlgorithm);
}



static int
dissect_cms_EncryptedKey(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_encryptedKey(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_EncryptedKey(FALSE, tvb, offset, pinfo, tree, hf_cms_encryptedKey);
}


static const ber_sequence_t KeyTransRecipientInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_version },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_rid },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_keyEncryptionAlgorithm },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_encryptedKey },
  { 0, 0, 0, NULL }
};

static int
dissect_cms_KeyTransRecipientInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   KeyTransRecipientInfo_sequence, hf_index, ett_cms_KeyTransRecipientInfo);

  return offset;
}
static int dissect_ktri(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_KeyTransRecipientInfo(FALSE, tvb, offset, pinfo, tree, hf_cms_ktri);
}



static int
dissect_cms_BIT_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}
static int dissect_publicKey(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_BIT_STRING(FALSE, tvb, offset, pinfo, tree, hf_cms_publicKey);
}


static const ber_sequence_t OriginatorPublicKey_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithm },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_publicKey },
  { 0, 0, 0, NULL }
};

static int
dissect_cms_OriginatorPublicKey(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   OriginatorPublicKey_sequence, hf_index, ett_cms_OriginatorPublicKey);

  return offset;
}
static int dissect_originatorKey_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_OriginatorPublicKey(TRUE, tvb, offset, pinfo, tree, hf_cms_originatorKey);
}


static const value_string cms_OriginatorIdentifierOrKey_vals[] = {
  {   0, "issuerAndSerialNumber" },
  {   1, "subjectKeyIdentifier" },
  {   2, "originatorKey" },
  { 0, NULL }
};

static const ber_choice_t OriginatorIdentifierOrKey_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_issuerAndSerialNumber },
  {   1, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_subjectKeyIdentifier_impl },
  {   2, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_originatorKey_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_cms_OriginatorIdentifierOrKey(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 OriginatorIdentifierOrKey_choice, hf_index, ett_cms_OriginatorIdentifierOrKey,
                                 NULL);

  return offset;
}
static int dissect_originator(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_OriginatorIdentifierOrKey(FALSE, tvb, offset, pinfo, tree, hf_cms_originator);
}



static int
dissect_cms_UserKeyingMaterial(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_ukm(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_UserKeyingMaterial(FALSE, tvb, offset, pinfo, tree, hf_cms_ukm);
}



static int
dissect_cms_GeneralizedTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_date(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_GeneralizedTime(FALSE, tvb, offset, pinfo, tree, hf_cms_date);
}
static int dissect_generalTime(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_GeneralizedTime(FALSE, tvb, offset, pinfo, tree, hf_cms_generalTime);
}



static int
dissect_cms_T_keyAttrId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, pinfo, tree, tvb, offset, hf_cms_ci_contentType, &object_identifier_id);

  return offset;
}
static int dissect_keyAttrId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_T_keyAttrId(FALSE, tvb, offset, pinfo, tree, hf_cms_keyAttrId);
}



static int
dissect_cms_T_keyAttr(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 87 "cms.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, pinfo, tree);




  return offset;
}
static int dissect_keyAttr(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_T_keyAttr(FALSE, tvb, offset, pinfo, tree, hf_cms_keyAttr);
}


static const ber_sequence_t OtherKeyAttribute_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_keyAttrId },
  { BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_keyAttr },
  { 0, 0, 0, NULL }
};

static int
dissect_cms_OtherKeyAttribute(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   OtherKeyAttribute_sequence, hf_index, ett_cms_OtherKeyAttribute);

  return offset;
}
static int dissect_other(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_OtherKeyAttribute(FALSE, tvb, offset, pinfo, tree, hf_cms_other);
}


static const ber_sequence_t RecipientKeyIdentifier_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_subjectKeyIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_date },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_other },
  { 0, 0, 0, NULL }
};

static int
dissect_cms_RecipientKeyIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   RecipientKeyIdentifier_sequence, hf_index, ett_cms_RecipientKeyIdentifier);

  return offset;
}
static int dissect_rKeyId_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_RecipientKeyIdentifier(TRUE, tvb, offset, pinfo, tree, hf_cms_rKeyId);
}


static const value_string cms_KeyAgreeRecipientIdentifier_vals[] = {
  {   0, "issuerAndSerialNumber" },
  {   1, "rKeyId" },
  { 0, NULL }
};

static const ber_choice_t KeyAgreeRecipientIdentifier_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_issuerAndSerialNumber },
  {   1, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_rKeyId_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_cms_KeyAgreeRecipientIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 KeyAgreeRecipientIdentifier_choice, hf_index, ett_cms_KeyAgreeRecipientIdentifier,
                                 NULL);

  return offset;
}
static int dissect_rekRid(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_KeyAgreeRecipientIdentifier(FALSE, tvb, offset, pinfo, tree, hf_cms_rekRid);
}


static const ber_sequence_t RecipientEncryptedKey_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_rekRid },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_encryptedKey },
  { 0, 0, 0, NULL }
};

static int
dissect_cms_RecipientEncryptedKey(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   RecipientEncryptedKey_sequence, hf_index, ett_cms_RecipientEncryptedKey);

  return offset;
}
static int dissect_RecipientEncryptedKeys_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_RecipientEncryptedKey(FALSE, tvb, offset, pinfo, tree, hf_cms_RecipientEncryptedKeys_item);
}


static const ber_sequence_t RecipientEncryptedKeys_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_RecipientEncryptedKeys_item },
};

static int
dissect_cms_RecipientEncryptedKeys(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      RecipientEncryptedKeys_sequence_of, hf_index, ett_cms_RecipientEncryptedKeys);

  return offset;
}
static int dissect_recipientEncryptedKeys(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_RecipientEncryptedKeys(FALSE, tvb, offset, pinfo, tree, hf_cms_recipientEncryptedKeys);
}


static const ber_sequence_t KeyAgreeRecipientInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_version },
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_originator },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_ukm },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_keyEncryptionAlgorithm },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_recipientEncryptedKeys },
  { 0, 0, 0, NULL }
};

static int
dissect_cms_KeyAgreeRecipientInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   KeyAgreeRecipientInfo_sequence, hf_index, ett_cms_KeyAgreeRecipientInfo);

  return offset;
}
static int dissect_kari_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_KeyAgreeRecipientInfo(TRUE, tvb, offset, pinfo, tree, hf_cms_kari);
}



static int
dissect_cms_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_keyIdentifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_cms_keyIdentifier);
}


static const ber_sequence_t KEKIdentifier_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_keyIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_date },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_other },
  { 0, 0, 0, NULL }
};

static int
dissect_cms_KEKIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   KEKIdentifier_sequence, hf_index, ett_cms_KEKIdentifier);

  return offset;
}
static int dissect_kekid(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_KEKIdentifier(FALSE, tvb, offset, pinfo, tree, hf_cms_kekid);
}


static const ber_sequence_t KEKRecipientInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_version },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_kekid },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_keyEncryptionAlgorithm },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_encryptedKey },
  { 0, 0, 0, NULL }
};

static int
dissect_cms_KEKRecipientInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   KEKRecipientInfo_sequence, hf_index, ett_cms_KEKRecipientInfo);

  return offset;
}
static int dissect_kekri_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_KEKRecipientInfo(TRUE, tvb, offset, pinfo, tree, hf_cms_kekri);
}


static const value_string cms_RecipientInfo_vals[] = {
  {   0, "ktri" },
  {   1, "kari" },
  {   2, "kekri" },
  { 0, NULL }
};

static const ber_choice_t RecipientInfo_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ktri },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_kari_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_kekri_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_cms_RecipientInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 RecipientInfo_choice, hf_index, ett_cms_RecipientInfo,
                                 NULL);

  return offset;
}
static int dissect_RecipientInfos_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_RecipientInfo(FALSE, tvb, offset, pinfo, tree, hf_cms_RecipientInfos_item);
}


static const ber_sequence_t RecipientInfos_set_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_RecipientInfos_item },
};

static int
dissect_cms_RecipientInfos(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 RecipientInfos_set_of, hf_index, ett_cms_RecipientInfos);

  return offset;
}
static int dissect_recipientInfos(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_RecipientInfos(FALSE, tvb, offset, pinfo, tree, hf_cms_recipientInfos);
}



static int
dissect_cms_ContentEncryptionAlgorithmIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_contentEncryptionAlgorithm(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_ContentEncryptionAlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_cms_contentEncryptionAlgorithm);
}



static int
dissect_cms_EncryptedContent(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_encryptedContent_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_EncryptedContent(TRUE, tvb, offset, pinfo, tree, hf_cms_encryptedContent);
}


static const ber_sequence_t EncryptedContentInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_encryptedContentType },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_contentEncryptionAlgorithm },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_encryptedContent_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_cms_EncryptedContentInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   EncryptedContentInfo_sequence, hf_index, ett_cms_EncryptedContentInfo);

  return offset;
}
static int dissect_encryptedContentInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_EncryptedContentInfo(FALSE, tvb, offset, pinfo, tree, hf_cms_encryptedContentInfo);
}


static const ber_sequence_t UnprotectedAttributes_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_UnprotectedAttributes_item },
};

static int
dissect_cms_UnprotectedAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 UnprotectedAttributes_set_of, hf_index, ett_cms_UnprotectedAttributes);

  return offset;
}
static int dissect_unprotectedAttrs_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_UnprotectedAttributes(TRUE, tvb, offset, pinfo, tree, hf_cms_unprotectedAttrs);
}


static const ber_sequence_t EnvelopedData_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_version },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_originatorInfo_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_recipientInfos },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_encryptedContentInfo },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_unprotectedAttrs_impl },
  { 0, 0, 0, NULL }
};

int
dissect_cms_EnvelopedData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   EnvelopedData_sequence, hf_index, ett_cms_EnvelopedData);

  return offset;
}



static int
dissect_cms_Digest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_digest(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_Digest(FALSE, tvb, offset, pinfo, tree, hf_cms_digest);
}


static const ber_sequence_t DigestedData_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_version },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_digestAlgorithm },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_encapContentInfo },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_digest },
  { 0, 0, 0, NULL }
};

static int
dissect_cms_DigestedData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DigestedData_sequence, hf_index, ett_cms_DigestedData);

  return offset;
}


static const ber_sequence_t EncryptedData_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_version },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_encryptedContentInfo },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_unprotectedAttrs_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_cms_EncryptedData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   EncryptedData_sequence, hf_index, ett_cms_EncryptedData);

  return offset;
}



static int
dissect_cms_MessageAuthenticationCodeAlgorithm(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_macAlgorithm(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_MessageAuthenticationCodeAlgorithm(FALSE, tvb, offset, pinfo, tree, hf_cms_macAlgorithm);
}


static const ber_sequence_t AuthAttributes_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_AuthAttributes_item },
};

static int
dissect_cms_AuthAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 AuthAttributes_set_of, hf_index, ett_cms_AuthAttributes);

  return offset;
}
static int dissect_authenticatedAttributes_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_AuthAttributes(TRUE, tvb, offset, pinfo, tree, hf_cms_authenticatedAttributes);
}



static int
dissect_cms_MessageAuthenticationCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_mac(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_MessageAuthenticationCode(FALSE, tvb, offset, pinfo, tree, hf_cms_mac);
}


static const ber_sequence_t AuthenticatedData_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_version },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_originatorInfo_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_recipientInfos },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_macAlgorithm },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_digestAlgorithm_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_encapContentInfo },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_authenticatedAttributes_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_mac },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_unauthenticatedAttributes_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_cms_AuthenticatedData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AuthenticatedData_sequence, hf_index, ett_cms_AuthenticatedData);

  return offset;
}



static int
dissect_cms_MessageDigest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 108 "cms.cnf"
  proto_item *pi;
  int old_offset = offset;

    offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

 
  pi = get_ber_last_created_item();

  /* move past TLV */
  old_offset = get_ber_identifier(tvb, old_offset, NULL, NULL, NULL);
  old_offset = get_ber_length(tree, tvb, old_offset, NULL, NULL);

  if(content_tvb) 
    cms_verify_msg_digest(pi, content_tvb, x509af_get_last_algorithm_id(), tvb, old_offset);



  return offset;
}



static int
dissect_cms_UTCTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTCTime,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_utcTime(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_UTCTime(FALSE, tvb, offset, pinfo, tree, hf_cms_utcTime);
}


static const value_string cms_Time_vals[] = {
  {   0, "utcTime" },
  {   1, "generalTime" },
  { 0, NULL }
};

static const ber_choice_t Time_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_NOOWNTAG, dissect_utcTime },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_generalTime },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_cms_Time(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Time_choice, hf_index, ett_cms_Time,
                                 NULL);

  return offset;
}



static int
dissect_cms_SigningTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_cms_Time(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



int
dissect_cms_Countersignature(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_cms_SignerInfo(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}

/*--- PDUs ---*/

static void dissect_ContentInfo_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_cms_ContentInfo(FALSE, tvb, 0, pinfo, tree, hf_cms_ContentInfo_PDU);
}
static void dissect_ContentType_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_cms_ContentType(FALSE, tvb, 0, pinfo, tree, hf_cms_ContentType_PDU);
}
static void dissect_SignedData_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_cms_SignedData(FALSE, tvb, 0, pinfo, tree, hf_cms_SignedData_PDU);
}
static void dissect_EnvelopedData_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_cms_EnvelopedData(FALSE, tvb, 0, pinfo, tree, hf_cms_EnvelopedData_PDU);
}
static void dissect_DigestedData_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_cms_DigestedData(FALSE, tvb, 0, pinfo, tree, hf_cms_DigestedData_PDU);
}
static void dissect_EncryptedData_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_cms_EncryptedData(FALSE, tvb, 0, pinfo, tree, hf_cms_EncryptedData_PDU);
}
static void dissect_AuthenticatedData_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_cms_AuthenticatedData(FALSE, tvb, 0, pinfo, tree, hf_cms_AuthenticatedData_PDU);
}
static void dissect_MessageDigest_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_cms_MessageDigest(FALSE, tvb, 0, pinfo, tree, hf_cms_MessageDigest_PDU);
}
static void dissect_SigningTime_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_cms_SigningTime(FALSE, tvb, 0, pinfo, tree, hf_cms_SigningTime_PDU);
}
static void dissect_Countersignature_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_cms_Countersignature(FALSE, tvb, 0, pinfo, tree, hf_cms_Countersignature_PDU);
}


/*--- End of included file: packet-cms-fn.c ---*/
#line 134 "packet-cms-template.c"

/*--- proto_register_cms ----------------------------------------------*/
void proto_register_cms(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_cms_ci_contentType,
      { "contentType", "cms.contentInfo.contentType",
        FT_OID, BASE_NONE, NULL, 0,
        "ContentType", HFILL }},

/*--- Included file: packet-cms-hfarr.c ---*/
#line 1 "packet-cms-hfarr.c"
    { &hf_cms_ContentInfo_PDU,
      { "ContentInfo", "cms.ContentInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.ContentInfo", HFILL }},
    { &hf_cms_ContentType_PDU,
      { "ContentType", "cms.ContentType",
        FT_OID, BASE_NONE, NULL, 0,
        "cms.ContentType", HFILL }},
    { &hf_cms_SignedData_PDU,
      { "SignedData", "cms.SignedData",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.SignedData", HFILL }},
    { &hf_cms_EnvelopedData_PDU,
      { "EnvelopedData", "cms.EnvelopedData",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.EnvelopedData", HFILL }},
    { &hf_cms_DigestedData_PDU,
      { "DigestedData", "cms.DigestedData",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.DigestedData", HFILL }},
    { &hf_cms_EncryptedData_PDU,
      { "EncryptedData", "cms.EncryptedData",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.EncryptedData", HFILL }},
    { &hf_cms_AuthenticatedData_PDU,
      { "AuthenticatedData", "cms.AuthenticatedData",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.AuthenticatedData", HFILL }},
    { &hf_cms_MessageDigest_PDU,
      { "MessageDigest", "cms.MessageDigest",
        FT_BYTES, BASE_HEX, NULL, 0,
        "cms.MessageDigest", HFILL }},
    { &hf_cms_SigningTime_PDU,
      { "SigningTime", "cms.SigningTime",
        FT_UINT32, BASE_DEC, VALS(x509af_Time_vals), 0,
        "cms.SigningTime", HFILL }},
    { &hf_cms_Countersignature_PDU,
      { "Countersignature", "cms.Countersignature",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.Countersignature", HFILL }},
    { &hf_cms_contentType,
      { "contentType", "cms.contentType",
        FT_OID, BASE_NONE, NULL, 0,
        "cms.T_contentType", HFILL }},
    { &hf_cms_content,
      { "content", "cms.content",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.T_content", HFILL }},
    { &hf_cms_version,
      { "version", "cms.version",
        FT_INT32, BASE_DEC, VALS(cms_CMSVersion_vals), 0,
        "cms.CMSVersion", HFILL }},
    { &hf_cms_digestAlgorithms,
      { "digestAlgorithms", "cms.digestAlgorithms",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cms.DigestAlgorithmIdentifiers", HFILL }},
    { &hf_cms_encapContentInfo,
      { "encapContentInfo", "cms.encapContentInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.EncapsulatedContentInfo", HFILL }},
    { &hf_cms_certificates,
      { "certificates", "cms.certificates",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cms.CertificateSet", HFILL }},
    { &hf_cms_crls,
      { "crls", "cms.crls",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cms.CertificateRevocationLists", HFILL }},
    { &hf_cms_signerInfos,
      { "signerInfos", "cms.signerInfos",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cms.SignerInfos", HFILL }},
    { &hf_cms_DigestAlgorithmIdentifiers_item,
      { "Item", "cms.DigestAlgorithmIdentifiers_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.DigestAlgorithmIdentifier", HFILL }},
    { &hf_cms_SignerInfos_item,
      { "Item", "cms.SignerInfos_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.SignerInfo", HFILL }},
    { &hf_cms_eContentType,
      { "eContentType", "cms.eContentType",
        FT_OID, BASE_NONE, NULL, 0,
        "cms.T_eContentType", HFILL }},
    { &hf_cms_eContent,
      { "eContent", "cms.eContent",
        FT_BYTES, BASE_HEX, NULL, 0,
        "cms.T_eContent", HFILL }},
    { &hf_cms_sid,
      { "sid", "cms.sid",
        FT_UINT32, BASE_DEC, VALS(cms_SignerIdentifier_vals), 0,
        "cms.SignerIdentifier", HFILL }},
    { &hf_cms_digestAlgorithm,
      { "digestAlgorithm", "cms.digestAlgorithm",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.DigestAlgorithmIdentifier", HFILL }},
    { &hf_cms_signedAttrs,
      { "signedAttrs", "cms.signedAttrs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cms.SignedAttributes", HFILL }},
    { &hf_cms_signatureAlgorithm,
      { "signatureAlgorithm", "cms.signatureAlgorithm",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.SignatureAlgorithmIdentifier", HFILL }},
    { &hf_cms_signatureValue,
      { "signature", "cms.signature",
        FT_BYTES, BASE_HEX, NULL, 0,
        "cms.SignatureValue", HFILL }},
    { &hf_cms_unsignedAttrs,
      { "unsignedAttrs", "cms.unsignedAttrs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cms.UnsignedAttributes", HFILL }},
    { &hf_cms_issuerAndSerialNumber,
      { "issuerAndSerialNumber", "cms.issuerAndSerialNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.IssuerAndSerialNumber", HFILL }},
    { &hf_cms_subjectKeyIdentifier,
      { "subjectKeyIdentifier", "cms.subjectKeyIdentifier",
        FT_BYTES, BASE_HEX, NULL, 0,
        "cms.SubjectKeyIdentifier", HFILL }},
    { &hf_cms_SignedAttributes_item,
      { "Item", "cms.SignedAttributes_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.Attribute", HFILL }},
    { &hf_cms_UnsignedAttributes_item,
      { "Item", "cms.UnsignedAttributes_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.Attribute", HFILL }},
    { &hf_cms_attrType,
      { "attrType", "cms.attrType",
        FT_OID, BASE_NONE, NULL, 0,
        "cms.T_attrType", HFILL }},
    { &hf_cms_attrValues,
      { "attrValues", "cms.attrValues",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cms.SET_OF_AttributeValue", HFILL }},
    { &hf_cms_attrValues_item,
      { "Item", "cms.attrValues_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.AttributeValue", HFILL }},
    { &hf_cms_originatorInfo,
      { "originatorInfo", "cms.originatorInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.OriginatorInfo", HFILL }},
    { &hf_cms_recipientInfos,
      { "recipientInfos", "cms.recipientInfos",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cms.RecipientInfos", HFILL }},
    { &hf_cms_encryptedContentInfo,
      { "encryptedContentInfo", "cms.encryptedContentInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.EncryptedContentInfo", HFILL }},
    { &hf_cms_unprotectedAttrs,
      { "unprotectedAttrs", "cms.unprotectedAttrs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cms.UnprotectedAttributes", HFILL }},
    { &hf_cms_certs,
      { "certs", "cms.certs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cms.CertificateSet", HFILL }},
    { &hf_cms_RecipientInfos_item,
      { "Item", "cms.RecipientInfos_item",
        FT_UINT32, BASE_DEC, VALS(cms_RecipientInfo_vals), 0,
        "cms.RecipientInfo", HFILL }},
    { &hf_cms_encryptedContentType,
      { "contentType", "cms.contentType",
        FT_OID, BASE_NONE, NULL, 0,
        "cms.ContentType", HFILL }},
    { &hf_cms_contentEncryptionAlgorithm,
      { "contentEncryptionAlgorithm", "cms.contentEncryptionAlgorithm",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.ContentEncryptionAlgorithmIdentifier", HFILL }},
    { &hf_cms_encryptedContent,
      { "encryptedContent", "cms.encryptedContent",
        FT_BYTES, BASE_HEX, NULL, 0,
        "cms.EncryptedContent", HFILL }},
    { &hf_cms_UnprotectedAttributes_item,
      { "Item", "cms.UnprotectedAttributes_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.Attribute", HFILL }},
    { &hf_cms_ktri,
      { "ktri", "cms.ktri",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.KeyTransRecipientInfo", HFILL }},
    { &hf_cms_kari,
      { "kari", "cms.kari",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.KeyAgreeRecipientInfo", HFILL }},
    { &hf_cms_kekri,
      { "kekri", "cms.kekri",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.KEKRecipientInfo", HFILL }},
    { &hf_cms_rid,
      { "rid", "cms.rid",
        FT_UINT32, BASE_DEC, VALS(cms_RecipientIdentifier_vals), 0,
        "cms.RecipientIdentifier", HFILL }},
    { &hf_cms_keyEncryptionAlgorithm,
      { "keyEncryptionAlgorithm", "cms.keyEncryptionAlgorithm",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.KeyEncryptionAlgorithmIdentifier", HFILL }},
    { &hf_cms_encryptedKey,
      { "encryptedKey", "cms.encryptedKey",
        FT_BYTES, BASE_HEX, NULL, 0,
        "cms.EncryptedKey", HFILL }},
    { &hf_cms_originator,
      { "originator", "cms.originator",
        FT_UINT32, BASE_DEC, VALS(cms_OriginatorIdentifierOrKey_vals), 0,
        "cms.OriginatorIdentifierOrKey", HFILL }},
    { &hf_cms_ukm,
      { "ukm", "cms.ukm",
        FT_BYTES, BASE_HEX, NULL, 0,
        "cms.UserKeyingMaterial", HFILL }},
    { &hf_cms_recipientEncryptedKeys,
      { "recipientEncryptedKeys", "cms.recipientEncryptedKeys",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cms.RecipientEncryptedKeys", HFILL }},
    { &hf_cms_originatorKey,
      { "originatorKey", "cms.originatorKey",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.OriginatorPublicKey", HFILL }},
    { &hf_cms_algorithm,
      { "algorithm", "cms.algorithm",
        FT_NONE, BASE_NONE, NULL, 0,
        "x509af.AlgorithmIdentifier", HFILL }},
    { &hf_cms_publicKey,
      { "publicKey", "cms.publicKey",
        FT_BYTES, BASE_HEX, NULL, 0,
        "cms.BIT_STRING", HFILL }},
    { &hf_cms_RecipientEncryptedKeys_item,
      { "Item", "cms.RecipientEncryptedKeys_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.RecipientEncryptedKey", HFILL }},
    { &hf_cms_rekRid,
      { "rid", "cms.rid",
        FT_UINT32, BASE_DEC, VALS(cms_KeyAgreeRecipientIdentifier_vals), 0,
        "cms.KeyAgreeRecipientIdentifier", HFILL }},
    { &hf_cms_rKeyId,
      { "rKeyId", "cms.rKeyId",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.RecipientKeyIdentifier", HFILL }},
    { &hf_cms_date,
      { "date", "cms.date",
        FT_STRING, BASE_NONE, NULL, 0,
        "cms.GeneralizedTime", HFILL }},
    { &hf_cms_other,
      { "other", "cms.other",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.OtherKeyAttribute", HFILL }},
    { &hf_cms_kekid,
      { "kekid", "cms.kekid",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.KEKIdentifier", HFILL }},
    { &hf_cms_keyIdentifier,
      { "keyIdentifier", "cms.keyIdentifier",
        FT_BYTES, BASE_HEX, NULL, 0,
        "cms.OCTET_STRING", HFILL }},
    { &hf_cms_digest,
      { "digest", "cms.digest",
        FT_BYTES, BASE_HEX, NULL, 0,
        "cms.Digest", HFILL }},
    { &hf_cms_macAlgorithm,
      { "macAlgorithm", "cms.macAlgorithm",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.MessageAuthenticationCodeAlgorithm", HFILL }},
    { &hf_cms_authenticatedAttributes,
      { "authenticatedAttributes", "cms.authenticatedAttributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cms.AuthAttributes", HFILL }},
    { &hf_cms_mac,
      { "mac", "cms.mac",
        FT_BYTES, BASE_HEX, NULL, 0,
        "cms.MessageAuthenticationCode", HFILL }},
    { &hf_cms_unauthenticatedAttributes,
      { "unauthenticatedAttributes", "cms.unauthenticatedAttributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cms.UnauthAttributes", HFILL }},
    { &hf_cms_AuthAttributes_item,
      { "Item", "cms.AuthAttributes_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.Attribute", HFILL }},
    { &hf_cms_UnauthAttributes_item,
      { "Item", "cms.UnauthAttributes_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.Attribute", HFILL }},
    { &hf_cms_CertificateRevocationLists_item,
      { "Item", "cms.CertificateRevocationLists_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "x509af.CertificateList", HFILL }},
    { &hf_cms_certificate,
      { "certificate", "cms.certificate",
        FT_NONE, BASE_NONE, NULL, 0,
        "x509af.Certificate", HFILL }},
    { &hf_cms_extendedCertificate,
      { "extendedCertificate", "cms.extendedCertificate",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.ExtendedCertificate", HFILL }},
    { &hf_cms_attrCert,
      { "attrCert", "cms.attrCert",
        FT_NONE, BASE_NONE, NULL, 0,
        "x509af.AttributeCertificate", HFILL }},
    { &hf_cms_CertificateSet_item,
      { "Item", "cms.CertificateSet_item",
        FT_UINT32, BASE_DEC, VALS(cms_CertificateChoices_vals), 0,
        "cms.CertificateChoices", HFILL }},
    { &hf_cms_issuer,
      { "issuer", "cms.issuer",
        FT_UINT32, BASE_DEC, VALS(x509if_Name_vals), 0,
        "x509if.Name", HFILL }},
    { &hf_cms_serialNumber,
      { "serialNumber", "cms.serialNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        "x509af.CertificateSerialNumber", HFILL }},
    { &hf_cms_keyAttrId,
      { "keyAttrId", "cms.keyAttrId",
        FT_OID, BASE_NONE, NULL, 0,
        "cms.T_keyAttrId", HFILL }},
    { &hf_cms_keyAttr,
      { "keyAttr", "cms.keyAttr",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.T_keyAttr", HFILL }},
    { &hf_cms_utcTime,
      { "utcTime", "cms.utcTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "cms.UTCTime", HFILL }},
    { &hf_cms_generalTime,
      { "generalTime", "cms.generalTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "cms.GeneralizedTime", HFILL }},
    { &hf_cms_extendedCertificateInfo,
      { "extendedCertificateInfo", "cms.extendedCertificateInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.ExtendedCertificateInfo", HFILL }},
    { &hf_cms_signature,
      { "signature", "cms.signature",
        FT_BYTES, BASE_HEX, NULL, 0,
        "cms.Signature", HFILL }},
    { &hf_cms_attributes,
      { "attributes", "cms.attributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cms.UnauthAttributes", HFILL }},

/*--- End of included file: packet-cms-hfarr.c ---*/
#line 145 "packet-cms-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-cms-ettarr.c ---*/
#line 1 "packet-cms-ettarr.c"
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
    &ett_cms_DigestedData,
    &ett_cms_EncryptedData,
    &ett_cms_AuthenticatedData,
    &ett_cms_AuthAttributes,
    &ett_cms_UnauthAttributes,
    &ett_cms_CertificateRevocationLists,
    &ett_cms_CertificateChoices,
    &ett_cms_CertificateSet,
    &ett_cms_IssuerAndSerialNumber,
    &ett_cms_OtherKeyAttribute,
    &ett_cms_Time,
    &ett_cms_ExtendedCertificate,
    &ett_cms_ExtendedCertificateInfo,

/*--- End of included file: packet-cms-ettarr.c ---*/
#line 150 "packet-cms-template.c"
  };

  /* Register protocol */
  proto_cms = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_cms, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_cms -------------------------------------------*/
void proto_reg_handoff_cms(void) {

/*--- Included file: packet-cms-dis-tab.c ---*/
#line 1 "packet-cms-dis-tab.c"
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


/*--- End of included file: packet-cms-dis-tab.c ---*/
#line 165 "packet-cms-template.c"
}

